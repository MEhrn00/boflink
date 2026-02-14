use std::{collections::HashMap, sync::atomic::Ordering};

use indexmap::IndexMap;
use object::SymbolIndex;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelExtend, ParallelIterator,
};

use crate::{
    arena::{ArenaHandle, ArenaRef, TypedArena},
    cli::InputArg,
    coff::{ImageFileMachine, SectionNumber, StorageClass},
    context::LinkContext,
    inputs::{InputsReader, InputsStore},
    object::{ObjectFile, ObjectFileId, ObjectSymbol},
    outputs::{
        OutputSection, OutputSectionId, OutputSectionInputsMap, SectionKey,
        create_reserved_sections,
    },
    symbols::{GlobalSymbol, MapEntry, SymbolId},
    timing::ScopedTimer,
};

pub struct Linker<'a> {
    /// Architecture
    pub architecture: ImageFileMachine,

    /// Input object files
    pub objs: Vec<ArenaRef<'a, ObjectFile<'a>>>,

    /// Output sections
    pub sections: Vec<ArenaRef<'a, OutputSection<'a>>>,

    required_symbol: Vec<SymbolId>,

    /// String arena
    strings: ArenaHandle<'a, u8>,
}

impl<'a> Linker<'a> {
    pub fn read_inputs(
        ctx: &LinkContext<'a>,
        inputs: &'a [InputArg],
        store: &'a InputsStore<'a>,
    ) -> crate::Result<Self> {
        let _timer = ScopedTimer::msg("read inputs");

        let input_objs = TypedArena::new();
        let strings = ctx.string_pool.get();

        let mut reader = InputsReader::new(
            ctx.options
                .machine
                .map(|emulation| emulation.into_machine())
                .unwrap_or(ImageFileMachine::Unknown),
            &strings,
            store,
            &input_objs,
        );

        rayon::in_place_scope(|scope| {
            reader.read_cli_inputs(ctx, scope, inputs);
        });

        Ok(Self {
            architecture: reader.architecture,
            objs: input_objs.into_vec(),
            sections: Vec::new(),
            required_symbol: Vec::new(),
            strings,
        })
    }

    pub fn mangle(&self, name: &'a [u8]) -> &'a [u8] {
        if self.architecture != ImageFileMachine::I386 {
            return name;
        }

        self.strings.alloc_bytes([b"_", name].concat().as_slice())
    }

    pub fn add_gc_root(&mut self, ctx: &mut LinkContext<'a>, name: &'a [u8]) {
        let name = self.mangle(name);
        if let MapEntry::Vacant(entry) = ctx.symbol_map.get_map_entry(name) {
            let symbol = entry.insert_default();
            let obj = &mut self.objs[0];
            let index = SymbolIndex(obj.symbols.len());
            self.objs[0].symbols.push(Some(ObjectSymbol {
                name,
                index,
                storage_class: StorageClass::External,
                external_id: Some(symbol.id()),
                // Make this symbol undefined so that it does not get claimed
                // by the internal object during symbol resolution
                value: 0,
                section_number: SectionNumber::Undefined,
                typ: 0,
                selection: None,
            }));
        }
    }

    pub fn add_required_symbol(&mut self, ctx: &mut LinkContext<'a>, name: &'a [u8]) {
        let name = self.mangle(name);
        let symbol = ctx.symbol_map.get_map_entry(name);
        let id = symbol.id();
        if !self.required_symbol.contains(&id) {
            self.required_symbol.push(id);
        }
    }

    pub fn add_traced_symbol(&mut self, ctx: &mut LinkContext<'a>, name: &'a [u8]) {
        let symbol = ctx.symbol_map.get_map_entry(self.mangle(name)).or_default();
        symbol.traced = true;
    }

    pub fn resolve_symbols(&mut self, ctx: &mut LinkContext<'a>) {
        let _timer = ScopedTimer::msg("symbol resolution");

        // First symbol resolution pass is used to populate the global symbol map
        // with symbol information and figure out which object file should be
        // the owner of the global symbol. All files are initially put in a lazy
        // state so any duplicate symbols will use the first one defined in the
        // from the command line order
        self.objs.par_iter().for_each(|obj| {
            obj.resolve_symbols(ctx, &self.objs);
        });

        // Figure out what object files should be included based on command line
        // input processing and through which object files define needed symbols
        // in command line options (--entry, --require-defined, --undefined).
        let live_symbols = std::mem::take(&mut self.objs[0].symbols);
        for symbol in live_symbols.iter().flatten() {
            if let Some(external_id) = symbol.external_id {
                let global = ctx.symbol_map.get_exclusive_symbol(external_id).unwrap();
                if !global.owner.is_internal() {
                    *self.objs[global.owner.index()].live.get_mut() = true;
                }
            }
        }

        self.objs[0].symbols = live_symbols;

        let live_objs = self
            .objs
            .par_iter_mut()
            .filter_map(|obj| {
                // Set command line input object files or `--whole-archive` members
                // as live
                if !obj.lazy {
                    *obj.live.get_mut() = true;
                }

                (*obj.live.get_mut()).then_some(obj.id)
            })
            .collect::<Vec<_>>();

        // Go through the list of live objects and transitively include all
        // dependent object files that have a symbol definition for any needed
        // undefined symbol.
        rayon::in_place_scope(|scope| {
            live_objs.par_iter().for_each(|id| {
                let obj = &self.objs[id.index()];
                obj.include_needed_objects(ctx, &self.objs, scope);
            });
        });

        // From this point, all object files needed are set as live

        // Resolve COMDAT leaders for live objects. This needs to happen live
        // objects to select the correct definition that should be used
        self.objs.par_iter().for_each(|obj| {
            if obj.live.load(Ordering::Relaxed) {
                obj.resolve_comdat_leaders(ctx, &self.objs);
            }
        });

        self.objs.par_iter_mut().for_each(|obj| {
            let ctx = &*ctx;
            if obj.live.load(Ordering::Relaxed) {
                obj.discard_unclaimed_comdats(ctx);
            }
        });

        ctx.exclusive_check_errored();

        // Redo symbol resolution from a clean slate using only the included object
        // files. This fixes the global symbol map in cases where an early object
        // file was chosen during the first symbol resolution pass but a later
        // object file has the definition being used
        ctx.symbol_map.par_for_each_symbol(|symbol| {
            *symbol = GlobalSymbol {
                name: symbol.name,
                traced: symbol.traced,
                ..Default::default()
            };
        });

        // Remove unused objects to shrink the list before re-resolving symbols.
        self.objs = std::mem::take(&mut self.objs)
            .into_par_iter()
            .filter_map(|mut obj| if *obj.live.get_mut() { Some(obj) } else { None })
            .collect::<Vec<_>>();

        // Need to recompute ids since indicies have most likely changed
        self.objs
            .par_iter_mut()
            .enumerate()
            .for_each(|(new_id, obj)| {
                obj.id = ObjectFileId::new(new_id);
            });

        self.objs.par_iter().for_each(|obj| {
            obj.resolve_symbols(ctx, &self.objs);
        });

        *ctx.stats.globals.get_mut() = ctx.symbol_map.len();
    }

    pub fn report_duplicate_symbols(&mut self, ctx: &LinkContext<'a>) {
        let duplicate_errors = self
            .objs
            .par_iter()
            .filter_map(|obj| {
                if !obj.live.load(Ordering::Relaxed) {
                    return None;
                }

                let mut errors: Vec<String> = Vec::new();
                for symbol in obj.symbols.iter().flatten() {
                    if !symbol.is_global() || symbol.is_weak() || symbol.is_common() {
                        continue;
                    }

                    if let Some(section) = symbol
                        .section_number
                        .index()
                        .map(|index| obj.section(index).unwrap())
                        && section.discarded.load(Ordering::Relaxed)
                    {
                        continue;
                    }

                    let external_ref = ctx.symbol_map.get(symbol.external_id.unwrap()).unwrap();
                    let global = external_ref.read().unwrap();
                    if global.owner != obj.id && !global.owner.is_internal() {
                        let owner = &self.objs[global.owner.index()];
                        errors.push(format!(
                            "duplicate symbol: {name}\n\
                                    defined at {owner}\n\
                                    defined at {this}",
                            name = symbol.demangle(ctx, obj.machine),
                            owner = owner.source(),
                            this = obj.source(),
                        ));
                    }
                }

                if !errors.is_empty() {
                    Some(errors)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for error in duplicate_errors.iter().flatten() {
            log::error!("{error}");
        }

        if !duplicate_errors.is_empty() {
            std::process::exit(1);
        }
    }

    pub fn create_output_sections(&mut self, ctx: &mut LinkContext<'a>) {
        let _timer = ScopedTimer::msg("output section allocation");
        // Add reserved sections
        self.sections = create_reserved_sections(&ctx.section_pool.get());
        let reserved_sections_len = self.sections.len();

        // Partition object file input sections.
        //
        // For each object file, accumulate a list of input sections which can
        // be mapped to known output sections and a list of input sections which
        // require new output section to be allocated.
        let mut known_outputs = Vec::with_capacity(self.objs.len());
        let mut needed_outputs = Vec::with_capacity(self.objs.len());

        self.objs
            .par_iter_mut()
            .map(|obj| {
                let objid = obj.id;
                obj.sections
                    .iter_mut()
                    .flatten()
                    .filter_map(|section| {
                        if *section.discarded.get_mut() {
                            None
                        } else {
                            Some(section)
                        }
                    })
                    .fold(
                        (
                            OutputSectionInputsMap::new(reserved_sections_len),
                            IndexMap::new(),
                        ),
                        |(mut known, mut needed), section| {
                            let key = SectionKey::new(ctx, section);
                            if let Some(id) = key.known_id() {
                                section.output = id;
                                let entry = known.get_or_default(id);
                                entry.push((objid, section.index));
                            } else {
                                let entry: &mut Vec<_> = needed.entry(key).or_default();
                                entry.push((objid, section.index));
                            }
                            (known, needed)
                        },
                    )
            })
            .unzip_into_vecs(&mut known_outputs, &mut needed_outputs);

        let ((mut new_outputs, join_mats), _) = rayon::join(
            || {
                let arena = ctx.section_pool.get();
                let mut section_map = HashMap::new();
                let mut sections = Vec::new();
                for (key, mut input_sections) in needed_outputs.into_iter().flatten() {
                    let name = key.name();
                    let flags = key.flags();
                    let index = *section_map.entry(key).or_insert_with(|| {
                        let index = sections.len();
                        let id = OutputSectionId::new(reserved_sections_len + index);
                        sections.push(arena.alloc_ref(OutputSection::new(id, name, flags)));
                        index
                    });
                    sections[index].inputs.append(&mut input_sections);
                }

                // Create matricies used for joining the input sections to the new
                // output sections
                let join_mats = sections
                    .par_iter()
                    .map(|section| section.create_join_matrix())
                    .collect::<Vec<_>>();

                (sections, join_mats)
            },
            || {
                // Join known outputs
                self.sections.par_iter_mut().for_each(|section| {
                    let output_id = section.id;
                    section.inputs.par_extend(
                        known_outputs
                            .par_iter()
                            .filter_map(|input_map| input_map.get(output_id))
                            .flat_map_iter(|inputs| inputs.iter().copied()),
                    );
                });
            },
        );

        self.sections.append(&mut new_outputs);

        // Join newly created outputs with the input sections
        self.objs.par_iter_mut().for_each(|obj| {
            let outputs = join_mats
                .par_iter()
                .by_uniform_blocks(1_000_000)
                .fold(Vec::new, |mut list, mat| {
                    if let Some(indicies) = mat.get(obj.id) {
                        list.extend(indicies.iter().map(|index| (mat.output_id, *index)));
                    }
                    list
                })
                .reduce(Vec::new, |mut v1, mut v2| {
                    v1.append(&mut v2);
                    v1
                });

            for (output_id, index) in outputs {
                let section = obj.section_mut(index).unwrap();
                section.output = output_id;
            }
        });
    }

    pub fn claim_undefined_symbols(&mut self, ctx: &LinkContext<'a>) {
        self.objs
            .par_iter_mut()
            .filter(|obj| obj.has_import_data)
            .for_each(|obj: &mut ArenaRef<'a, ObjectFile<'a>>| {
                let obj = obj.as_mut();
                for symbol in obj.symbols.iter().flatten() {
                    let Some(external_id) = symbol.external_id else {
                        continue;
                    };

                    let Some(section_index) = symbol.section_number.index() else {
                        continue;
                    };

                    let section = obj.sections[section_index.0].as_mut().unwrap();
                    if !(section.name == b".text" || section.name == b".text$4") {
                        continue;
                    }

                    let external_ref = ctx.symbol_map.get(external_id).unwrap();
                    let mut global = external_ref.write().unwrap();
                    if global.owner == obj.id {
                        global.imported = true;
                    }
                }
            });
    }
}
