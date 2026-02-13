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
    inputs::{InputSymbol, InputsStore, ObjectFile, ObjectFileId},
    outputs::{
        OutputSection, OutputSectionId, OutputSectionInputsMap, SectionKey,
        create_reserved_sections,
    },
    reader::InputsReader,
    symbols::{GlobalSymbol, MapEntry},
    timing::ScopedTimer,
};

pub struct Linker<'a> {
    /// Architecture
    pub architecture: ImageFileMachine,

    /// Input object files
    pub objs: Vec<ArenaRef<'a, ObjectFile<'a>>>,

    /// Output sections
    pub sections: Vec<ArenaRef<'a, OutputSection<'a>>>,

    /// Local arena
    arena: LinkerArena<'a>,
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
            arena: LinkerArena {
                strings,
                sections: ctx.section_pool.get(),
            },
        })
    }

    pub fn mangle(&self, name: &'a [u8]) -> &'a [u8] {
        if self.architecture != ImageFileMachine::I386 {
            return name;
        }

        self.arena
            .strings
            .alloc_bytes([b"_", name].concat().as_slice())
    }

    pub fn add_root_symbol(&mut self, ctx: &mut LinkContext<'a>, name: &'a [u8]) {
        let name = self.mangle(name);
        if let MapEntry::Vacant(entry) = ctx.symbol_map.get_map_entry(self.mangle(name)) {
            let symbol = entry.insert_default();
            let obj = &mut self.objs[0];
            let index = SymbolIndex(obj.symbols.len());
            self.objs[0].symbols.push(Some(InputSymbol {
                name,
                index,
                storage_class: StorageClass::External,
                external_id: Some(symbol.id()),
                value: 0,
                section_number: SectionNumber::Undefined,
                typ: 0,
                selection: None,
            }));
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
        for root_symbol in live_symbols.iter().flatten() {
            if let Some(external_id) = root_symbol.external_id {
                let symbol = ctx.symbol_map.get_exclusive_symbol(external_id).unwrap();
                if let Some(owner) = symbol.owner {
                    *self.objs[owner.index()].live.get_mut() = true;
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
            if obj.live.load(Ordering::Relaxed)
                && let Err(e) = obj.discard_unused_comdats(ctx)
            {
                log::error!(logger: ctx, "{}: {e}", obj.source());
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

        log::trace!(
            "found {} live objects after symbol resolution",
            self.objs.len() - 1
        );
    }

    pub fn create_output_sections(&mut self, ctx: &mut LinkContext<'a>) {
        let _timer = ScopedTimer::msg("output section allocation");
        // Add reserved sections
        self.sections = create_reserved_sections(&self.arena.sections);
        let reserved_len = self.sections.len();

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
                        // Discard empty sections
                        if section.length == 0 {
                            *section.discarded.get_mut() = true;
                        }

                        if *section.discarded.get_mut() {
                            None
                        } else {
                            Some(section)
                        }
                    })
                    .fold(
                        (OutputSectionInputsMap::new(reserved_len), IndexMap::new()),
                        |(mut known, mut needed), section| {
                            let key = SectionKey::new(ctx, section);
                            if let Some(id) = key.known_id() {
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

        // Spin off two jobs. The first join will go through the lists of known
        // output sections for each object file. The second will allocate the
        // new output sections for the lists of needed sections.

        let (mut join_mats, mut new_outputs) = rayon::join(
            || {
                // Join known outputs
                self.sections
                    .par_iter_mut()
                    .enumerate()
                    .map(|(index, section)| (OutputSectionId::new(index), section))
                    .for_each(|(id, section)| {
                        section.inputs.par_extend(
                            known_outputs
                                .par_iter()
                                .filter_map(|input_map| input_map.get(id))
                                .flat_map_iter(|inputs| inputs.iter().copied()),
                        );
                    });

                // Remove empty sections except for .text, .data, .bss.
                // Do this sequentially since there are not that many pre-allocated
                // output sections. This also gives time for rayon to schedule execution
                // of the second closure if it has not already done so
                self.sections.retain(|section| {
                    section.name == b".text"
                        || section.name == b".data"
                        || section.name == b".bss"
                        || !section.inputs.is_empty()
                });

                // Fix output section metadata
                self.sections.par_iter_mut().for_each(|section| {
                    section.sort_inputs(ctx, &self.objs);
                    section.compute_length(&self.objs);
                    section.compute_alignment(&self.objs);
                });

                // Create matricies used for joining the output sections to the
                // associated input sections in each object file
                self.sections
                    .par_iter()
                    .map(|section| section.create_join_matrix())
                    .collect::<Vec<_>>()
            },
            || {
                // Allocate new output sections for the needed inputs.
                // This is done sequentially since in typical scenarios, the number
                // of new output sections should be relatively small unless
                // `--no-merge-groups` was specified and large object files were
                // compiled with `-ffunction-sections -fdata-sections`
                let arena = ctx.section_pool.get();
                let mut section_map = HashMap::new();
                let mut sections = Vec::new();
                for (key, mut input_sections) in needed_outputs.into_iter().flatten() {
                    let name = key.name();
                    let flags = key.flags();
                    let output_id = section_map.entry(key).or_insert_with(|| {
                        let id = OutputSectionId::new(sections.len());
                        sections.push(arena.alloc_ref(OutputSection::new(name, flags)));
                        id
                    });
                    sections[output_id.index()]
                        .inputs
                        .append(&mut input_sections);
                }

                // Fix metadata for new output sections
                sections.par_iter_mut().for_each(|section| {
                    section.sort_inputs(ctx, &self.objs);
                    section.compute_length(&self.objs);
                    section.compute_alignment(&self.objs);
                });

                sections
            },
        );

        join_mats.reserve_exact(new_outputs.len());
        join_mats.par_extend(
            new_outputs
                .par_iter()
                .map(|section| section.create_join_matrix()),
        );
        self.sections.append(&mut new_outputs);

        // Join output sections to the associated inputs
        self.objs.par_iter_mut().for_each(|obj| {
            let outputs = join_mats
                .par_iter()
                .enumerate()
                .map(|(index, mat)| (OutputSectionId::new(index), mat))
                .by_uniform_blocks(1_000_000)
                .fold(Vec::new, |mut list, (id, mat)| {
                    if let Some(indicies) = mat.get(obj.id) {
                        list.extend(indicies.iter().map(|index| (id, *index)));
                    }
                    list
                })
                .reduce(Vec::new, |mut v1, mut v2| {
                    v1.append(&mut v2);
                    v1
                });

            for (output_id, index) in outputs {
                let section = obj.input_section_mut(index).unwrap();
                section.output = output_id;
            }
        });

        if log::log_enabled!(log::Level::Debug) {
            for output in self.sections.iter() {
                let name = String::from_utf8_lossy(output.name);
                for (obj_id, index) in output.inputs.iter().copied() {
                    let obj = &self.objs[obj_id.index()];
                    let section = obj.input_section(index).unwrap();
                    let input_name = String::from_utf8_lossy(section.name);
                    log::debug!(
                        "{}: {input_name} input section mapped to {name} output section",
                        obj.source()
                    );
                }
            }
        }
    }

    pub fn rebase_sections(&mut self) {
        let _timer = ScopedTimer::msg("rebase sections");
    }
}

/// Arena instances that are exclusive for the linker
struct LinkerArena<'a> {
    strings: ArenaHandle<'a, u8>,
    sections: ArenaHandle<'a, OutputSection<'a>>,
}
