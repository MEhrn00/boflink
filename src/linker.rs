use std::{
    collections::HashMap,
    sync::{
        RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelExtend, ParallelIterator,
    },
    slice::ParallelSliceMut,
};

use crate::{
    arena::{ArenaHandle, ArenaRef, TypedArena},
    cli::InputArg,
    coff::ImageFileMachine,
    context::LinkContext,
    inputs::{InputsStore, ObjectFile, ObjectFileId},
    outputs::{
        OutputSection, OutputSectionId, RebaseEntry, RebaseGroup, SectionKey,
        create_reserved_sections,
    },
    reader::InputsReader,
    symbols::{GlobalSymbol, MapEntry, SymbolId},
    timing::ScopedTimer,
};

pub struct Linker<'a> {
    /// Architecture
    pub architecture: ImageFileMachine,

    /// Input object files
    pub objs: Vec<ArenaRef<'a, ObjectFile<'a>>>,

    /// Command line specified symbols
    pub root_symbols: Vec<SymbolId>,

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
            root_symbols: Vec::new(),
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
        if let MapEntry::Vacant(entry) = ctx.symbol_map.get_map_entry(self.mangle(name)) {
            let symbol = entry.insert_default();
            self.root_symbols.push(symbol.id());
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
        for root_symbol in self.root_symbols.iter().copied() {
            let symbol = ctx.symbol_map.get_exclusive_symbol(root_symbol).unwrap();
            if let Some(owner) = symbol.owner.index() {
                *self.objs[owner].live.get_mut() = true;
            }
        }

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
                let obj = &self.objs[id.index().unwrap()];
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
            .filter(|obj| obj.id.is_internal() || obj.live.load(Ordering::Relaxed))
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

        let mut section_map = HashMap::<SectionKey, OutputSectionId>::new();
        let global_sections = RwLock::new((&mut section_map, &mut self.sections));

        let inputs_matricies = self
            .objs
            .par_iter_mut()
            .map(|obj| {
                // Create a matrix where X is the index of the output section
                // and Y is the list of input sections for that output section
                let mut outputs_matrix = Vec::new();
                outputs_matrix.resize(26, Vec::new());
                let mut needed_sections = HashMap::<SectionKey, Vec<_>>::new();
                for section in obj.sections.iter_mut().flatten() {
                    // Discard empty sections
                    if section.length == 0 {
                        *section.discarded.get_mut() = true;
                    }

                    if *section.discarded.get_mut() {
                        continue;
                    }

                    let key = SectionKey::new(ctx, section);
                    if let Some(id) = key.known_output() {
                        section.output = id;
                        outputs_matrix[id.index()].push(section.index);
                    } else {
                        needed_sections.entry(key).or_default().push(section.index);
                    }
                }

                (obj, outputs_matrix, needed_sections)
            })
            .map(|(obj, mut outputs_matrix, needed_sections)| {
                // If the object file contained input sections that could not be
                // speculatively placed into a known section, allocate needed
                // output sections.
                if !needed_sections.is_empty() {
                    let mut guard = global_sections.write().unwrap();
                    let (mut section_map, mut section_list) =
                        (std::mem::take(guard.0), std::mem::take(guard.1));
                    let section_arena = ctx.section_pool.get();
                    for (key, indicies) in needed_sections {
                        let name = key.name();
                        let flags = key.flags();
                        let output_id = *section_map.entry(key).or_insert_with(|| {
                            let id = OutputSectionId::new(section_list.len());
                            section_list.push(
                                section_arena.alloc_ref(OutputSection::new(id, name, flags, false)),
                            );
                            id
                        });
                        outputs_matrix.resize(output_id.index() + 1, Vec::new());
                        outputs_matrix[output_id.index()] = indicies
                            .into_iter()
                            .inspect(|&index| {
                                let section = obj.input_section_mut(index).unwrap();
                                section.output = output_id;
                            })
                            .collect();
                    }

                    let _ = std::mem::replace(guard.0, section_map);
                    let _ = std::mem::replace(guard.1, section_list);
                }

                // Return the object file id and matrix of output section mappings
                (obj.id, outputs_matrix)
            })
            .collect::<Vec<_>>();

        // Join input sections to each output section
        self.sections.par_iter_mut().for_each(|output_section| {
            let output_id = output_section.id;
            let alignment = AtomicUsize::new(0);

            output_section
                .inputs
                .par_extend(inputs_matricies.par_iter().flat_map(|(objid, matrix)| {
                    let alignment = &alignment;
                    let objid = *objid;
                    let obj = &self.objs[objid.index().unwrap()];
                    // Get the associated list of input sections from the object
                    // file that are mapped to this output section
                    let inputs = &matrix[output_id.index()];
                    inputs.par_iter().copied().map(move |index| {
                        let input_section = obj.input_section(index).unwrap();
                        let section_align = input_section.characteristics.alignment();
                        // Compute alignment needed
                        if section_align > 0 {
                            alignment.fetch_max(section_align, Ordering::SeqCst);
                        }
                        (objid, index)
                    })
                }));

            // Check if this section is empty and mark it as discarded
            if output_section.inputs.is_empty() {
                output_section.discard = true;
                return;
            }

            // Set alignment
            output_section
                .characteristics
                .set_alignment(alignment.into_inner());

            // Sort sections
            if ctx.options.merge_groups {
                let output_name = output_section.name;
                output_section.inputs.par_sort_unstable_by_key(
                    |(objid, index)| -> (&'a [u8], ObjectFileId, usize) {
                        let objid = *objid;
                        let index = *index;
                        let mut name = self.objs[objid.index().unwrap()]
                            .input_section(index)
                            .unwrap()
                            .name;
                        name = &name[output_name.len()..];
                        // Sort by "$<subname>" then object order then section index
                        (name, objid, index.0)
                    },
                );
            } else {
                // Sort by object order and section index if not merging grouped sections
                output_section
                    .inputs
                    .par_sort_unstable_by_key(|(objid, index)| (*objid, index.0));
            }
        });

        // These sections may be empty and marked as discarded but they should
        // always be kept
        self.sections[OutputSectionId::Text.index()..=OutputSectionId::Bss.index()]
            .iter_mut()
            .for_each(|section| {
                section.discard = false;
            });
    }

    pub fn rebase_sections(&mut self) {
        let _timer = ScopedTimer::msg("rebase sections");

        let rebase_groups = self
            .sections
            .par_iter_mut()
            .filter_map(|section| {
                if section.discard {
                    return None;
                }

                let mut rebases = Vec::with_capacity(self.objs.len());
                rebases.resize(self.objs.len(), Vec::new());

                let mut length = 0u32;
                let mut virtual_address = 0u32;
                for (objid, index) in section.inputs.iter().copied() {
                    let obj = &self.objs[objid.index().unwrap()];
                    let input_section = obj.input_section(index).unwrap();
                    let align = input_section.characteristics.alignment();
                    if align > 0 {
                        virtual_address = virtual_address.next_multiple_of(align as u32);
                    }
                    length = virtual_address;
                    rebases[objid.index().unwrap()].push(RebaseEntry {
                        index,
                        address: virtual_address,
                    });

                    virtual_address += input_section.length;
                }

                section.length = length;
                Some(RebaseGroup {
                    output: section.id,
                    rebases,
                })
            })
            .collect::<Vec<_>>();

        self.objs.par_iter_mut().for_each(|obj| {
            for group in &rebase_groups {
                let rebase_list = &group.rebases[obj.id.index().unwrap()];
                for entry in rebase_list {
                    let section = obj.input_section_mut(entry.index).unwrap();
                    section.virtual_address = entry.address;
                }
            }
        });
    }
}

/// Arena instances that are exclusive for the linker
struct LinkerArena<'a> {
    strings: ArenaHandle<'a, u8>,
    sections: ArenaHandle<'a, OutputSection<'a>>,
}
