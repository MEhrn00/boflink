use std::{
    collections::HashMap,
    sync::{RwLock, atomic::Ordering},
};

use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};

use crate::{
    arena::{ArenaHandle, ArenaRef, TypedArena},
    cli::InputArg,
    coff::ImageFileMachine,
    context::LinkContext,
    inputs::{InputsStore, ObjectFile, ObjectFileId},
    outputs::{OutputSection, OutputSectionId, SectionKey, create_reserved_sections},
    reader::InputsReader,
    symbols::{GlobalSymbol, MapEntry, SymbolId},
    timing::ScopedTimer,
};

pub struct Linker<'a> {
    pub architecture: ImageFileMachine,
    strings: ArenaHandle<'a, u8>,
    sections: ArenaHandle<'a, OutputSection<'a>>,
    pub objs: Vec<ArenaRef<'a, ObjectFile<'a>>>,
    pub output_sections: Vec<ArenaRef<'a, OutputSection<'a>>>,
    pub root_symbols: Vec<SymbolId>,
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
            strings,
            sections: ctx.section_pool.get(),
            objs: input_objs.into_vec(),
            root_symbols: Vec::new(),
            output_sections: Vec::new(),
        })
    }

    pub fn mangle(&self, name: &'a [u8]) -> &'a [u8] {
        if self.architecture != ImageFileMachine::I386 {
            return name;
        }

        self.strings.alloc_bytes([b"_", name].concat().as_slice())
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
        self.output_sections = create_reserved_sections(&self.sections);

        // Go through input sections and key them based on their names and
        // characteristics. This optimistically maps them assuming that grouped
        // sections will be merged. Any unknown sections that cannot be mapped
        // to a reserved section need to be allocated

        let mut global_map = HashMap::<SectionKey, OutputSectionId>::new();
        let map_ref = RwLock::new((&mut global_map, &mut self.output_sections));

        self.objs
            .par_iter_mut()
            .map(|obj| {
                // Assign input sections to known output sections while collecting
                // a list of unhandled inputs
                let unhandled = obj.assign_known_output_sections();
                (obj, unhandled)
            })
            .filter(|(_, unhandled)| !unhandled.is_empty())
            .for_each_init(
                || (&map_ref, ctx.section_pool.get()),
                |(map_ref, section_arena), (obj, local_map)| {
                    // Go through non-empty lists of object-local unhandled sections and allocate
                    // new output sections for them. Hopefully, there are not that many object files
                    // which need new output sections allocated so this will not run as often
                    let mut global_map = map_ref.write().unwrap();
                    let mut map = std::mem::take(global_map.0);
                    for (key, unhandled) in local_map {
                        let entry = map.entry(key);
                        let id = *entry.or_insert_with_key(|key| {
                            let id = OutputSectionId::new(global_map.1.len());
                            global_map.1.push(
                                section_arena
                                    .alloc_ref(OutputSection::new(id, key.name, key.flags, false)),
                            );
                            id
                        });

                        unhandled.into_iter().for_each(|index| {
                            log::debug!(
                                "{}: handling assignment for input section {index}",
                                obj.source()
                            );
                            let section = obj.input_section_mut(index).unwrap();
                            section.output = id;
                        });
                    }

                    let _ = std::mem::replace(global_map.0, map);
                },
            );
    }
}
