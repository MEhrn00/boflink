//! Main link driver.
//!
//! This module contains implemenrations for the linker passes.

use std::collections::HashMap;

use boflink_arena::{BumpHandle, TypedArena, TypedArenaRef};
use boflink_index::{
    IndexVec,
    bit_set::{AtomicDenseBitSet, DenseBitSet},
};
use bstr::BStr;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};

use crate::{
    bail,
    cli::InputArg,
    coff::{ImageFileMachine, SectionIndex, SymbolIndex},
    context::LinkContext,
    fatal,
    inputs::InputsReader,
    object::{ObjectFile, ObjectFileId},
    symbols::{GlobalSymbol, GlobalSymbolFlags, Symbol, SymbolId, SymbolMap, SyncSymbolMap},
    timing::ScopedTimer,
    workqueue::{ParallelWorkQueue, WorkExtender},
};

pub struct LinkInputs<'a> {
    architecture: ImageFileMachine,
    live_objs: Vec<ObjectFileId>,
    symbols: SymbolMap<'a>,
    objs: IndexVec<ObjectFileId, TypedArenaRef<'a, ObjectFile<'a>>>,
    required_symbols: Vec<SymbolId>,
    gc_roots: Vec<SymbolId>,
    bump: BumpHandle<'a>,
}

impl<'a> LinkInputs<'a> {
    pub fn read_inputs(ctx: &mut LinkContext<'a>, inputs: &'a [InputArg]) -> crate::Result<Self> {
        let _timer = ScopedTimer::msg("read inputs");
        let obj_store = TypedArena::new();

        let mut reader = InputsReader::new(ctx, &obj_store);
        let symbols = SyncSymbolMap::with_map_count(
            ctx.options.threads.map(|threads| threads.get()).unwrap(),
        );

        rayon::in_place_scope(|scope| {
            reader.read_cli_inputs(ctx, scope, inputs, &symbols);
        });

        let architecture = reader.architecture;
        let initial_set = reader.live_objs;
        let objs = IndexVec::from_raw(obj_store.into_vec());

        ctx.exit_on_error();
        if objs.is_empty() {
            bail!("no input files");
        }

        if architecture == ImageFileMachine::Unknown {
            bail!("unable to detect target architecture from input files");
        }

        let symbols = symbols.into_unsync();
        *ctx.stats.globals.get_mut() = symbols.len();

        Ok(Self {
            architecture,
            live_objs: initial_set,
            symbols,
            objs,
            gc_roots: Vec::new(),
            required_symbols: Vec::new(),
            bump: ctx.bump_pool.get(),
        })
    }

    pub fn add_symbols(&mut self, ctx: &LinkContext<'a>) {
        let mangle = |name: &'a str| {
            if self.architecture != ImageFileMachine::I386 {
                return BStr::new(name);
            }

            let mangled = [b"_", name.as_bytes()].concat();
            let mangled = self.bump.alloc_bytes(&mangled);
            BStr::new(mangled)
        };

        let symbols = &mut self.symbols;
        let mut add_symbol = |name: &'a str| -> SymbolId {
            let symbol = symbols.get_map_entry(mangle(name));
            let id = symbol.id();
            symbol.or_default();
            id
        };

        // Add all command line symbols as GC roots
        for name in [&ctx.options.entry]
            .into_iter()
            .chain(ctx.options.require_defined.iter())
            .chain(ctx.options.undefined.iter())
        {
            self.gc_roots.push(add_symbol(name));
        }

        // Add require defined symbols
        for name in ctx.options.require_defined.iter() {
            self.required_symbols.push(add_symbol(name));
        }

        let mut set_flags = |name: &'a str, flags: GlobalSymbolFlags| {
            let symbol = symbols.get_map_entry(mangle(name));
            symbol.or_default().flags |= flags
        };

        // Add traced symbols
        for name in ctx.options.trace_symbol.iter() {
            set_flags(name, GlobalSymbolFlags::Traced);
        }

        // Add ignored undefined symbols
        for name in ctx.options.ignore_unresolved_symbol.iter() {
            set_flags(name, GlobalSymbolFlags::AllowUndefined);
        }
    }

    pub fn resolve_symbols(mut self, ctx: &LinkContext<'a>) -> Linker<'a> {
        let timer = ScopedTimer::msg("symbol resolution");

        // Initialize definitions for global symbols
        self.objs.par_iter_enumerated().for_each(|(id, obj)| {
            obj.resolve_symbols(id, &self.symbols);
        });

        // Collect the list of live objects from command line inputs and symbol
        // flags
        let queue = ParallelWorkQueue::new();
        let mut live_set = DenseBitSet::new_empty(self.objs.len());

        let mut mark_live = |id| {
            if live_set.insert(id) {
                queue.push_back(id);
            }
        };

        // Mark command line inputs as live
        for obj in std::mem::take(&mut self.live_objs) {
            mark_live(obj);
        }

        // Mark objects containing GC root symbols as live
        let gc_roots = self.gc_roots.iter();
        for &symbol in gc_roots {
            let global = self.symbols.get_exclusive_symbol(symbol).unwrap();
            if !global.is_undefined() {
                mark_live(global.owner);
            }
        }

        let live_set: AtomicDenseBitSet<_> = live_set.into();

        // Traverse through the object files to transitively include any
        // dependent object files that satisfy their undefined symbols
        queue.run(|extender, objid| {
            let obj = &self.objs[objid];
            obj.include_needed_objects(ctx, &self.symbols, &live_set, &self.objs, |objid| {
                extender.add(objid);
            });
        });

        let live_set: DenseBitSet<ObjectFileId> = live_set.into();

        // Lazy object files only had their external symbols initialized during
        // parsing. Go through and initialize sections/locals for object files
        // newly marked live
        self.objs.par_iter_enumerated_mut().for_each(|(id, obj)| {
            if obj.parsed_lazy()
                && live_set.contains(id)
                && let Err(e) = obj.initialize(ctx)
            {
                log::error!(logger: ctx, "cannot parse {}: {e}", obj.file);
            }
        });

        ctx.exit_on_error();

        // Handle COMDATs
        self.resolve_comdats(&live_set);

        // Redo symbol resolution from a clean slate only with the live object
        // files
        let objs = std::mem::take(&mut self.objs);

        let (objs, _) = rayon::join(
            || {
                objs.into_par_iter_enumerated()
                    .filter_map(|(i, obj)| live_set.contains(i).then_some(obj))
                    .collect::<IndexVec<_, _>>()
            },
            || {
                self.symbols.par_for_each_symbol(|symbol| {
                    let mut flags = symbol.flags;
                    flags.remove(
                        GlobalSymbolFlags::Weak
                            | GlobalSymbolFlags::Function
                            | GlobalSymbolFlags::Imported,
                    );
                    *symbol = GlobalSymbol::new(symbol.name);
                    symbol.flags = flags;
                });
            },
        );

        self.objs = objs;
        self.objs.par_iter_enumerated().for_each(|(id, obj)| {
            obj.resolve_symbols(id, &self.symbols);
        });

        // Resolve common symbols after regular definitions have been re-selected
        self.objs.par_iter_enumerated().for_each(|(id, obj)| {
            obj.resolve_common_symbols(id, &self.symbols);
        });

        // Report duplicate symbols
        self.report_duplicate_symbols(ctx);

        // Set owners for remaining undefined symbols
        self.objs.par_iter_enumerated_mut().for_each(|(id, obj)| {
            obj.claim_undefined_symbols(id, &self.symbols);
        });

        timer.stop();
        log::debug!("found {} live objects", self.objs.len());

        Linker {
            architecture: self.architecture,
            symbols: self.symbols,
            objs: self.objs,
            gc_roots: self.gc_roots,
            bump: self.bump,
        }
    }

    /// Resolve and deduplicate COMDAT definitions
    fn resolve_comdats(&mut self, live_set: &DenseBitSet<ObjectFileId>) {
        let objs = &self.objs;
        let symbols = &self.symbols;

        self.objs.par_iter_enumerated().for_each(|(id, obj)| {
            if obj.has_comdats() && live_set.contains(id) {
                obj.resolve_comdat_leaders(id, symbols, live_set, objs);
            }
        });

        self.objs.par_iter_enumerated_mut().for_each(|(id, obj)| {
            if obj.has_comdats() && live_set.contains(id) {
                obj.discard_unclaimed_comdats(id, symbols);
            }
        });
    }

    /// Logs duplicate symbol definitions and exits if any were found
    fn report_duplicate_symbols(&self, ctx: &LinkContext<'a>) {
        let symbols = &self.symbols;
        let objs = self.objs.as_slice();

        let duplicate_errors = self
            .objs
            .par_iter_enumerated()
            .filter_map(|(id, obj)| {
                let errors = obj.collect_duplicate_symbol_errors(ctx, id, symbols, objs);
                (!errors.is_empty()).then_some(errors)
            })
            .collect::<Vec<_>>();

        for error in duplicate_errors.iter().flatten() {
            log::error!(logger: ctx, "{error}");
        }

        ctx.exit_on_error();
    }
}

pub struct Linker<'a> {
    architecture: ImageFileMachine,
    symbols: SymbolMap<'a>,
    objs: IndexVec<ObjectFileId, TypedArenaRef<'a, ObjectFile<'a>>>,
    gc_roots: Vec<SymbolId>,
    bump: BumpHandle<'a>,
}

impl<'a> Linker<'a> {
    pub fn do_gc(&mut self, ctx: &LinkContext<'a>) {
        let timer = ScopedTimer::msg("gc sections");

        let objs = self.objs.as_slice();
        let symtab = &self.symbols;

        let queue = ParallelWorkQueue::new();

        let visit_section =
            |id: ObjectFileId,
             obj: &ObjectFile<'a>,
             i: SectionIndex,
             extender: WorkExtender<(ObjectFileId, SectionIndex)>| {
                let section = obj.sections[i].as_ref().unwrap();
                if section.live && section.mark_visited() {
                    extender.add((id, i));
                }
            };

        let visit_symbol = |id: SymbolId, extender| {
            let external = symtab.get(id).unwrap();
            let global = external.read();
            if !(global.is_undefined() || global.is_common()) {
                let obj = &objs[global.owner];
                let i = global.section_index().unwrap();
                visit_section(global.owner, obj, i, extender);
            }
        };

        // Establish the initial GC root sections from the list of symbols
        queue.extender(|extender| {
            self.gc_roots
                .iter()
                .for_each(|&symbol| visit_symbol(symbol, extender.clone()));
        });

        // If the root sections are empty, there are no definitions for the
        // symbols specified on the command line. This is a fatal error since
        // it would discard every section except for debug sections
        if queue.is_empty() {
            fatal!(
                "cannot establish --gc-sections roots from --entry, --undefined, and --require-defined option values"
            );
        }

        // Visit sections reachable from the GC roots
        queue.run(|extender, (objid, section_index)| {
            let obj = &objs[objid];
            let section = obj.sections[section_index].as_ref().unwrap();

            let visit_section = |i: SectionIndex| {
                visit_section(objid, obj, i, extender.clone());
            };

            for reloc in section.relocs.iter() {
                let symbol = SymbolIndex(reloc.symbol().0 as u32);
                if let Ok(coff_symbol) = obj.coff_symbols.symbol(symbol) {
                    if coff_symbol.is_global() {
                        let symbol = obj.symbols[symbol].as_ref().unwrap().external().unwrap();
                        visit_symbol(symbol.id, extender.clone());
                    } else if let Some(i) = coff_symbol.section_index() {
                        visit_section(i);
                    }
                }
            }

            for (i, _) in obj.followers(section_index) {
                visit_section(i);
            }
        });

        // Discard sections not visited
        let mut discarded = Vec::with_capacity(self.objs.len());
        self.objs
            .par_iter_enumerated_mut()
            .map(|(id, obj)| {
                let obj = obj.as_mut();
                obj.sections
                    .iter_enumerated_mut()
                    .filter_map(|(i, section)| section.as_mut().map(|section| (i, section)))
                    .filter_map(|(i, section)| {
                        (!*section.visited.get_mut() && section.live).then(|| {
                            section.live = false;
                            (id, i)
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect_into_vec(&mut discarded);

        timer.stop();
        if ctx.options.print_gc_sections {
            discarded.into_iter().flatten().for_each(|(obj, section)| {
                let obj = &self.objs[obj];
                let section = obj.sections[section].as_ref().unwrap();

                // Do not print empty .text, .data, .bss sections from COFF imports
                // to reduce clutter
                let names: [&[u8]; 3] = [b".text", b".data", b".bss"];
                if obj.has_import_metadata() && names.iter().any(|name| *name == section.name) {
                    return;
                }

                log::info!("{}: discarding {}", obj.file, section.name);
            });
        }
    }

    /// Removes sections containing duplicate GCC identification strings
    pub fn dedup_gcc_ident(&mut self) {
        let idents = self
            .objs
            .par_iter_mut()
            .map(|obj| {
                obj.sections
                    .iter_mut()
                    .flatten()
                    .filter_map(|section| {
                        (section.live && section.relocs.is_empty() && section.name == b".rdata$zzz")
                            .then(|| {
                                section.live = false;
                                (section.check_sum, section)
                            })
                    })
                    .collect::<HashMap<_, _>>()
            })
            .reduce(HashMap::new, |mut a, b| {
                a.extend(b);
                a
            });

        idents.into_par_iter().for_each(|(_, section)| {
            section.live = true;
        });
    }

    pub fn define_common_symbols(&mut self) {
        self.objs.par_iter_enumerated_mut().for_each(|(id, obj)| {
            obj.define_common_symbols(id, &self.symbols);
        });
    }
}
