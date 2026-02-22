//! Main link driver.
//!
//! This module contains implemenrations for the linker passes.
use std::{collections::HashMap, sync::atomic::Ordering};

use bstr::BStr;
use indexmap::IndexMap;
use parking_lot::RwLockUpgradableReadGuard;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelExtend, ParallelIterator,
};

use crate::{
    arena::{ArenaHandle, ArenaRef, TypedArena},
    cli::InputArg,
    coff::{ImageFileMachine, Section, SectionFlags, Symbol},
    context::LinkContext,
    inputs::{InputsReader, InputsStore},
    object::{InputSection, ObjectFile, ObjectFileId},
    outputs::{
        MappedSection, OutputFile, OutputFileHeader, OutputSection, OutputSectionId,
        OutputSectionPartials, SectionKey, create_reserved_sections,
    },
    symbols::{GlobalSymbol, GlobalSymbolFlags, SymbolId},
    timing::ScopedTimer,
};

/// Structure with all of the link information.
///
/// This is designed to act as a container for holding different collections of
/// artifacts. It is treated more as a plain data container with some methods
/// rather than having a defined API
pub struct Linker<'a> {
    /// Input object files
    pub objs: Vec<ArenaRef<'a, ObjectFile<'a>>>,

    /// The output file
    pub output: OutputFile<'a>,

    /// Symbols which require definitions at the end of the link
    required_symbol: Vec<SymbolId>,

    /// GC root symbols
    pub gc_roots: Vec<SymbolId>,

    /// Exclusive arena handle for allocating strings
    strings: ArenaHandle<'a, u8>,
}

impl<'a> Linker<'a> {
    /// Reads a set of [`InputArg`]s and creates the initial linker structure
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
            output: OutputFile {
                header: OutputFileHeader {
                    machine: reader.architecture,
                    ..Default::default()
                },
                ..Default::default()
            },
            objs: input_objs.into_vec(),
            required_symbol: Vec::new(),
            gc_roots: Vec::new(),
            strings,
        })
    }

    /// Mangles the specified name using the mangling scheme from the linker
    /// architecture.
    pub fn arch_mangle(&self, name: &'a BStr) -> &'a BStr {
        if self.output.architecture() != ImageFileMachine::I386 {
            return name;
        }

        let mangled = [b"_", AsRef::<[u8]>::as_ref(name)].concat();
        let mangled = self.strings.alloc_bytes(&mangled);
        BStr::new(mangled)
    }

    /// Adds the specified symbol as a GC root.
    ///
    /// The symbol name should not be mangled before calling this function.
    pub fn add_gc_root(&mut self, ctx: &mut LinkContext<'a>, name: &'a BStr) {
        let name = self.arch_mangle(name);
        let symbol = ctx.symbol_map.get_map_entry(name);
        let id = symbol.id();
        symbol.or_default();
        if !self.gc_roots.contains(&id) {
            self.gc_roots.push(id);
        }
    }

    /// Adds a symbol that requires a definition at the end of linking.
    ///
    /// This only adds the symbol and stores an ID for. The check needs to be
    /// done explicitly
    pub fn add_required_symbol(&mut self, ctx: &mut LinkContext<'a>, name: &'a BStr) {
        let name = self.arch_mangle(name);
        let symbol = ctx.symbol_map.get_map_entry(name);
        let id = symbol.id();
        symbol.or_default();
        if !self.required_symbol.contains(&id) {
            self.required_symbol.push(id);
        }
    }

    /// Marks the specified symbol for trace output
    pub fn add_traced_symbol(&mut self, ctx: &mut LinkContext<'a>, name: &'a BStr) {
        let symbol = ctx
            .symbol_map
            .get_map_entry(self.arch_mangle(name))
            .or_default();
        symbol.set_traced(true);
    }

    pub fn add_ignored_undefined_symbol(&mut self, ctx: &mut LinkContext<'a>, name: &'a BStr) {
        let symbol = ctx
            .symbol_map
            .get_map_entry(self.arch_mangle(name))
            .or_default();
        symbol.flags |= GlobalSymbolFlags::AllowUndefined;
    }

    /// Handles resolving symbols from the currently held object files.
    ///
    /// This will go through and mark object files as live which should be included
    /// in the linked output
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
        let live_symbols = self.gc_roots.iter().chain(self.required_symbol.iter());
        for &symbol in live_symbols {
            let global = ctx.symbol_map.get_exclusive_symbol(symbol).unwrap();
            if !global.owner.is_internal() {
                self.objs[global.owner.index()].set_live(true);
            }
        }

        let live_objs = self
            .objs
            .par_iter_mut()
            .filter_map(|obj| {
                // Set command line input object files or `--whole-archive` members
                // as live
                if !obj.lazy {
                    obj.set_live(true);
                }

                if obj.is_live() { Some(obj.id) } else { None }
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

        // Initial parsing of object files only initialized external symbol references
        // for lazy object files. Now that the list of live object files is known,
        // fully initialize the sections and symbols in extracted object files
        self.objs.par_iter_mut().for_each(|obj| {
            let initialize = |obj: &mut ArenaRef<'a, ObjectFile<'a>>| -> crate::Result<()> {
                obj.initialize_sections(ctx)?;
                obj.initialize_symbols(ctx)?;
                Ok(())
            };

            if obj.lazy
                && obj.is_live()
                && let Err(e) = initialize(obj)
            {
                log::error!(logger: &*ctx, "cannot parse {}: {e}", obj.source());
            }
        });

        ctx.exclusive_check_errored();

        // Resolve COMDAT leaders for live objects. This needs to happen for live
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

        // Redo symbol resolution from a clean slate using only the included object
        // files. This fixes the global symbol map in cases where an early object
        // file was chosen during the first symbol resolution pass but a later
        // object file has the definition being used
        ctx.symbol_map.par_for_each_symbol(|symbol| {
            *symbol = GlobalSymbol {
                name: symbol.name,
                flags: symbol.flags,
                ..Default::default()
            };
        });

        // Remove unused objects to shrink the list before re-resolving symbols.
        self.objs = std::mem::take(&mut self.objs)
            .into_par_iter()
            .filter_map(|mut obj| if obj.is_live() { Some(obj) } else { None })
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

    /// Fixes definitions for common symbols
    ///
    /// The rules for this are global definition > common definition > weak definition.
    /// In rare cases, this precedence can be out of order when common symbols
    /// are intermixed with weak/common symbols from extracted archive members.
    ///
    /// Regular symbol resolution will select the first common symbol seen if
    /// there are duplicates to handle archive extraction. If duplicate common
    /// symbols are present after archive extraction, the one with the largest
    /// definition should be used.
    ///
    /// There are many weird rules with common symbols. They hardly make sense
    /// in C/C++ but for some reason, were added to mimic FORTRAN 77 behavior.
    /// GCC and Clang have defaulted to `-fno-common` so common symbols should
    /// not be seen when using those compilers.
    /// MSVC unfortunately still uses common symbols...
    pub fn fix_commons_resolution(&mut self, ctx: &LinkContext<'a>) {
        self.objs
            .par_iter_mut()
            .filter(|obj| obj.has_common_symbols)
            .for_each(|obj| {
                let obj = obj.as_mut();

                for (i, symbol) in obj.coff_symbols.iter() {
                    if !symbol.is_common() {
                        continue;
                    }

                    let external_ref = obj.symbols.external_symbol_ref(ctx, i).unwrap();
                    let mut global = external_ref.write();
                    if global.owner == obj.id {
                        continue;
                    }

                    // Two common definitions for the same symbol should use the largest
                    // one. Common symbols also use the definition for weak symbols.
                    if global.is_weak() || (global.is_common() && symbol.value() > global.value()) {
                        global.owner = obj.id;
                        global.value = symbol.value();
                        global.section_number = symbol.section_number();
                        global.storage_class = symbol.storage_class();
                        global.owner_index = i;
                    }
                }
            });
    }

    /// Creates fragmented .bss sections in object files for common symbol definitions
    pub fn define_common_symbols(&mut self, ctx: &LinkContext<'a>) {
        self.objs
            .par_iter_mut()
            .filter(|obj| obj.has_common_symbols)
            .for_each(|obj| {
                let obj = obj.as_mut();
                for (i, symbol) in obj.coff_symbols.iter() {
                    if !symbol.is_common() {
                        continue;
                    }

                    let external_ref = obj.symbols.external_symbol_ref(ctx, i).unwrap();
                    {
                        let global = external_ref.read();
                        if global.owner != obj.id {
                            continue;
                        }
                    }

                    let mut flags = SectionFlags::CntUninitializedData
                        | SectionFlags::MemRead
                        | SectionFlags::MemWrite;

                    flags.set_alignment(symbol.value().next_power_of_two().min(8192u32));

                    let index = obj.sections.push(InputSection {
                        name: BStr::new(b".bss"),
                        flags,
                        length: symbol.value(),
                        ..Default::default()
                    });

                    // Only one symbol should acquire this lock so there are
                    // not any data races here due to double locking
                    let mut global = external_ref.write();
                    global.value = 0;
                    global.section_number = index.0 as i32;
                }
            });
    }

    /// Logs any symbol errors related to duplicate definitions.
    ///
    /// This will exit the program if any are found.
    pub fn report_duplicate_symbols(&mut self, ctx: &LinkContext<'a>) {
        // Collect errors into a Vec such that the ordering of reported errors
        // is deterministic and follows the ordering of input files
        let duplicate_errors = self
            .objs
            .par_iter()
            .filter_map(|obj| {
                let errors = obj.collect_duplicate_symbol_errors(ctx, &self.objs);
                // Filter out empty errors to reduce the potential size of the
                // collected errors in case something went really wrong
                if !errors.is_empty() {
                    Some(errors)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Log errors and exit if any were seen
        for error in duplicate_errors.iter().flatten() {
            log::error!("{error}");
        }

        if !duplicate_errors.is_empty() {
            std::process::exit(1);
        }
    }

    /// Creates the initial set of output sections and links them to the list of
    /// input sections.
    ///
    /// This only does output section creation and linking. Other information,
    /// such as alignment, size, etc. is not calculated. The main purpose is to
    /// get the general layout of where symbols will end up in the output file
    pub fn create_output_sections(&mut self, ctx: &mut LinkContext<'a>) {
        let _timer = ScopedTimer::msg("create output sections");
        self.output.sections = create_reserved_sections();
        let reserved_sections_len = self.output.sections.len();

        let mut partials = Vec::with_capacity(self.objs.len());
        let mut needed_outputs = Vec::with_capacity(self.objs.len());

        self.objs
            .par_iter_mut()
            .map(|obj| {
                let mut partials = OutputSectionPartials::new(reserved_sections_len);
                let mut needed_outputs = IndexMap::new();

                for (i, section) in obj.sections.enumerate_mut() {
                    if section.is_discarded() {
                        continue;
                    }

                    let key = SectionKey::new(ctx, section);
                    if let Some(output_id) = key.known_id() {
                        section.output = output_id;
                        let output_partial = partials.get_or_default(output_id);
                        output_partial.push(i);
                    } else {
                        let entry: &mut Vec<_> = needed_outputs.entry(key).or_default();
                        entry.push(i);
                    }
                }

                (partials, needed_outputs)
            })
            .unzip_into_vecs(&mut partials, &mut needed_outputs);

        let (mut new_sections, _) = rayon::join(
            || {
                let mut section_map = HashMap::new();
                let mut new_sections = Vec::new();
                for (objid, needs_map) in needed_outputs.into_iter().enumerate() {
                    for (key, input_sections) in needs_map {
                        let name = key.name();
                        let flags = key.flags();
                        let index = *section_map.entry(key).or_insert_with(|| {
                            let index = new_sections.len();
                            let id = OutputSectionId::new(reserved_sections_len + index);
                            new_sections.push(OutputSection::new(
                                id,
                                BStr::new(name),
                                flags,
                                false,
                            ));
                            index
                        });

                        let objid = ObjectFileId::new(objid);
                        let mut remaining = input_sections.len() as u32;
                        let output_section = &mut new_sections[index];
                        for input_section in input_sections {
                            remaining -= 1;
                            output_section.mappings.0.push(MappedSection {
                                remaining,
                                obj: objid,
                                index: input_section,
                                relocs: Vec::new(),
                                rva: 0,
                            });
                        }
                    }
                }
                new_sections
            },
            || {
                self.output.sections.par_iter_mut().for_each(|section| {
                    let output_id = section.id;
                    section.mappings.0.par_extend(
                        partials
                            .par_iter()
                            .enumerate()
                            .filter_map(|(objid, partial)| {
                                partial
                                    .get(output_id)
                                    .map(|list| (ObjectFileId::new(objid), list))
                            })
                            .flat_map_iter(|(obj, input_indicies)| {
                                let mut remaining = input_indicies.len() as u32;
                                input_indicies.iter().map(move |&index| {
                                    remaining -= 1;
                                    MappedSection {
                                        remaining,
                                        obj,
                                        index,
                                        relocs: Vec::new(),
                                        rva: 0,
                                    }
                                })
                            }),
                    );
                });
            },
        );

        self.output.sections.append(&mut new_sections);
        self.objs
            .par_iter_mut()
            .filter(|obj| !obj.sections.is_empty())
            .for_each(|obj| {
                let obj = obj.as_mut();
                for output_section in self.output.sections.iter() {
                    let mappings = output_section.mappings.find_object_mappings(obj.id);
                    if mappings.is_empty() {
                        continue;
                    }

                    let mapping = mappings.first().unwrap();
                    assert!(mapping.obj == obj.id);

                    for mapping in mappings.iter() {
                        let section = &mut obj.sections[mapping.index];
                        section.output = output_section.id;
                        obj.sections[mapping.index].output = output_section.id;
                    }
                }
            });
    }

    /// Discards sections defining symbols related to imports and marks those
    /// symbols as being imported.
    ///
    /// These definitions will be marked live only if needed. This has to occur
    /// after output sections are created or else needed thunk definitions will
    /// not get allocated to an output section
    pub fn mark_import_symbols(&mut self, ctx: &LinkContext<'a>) {
        self.objs
            .par_iter_mut()
            .filter(|obj| obj.has_import_data)
            .for_each(|obj| {
                let obj = obj.as_mut();
                for (i, symbol) in obj.coff_symbols.iter() {
                    let Some(section_index) = symbol.section() else {
                        continue;
                    };

                    let section = &mut obj.sections[section_index];
                    section.set_discarded(true);

                    if symbol.is_local() {
                        continue;
                    }

                    // Globals for .idata entries and code thunks get marked as
                    // imported
                    if section.contains_import_data() || section.contains_code() {
                        let external_ref = obj.symbols.external_symbol_ref(ctx, i).unwrap();
                        let mut global = external_ref.write();
                        if global.owner == obj.id {
                            global.flags.insert(GlobalSymbolFlags::Imported);
                        }
                    }
                }
            });
    }

    /// Globals initialization will only create undefined symbols but does not
    /// populate them. Symbol resolution will only handle claiming defined symbols.
    /// Undefined symbols added to the symbol table are left partially initialized
    /// and pointing to the internal object file.
    ///
    /// This will do a symbol resolution round to set owners for undefined symbols
    /// and also set symbols resolved to weak symbols to use the weak default.
    pub fn claim_undefined_symbols(&mut self, ctx: &LinkContext<'a>) {
        self.objs.par_iter_mut().for_each(|obj| {
            let obj = obj.as_mut();

            for (i, symbol) in obj.coff_symbols.iter() {
                if symbol.is_undefined() {
                    let external_ref = obj.symbols.external_symbol_ref(ctx, i).unwrap();
                    let mut global = external_ref.write();
                    if global.is_undefined()
                        && (global.owner.is_internal() || obj.id < global.owner)
                    {
                        global.owner = obj.id;
                        global.owner_index = i;
                    }
                } else if symbol.is_weak() {
                    let (external, external_ref) =
                        obj.symbols.external_symbol_ref2(ctx, i).unwrap();
                    let mut global = external_ref.write();
                    if global.owner == obj.id && global.owner_index == i {
                        // TODO: check recursive weak definitions and handle cycles.
                        // Should not be a thing but it is technically possible...
                        let default_symbol =
                            obj.coff_symbols.symbol(external.weak_default).unwrap();
                        global.value = default_symbol.value();
                        global.section_number = default_symbol.section_number();
                        global.storage_class = default_symbol.storage_class();
                        global.owner_index = external.weak_default;
                    }
                }
            }
        });
    }

    pub fn scan_relocations(&mut self, ctx: &mut LinkContext<'a>) {
        let _timer = ScopedTimer::msg("scan relocations");

        let objs = &self.objs;
        // Scan relocations against input sections
        let undefined_symbols = self
            .objs
            .par_iter()
            .filter_map(|obj| {
                obj.scan_relocations(ctx, objs)
                    .inspect_err(|e| log::error!(logger: &*ctx, "{e}"))
                    .ok()
            })
            .reduce(IndexMap::new, |mut a1, a2| {
                a1.extend(a2);
                a1
            });

        ctx.exclusive_check_errored();

        if !undefined_symbols.is_empty() {
            for (id, mut references) in undefined_symbols {
                let name = ctx.symbol_map.get_exclusive_symbol(id).unwrap().name;
                let remaining = references.len().saturating_sub(5);
                if remaining > 0 {
                    references.truncate(5);
                    references.push(format!("referenced {remaining} more times"));
                }

                let msg = format_args!(
                    "undefined symbol: {}\n{}",
                    ctx.demangle(name, self.output.architecture()),
                    references.join("\n")
                );

                if ctx.options.warn_unresolved_symbols {
                    log::warn!("{msg}");
                } else {
                    log::error!(logger: &*ctx, "{msg}");
                    std::process::exit(1);
                }
            }
        }

        // Scan relocations against output sections
        self.output.sections.par_iter_mut().for_each(|section| {
            section.scan_relocations(ctx, objs);
        });
    }

    /// Rewrites DLL imported symbols to use DFR
    pub fn rewrite_dfr_imports(&mut self, ctx: &LinkContext<'a>) {
        self.objs
            .par_iter()
            .filter(|obj| obj.has_import_data)
            .for_each_init(
                || ctx.string_pool.get(),
                |strings, obj| {
                    for (i, symbol) in obj.coff_symbols.iter() {
                        if symbol.is_local() || symbol.is_undefined() {
                            continue;
                        }

                        let section = &obj.sections[symbol.section().unwrap()];
                        // If the section is discarded, this means that the
                        // imported symbol is unreferenced by non-import objects.
                        if section.discarded.load(Ordering::Relaxed) {
                            continue;
                        }

                        let external_ref = obj.symbols.external_symbol_ref(ctx, i).unwrap();

                        let global = external_ref.upgradable_read();
                        if global.owner != obj.id {
                            continue;
                        }

                        let owner = &self.objs[global.owner.index()];
                        let Some(dllname) = owner.resolve_import_dllname(ctx, &self.objs) else {
                            continue;
                        };

                        let mut global = RwLockUpgradableReadGuard::upgrade(global);
                        let mut name = global.name.strip_prefix(b"__imp_").unwrap_or(global.name);
                        if obj.machine == ImageFileMachine::I386 {
                            name = name.strip_prefix(b"_").unwrap_or(name);
                            name = strings
                                .alloc_bytes([b"__imp__", dllname, b"$", name].concat().as_slice());
                        } else {
                            name = strings
                                .alloc_bytes([b"__imp_", dllname, b"$", name].concat().as_slice());
                        };
                        global.name = BStr::new(name);
                    }
                },
            );
    }

    pub fn sort_section_mappings(&mut self, ctx: &LinkContext<'a>) {
        let _timer = ScopedTimer::msg("sort grouped sections");
        self.output
            .sections
            .par_iter_mut()
            .filter(|section| !section.exclude)
            .for_each(|section| {
                section.sort_mappings(ctx, &self.objs);
            });
    }

    pub fn compute_sections(&mut self, ctx: &LinkContext<'a>) {}
}
