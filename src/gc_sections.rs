use std::sync::atomic::Ordering;

use object::{SectionIndex, SymbolIndex};
use rayon::{
    Scope,
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelIterator,
    },
};

use crate::{
    arena::ArenaRef,
    coff::SectionFlags,
    context::LinkContext,
    fatal,
    linker::Linker,
    object::{InputSection, ObjectFile, ObjectFileId},
    symbols::Symbol,
    timing::ScopedTimer,
};

impl<'a> Linker<'a> {
    pub fn do_gc(&mut self, ctx: &mut LinkContext<'a>) {
        let _timer = ScopedTimer::msg("gc sections");

        // Establish the list of GC roots
        let (symbol_roots, obj_roots) = rayon::join(
            || {
                self.gc_roots
                    .iter()
                    .filter_map(|&symbol| {
                        let symbol = ctx.symbol_map.get(symbol).unwrap();
                        let global = symbol.read();
                        let section_index = global.section()?;
                        let owner = &self.objs[global.owner.index()];
                        let section = owner.sections[section_index.0].as_ref().unwrap();
                        if section_is_live(section) && should_visit(section) {
                            Some((owner.id, section.index))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            },
            || {
                // Go through the object files and keep sections that should always be kept
                self.objs
                    .par_iter()
                    .flat_map_iter(|obj| {
                        obj.sections.iter().flatten().filter_map(|section| {
                            if section.discarded.load(Ordering::Relaxed) {
                                return None;
                            }

                            if metadata_section(section)
                                && section_is_live(section)
                                && should_visit(section)
                                && (!section.coff_relocs.is_empty()
                                    || !section.followers.is_empty())
                            {
                                Some((obj.id, section.index))
                            } else {
                                None
                            }
                        })
                    })
                    .collect::<Vec<_>>()
            },
        );

        // If the list of GC roots derived from symbols is empty, the result of
        // --gc-sections would discard every section except for metadata sections
        // and their outgoing references.
        // Exit with an error if that is the case since this would discard sections
        // that need to be included.
        if symbol_roots.is_empty() {
            fatal!(
                "cannot establish --gc-sections roots from --entry, --undefined, and --require-defined option set"
            );
        }

        // Visit sections reachable from the root sections
        rayon::in_place_scope(|scope| {
            symbol_roots
                .into_par_iter()
                .chain(obj_roots.into_par_iter())
                .for_each(|(obj, section_index)| {
                    visit_section(&*ctx, &self.objs, obj, section_index, scope);
                });
        });

        // Discard unreachable sections
        let mut discarded = Vec::with_capacity(self.objs.len());
        self.objs
            .par_iter_mut()
            .map(|obj| {
                let obj = obj.as_mut();
                obj.sections
                    .iter_mut()
                    .flatten()
                    .filter_map(|section| {
                        if !*section.gc_visited.get_mut() && !*section.discarded.get_mut() {
                            *section.discarded.get_mut() = true;
                            Some((obj.id, section.index))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect_into_vec(&mut discarded);

        if ctx.options.print_gc_sections {
            discarded.into_iter().flatten().for_each(|(obj, section)| {
                let obj = &self.objs[obj.index()];
                let section = obj.section(section).unwrap();
                // Do not print empty .text, .data, .bss sections from COFF imports
                // to reduce clutter
                let names: [&[u8]; 3] = [b".text", b".data", b".bss"];
                if obj.has_import_data
                    && names.contains(&section.name)
                    && section.length == 0
                    && section.coff_relocs.is_empty()
                {
                    return;
                }

                log::info!(
                    "{}: discarding {}",
                    obj.source(),
                    String::from_utf8_lossy(section.name),
                );
            });
        }
    }
}

fn visit_section<'scope, 'a: 'scope>(
    ctx: &'scope LinkContext<'a>,
    objs: &'scope [ArenaRef<'a, ObjectFile<'a>>],
    obj: ObjectFileId,
    section: SectionIndex,
    scope: &Scope<'scope>,
) {
    let obj = &objs[obj.index()];
    let section = obj.sections[section.0].as_ref().unwrap();

    // The section should get marked by the caller as visited before this gets
    // called
    debug_assert!(section.gc_visited.load(Ordering::Relaxed));

    let associative_relocs = section
        .followers
        .iter()
        .flat_map(|index| obj.sections[index.0].as_ref())
        .flat_map(|section| section.coff_relocs.iter());

    for reloc in section.coff_relocs.iter().chain(associative_relocs) {
        // Skip over relocations to invalid symbols
        let Some(symbol) = obj.coff_symbol(reloc.symbol()) else {
            continue;
        };

        if symbol.is_global() {
            let (_, external_ref) = obj.external_symbol_ref(ctx, reloc.symbol()).unwrap();
            let global = external_ref.read();
            visit_symbol(ctx, objs, global.owner, global.index, scope);
        } else {
            visit_definition(ctx, objs, obj.id, symbol.section(), scope);
        }
    }
}

fn visit_symbol<'scope, 'a: 'scope>(
    ctx: &'scope LinkContext<'a>,
    objs: &'scope [ArenaRef<'a, ObjectFile<'a>>],
    obj: ObjectFileId,
    index: SymbolIndex,
    scope: &Scope<'scope>,
) {
    let obj = &objs[obj.index()];
    let symbol = obj.coff_symbol(index).unwrap();
    // Visit the default symbol if visiting a weak external
    if symbol.is_weak() {
        let weak_aux = obj.coff_symbols.aux_weak_external(index).unwrap();
        visit_symbol(ctx, objs, obj.id, weak_aux.default_symbol(), scope);
    } else {
        visit_definition(ctx, objs, obj.id, symbol.section(), scope);
    }
}

fn visit_definition<'scope, 'a: 'scope>(
    ctx: &'scope LinkContext<'a>,
    objs: &'scope [ArenaRef<'a, ObjectFile<'a>>],
    obj: ObjectFileId,
    number: Option<SectionIndex>,
    scope: &Scope<'scope>,
) {
    if let Some(section_index) = number {
        let owner = &objs[obj.index()];
        let section = owner.section(section_index).unwrap();
        if section_is_live(section) && should_visit(section) {
            scope.spawn(|scope| {
                visit_section(ctx, objs, owner.id, section.index, scope);
            });
        }
    }
}

fn section_is_live(section: &InputSection) -> bool {
    !section.discarded.load(Ordering::Relaxed)
}

fn should_visit(section: &InputSection) -> bool {
    section
        .gc_visited
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map(|visited| !visited)
        .unwrap_or(false)
}

fn metadata_section(section: &InputSection) -> bool {
    // Always keep debug sections. These should not be present unless `--no-strip-debug`
    // was specified

    let has_debug_flags = section.characteristics.contains(
        SectionFlags::CntInitializedData | SectionFlags::MemRead | SectionFlags::MemDiscardable,
    );

    let codeview_names = [b".debug$F", b".debug$P", b".debug$S", b".debug$T"];

    if has_debug_flags
        && (codeview_names.iter().any(|&n| n == section.name)
            || section.name.starts_with(b".debug_"))
    {
        return true;
    }

    // Also keep import data
    let has_idata_flags = section.characteristics.contains(
        SectionFlags::CntInitializedData | SectionFlags::MemRead | SectionFlags::MemWrite,
    );

    let import_names = [
        b".idata$2",
        b".idata$3",
        b".idata$4",
        b".idata$5",
        b".idata$6",
        b".idata$7",
    ];

    has_idata_flags && import_names.iter().any(|&n| n == section.name)
}
