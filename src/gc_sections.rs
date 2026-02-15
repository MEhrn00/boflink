use std::sync::atomic::Ordering;

use object::SectionIndex;
use rayon::{
    Scope,
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelIterator,
    },
};

use crate::{
    arena::ArenaRef,
    coff::{SectionFlags, SectionNumber},
    context::LinkContext,
    fatal,
    linker::Linker,
    object::{InputSection, ObjectFile, ObjectFileId},
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
                        let global = symbol.read().unwrap();
                        let section_index = global.section_number.index()?;
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

                            if retained_section(section)
                                && section_is_live(section)
                                && should_visit(section)
                                && (!section.coff_relocs.is_empty()
                                    || !section.associative_edges.is_empty())
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
        // --gc-sections would discard every section since the kept sections from
        // object files are metadata sections. Exit with an error if that is the case
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

    let visit_definition = |obj: ObjectFileId, number: SectionNumber| {
        if let Some(section_index) = number.index() {
            let owner = &objs[obj.index()];
            let section = owner.sections[section_index.0].as_ref().unwrap();
            if section_is_live(section) && should_visit(section) {
                scope.spawn(|scope| {
                    visit_section(ctx, objs, owner.id, section.index, scope);
                });
            }
        }
    };

    let associative_relocs = section
        .associative_edges
        .iter()
        .flat_map(|index| obj.sections[index.0].as_ref())
        .flat_map(|section| section.coff_relocs.iter());

    for reloc in section.coff_relocs.iter().chain(associative_relocs) {
        let symbol_index = reloc.symbol();
        // Skip over relocations to invalid symbols
        let Some(symbol) = obj.symbols.get(symbol_index.0) else {
            continue;
        };

        let Some(symbol) = symbol.as_ref() else {
            continue;
        };

        if let Some(external_ref) = symbol.external_id {
            let global_ref = ctx.symbol_map.get(external_ref).unwrap();
            let global = global_ref.read().unwrap();
            visit_definition(global.owner, global.section_number);
        } else {
            visit_definition(obj.id, symbol.section_number);
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

fn retained_section(section: &InputSection) -> bool {
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
