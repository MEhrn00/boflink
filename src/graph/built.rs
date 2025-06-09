use std::{
    cell::OnceCell,
    collections::{BTreeMap, LinkedList},
};

use indexmap::IndexMap;
use log::{debug, warn};
use object::{
    pe::{
        IMAGE_FILE_LINE_NUMS_STRIPPED, IMAGE_REL_AMD64_REL32, IMAGE_REL_I386_DIR32,
        IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA,
        IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_STATIC,
        IMAGE_SYM_TYPE_NULL,
    },
    write::coff::{Relocation, SectionHeader, Writer},
};

use crate::linker::LinkerTargetArch;

use super::{
    edge::{ComdatSelection, DefinitionEdgeWeight, Edge, RelocationEdgeWeight},
    link::{LinkGraph, LinkGraphArena},
    node::{
        CoffNode, LibraryNode, ReachableDfs, SectionNode, SectionNodeCharacteristics,
        SectionNodeData, SymbolName, SymbolNode, SymbolNodeStorageClass, SymbolNodeType,
    },
};

const SECTION_ALIGN_SHIFT: u32 = 20;

#[derive(Debug, thiserror::Error)]
pub enum LinkGraphLinkError {
    #[error("{coff_name}: {reference} references symbol '{symbol}' defined in discarded section.")]
    DiscardedSection {
        coff_name: String,
        reference: String,
        symbol: String,
    },

    #[error(
        "{coff_name}: {section}+{address:#x} relocation is outside section bounds (size = {size:#x})."
    )]
    RelocationBounds {
        coff_name: String,
        section: String,
        address: u32,
        size: u32,
    },

    #[error("{coff_name}: relocation adjustment at '{section}+{address:#x}' overflowed.")]
    RelocationOverflow {
        coff_name: String,
        section: String,
        address: u32,
    },
}

/// An output section with the header and contained sections.
#[derive(Default)]
pub(super) struct OutputSection<'arena, 'data> {
    /// The section header
    header: SectionHeader,

    /// The list of nodes contained in this output section.
    pub nodes: Vec<&'arena SectionNode<'arena, 'data>>,
}

/// The built link graph with all of the processed inputs.
///
/// This graph does not allow adding any more inputs and is only used for
/// post-processing and building the linked output file.
pub struct BuiltLinkGraph<'arena, 'data> {
    /// Machine value for the output COFF.
    machine: LinkerTargetArch,

    /// The sections.
    sections: IndexMap<&'arena str, OutputSection<'arena, 'data>>,

    /// The node for the COMMON section.
    common_section: OnceCell<&'arena SectionNode<'arena, 'data>>,

    /// Pseudo-COFF for holding metadata sections.
    root_coff: &'arena CoffNode<'data>,

    /// The library nodes in the graph.
    library_nodes: IndexMap<&'data str, &'arena LibraryNode<'arena, 'data>>,

    /// The API node if it exists.
    api_node: Option<&'arena LibraryNode<'arena, 'data>>,

    /// The symbol with external storage class.
    external_symbols: IndexMap<&'data str, &'arena SymbolNode<'arena, 'data>>,

    /// Graph arena allocator.
    arena: &'arena LinkGraphArena,
}

impl<'arena, 'data> BuiltLinkGraph<'arena, 'data> {
    pub(super) fn new(link_graph: LinkGraph<'arena, 'data>) -> BuiltLinkGraph<'arena, 'data> {
        // Partition the sections by name and discard LnkRemove section
        let mut sections: IndexMap<&str, OutputSection> = link_graph
            .section_nodes
            .into_iter()
            .filter(|section| {
                if section
                    .characteristics()
                    .contains(SectionNodeCharacteristics::LnkRemove)
                {
                    debug!(
                        "{}: discarding 'IMAGE_SCN_LNK_REMOVE' section {}",
                        section.coff(),
                        section.name()
                    );
                    section.discard();
                    false
                } else if section.is_debug() {
                    debug!(
                        "{}: discarding debug section {}",
                        section.coff(),
                        section.name()
                    );
                    section.discard();
                    false
                } else {
                    true
                }
            })
            .fold(IndexMap::new(), |mut outputs, section_node| {
                let section_entry = outputs.entry(section_node.name().group_name()).or_default();
                section_entry.nodes.push(section_node);
                outputs
            });

        // Sort grouped sections
        sections
            .values_mut()
            .for_each(|section| section.nodes.sort_by_key(|section| section.name().as_str()));

        // Dedup equivalent .rdata$zzz sections
        if let Some(section) = sections.get_mut(".rdata") {
            section.nodes.dedup_by(|first, second| {
                first
                    .name()
                    .group_ordering()
                    .is_some_and(|ordering| ordering == "zzz")
                    && second
                        .name()
                        .group_ordering()
                        .is_some_and(|ordering| ordering == "zzz")
                    // Only dedup them if they have no incoming relocations
                    && first.relocations().is_empty()
                    && second.relocations().is_empty()
                    && first.checksum() == second.checksum()
            });
        }

        // Create the built link graph
        Self {
            machine: link_graph.machine,
            sections,
            common_section: link_graph.common_section,
            library_nodes: link_graph.library_nodes,
            root_coff: link_graph.root_coff,
            api_node: link_graph.api_node,
            external_symbols: link_graph.external_symbols,
            arena: link_graph.arena,
        }
    }

    /// Merge the .bss section with the .data section.
    pub fn merge_bss(&mut self) {
        self.allocate_commons();

        let bss_section = self.sections.entry(".bss").or_default();
        let mut bss_nodes = std::mem::take(&mut bss_section.nodes);

        let data_section = self
            .sections
            .entry(".data")
            .or_insert_with(|| OutputSection {
                // Manually set the characteristics for the output section to
                // match what is expected if the .data section does not already
                // exist
                header: SectionHeader {
                    characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA
                        | IMAGE_SCN_MEM_READ
                        | IMAGE_SCN_MEM_WRITE,
                    ..Default::default()
                },
                nodes: Vec::with_capacity(bss_nodes.len()),
            });

        data_section.nodes.append(&mut bss_nodes);
        debug!("'.bss' output section merged with '.data' section");
    }

    /// Discards all sections which are not reachable by the specified symbols.
    ///
    /// This method should only be called once since it does not save state.
    pub fn gc_sections<S: AsRef<str>>(&mut self, symbols: impl Iterator<Item = S>) {
        let mut section_count = 0usize;

        // Mark all sections as discarded
        self.sections
            .values()
            .flat_map(|section| {
                section_count += section.nodes.len();
                section.nodes.iter()
            })
            .for_each(|section| {
                section.discard();
            });

        // Set up the GC roots
        let mut section_dfs = ReachableDfs::with_capacity(section_count);

        for gc_symbol in symbols {
            if let Some(root_symbol) = self.external_symbols.get(gc_symbol.as_ref()) {
                if let Some(root_definition) = root_symbol.definitions().front() {
                    section_dfs.visit(root_definition.target());
                } else {
                    warn!(
                        "'--keep-symbol={}' is an imported symbol",
                        gc_symbol.as_ref()
                    );
                }
            } else {
                warn!("'--keep-symbol={}' is non-existent", gc_symbol.as_ref());
            }
        }

        // If no GC roots are established, the entire graph would be discarded.
        // Keep all sections in the graph so that the graph stays valid and
        // return out. This should never happen since the entrypoint is a GC
        // root and the entrypoint should be defined in the graph.
        if section_dfs.remaining() == 0 {
            warn!("no GC roots were added for '--gc-sections', aborting");
            self.sections
                .values()
                .flat_map(|section| section.nodes.iter())
                .for_each(|section| section.keep());
            return;
        }

        // Keep all sections reachable by the GC roots
        section_dfs.for_each(|section| section.keep());
    }

    /// Print discarded sections
    pub fn print_discarded_sections(&self) {
        for section in self
            .sections
            .values()
            .flat_map(|sections| sections.nodes.iter())
        {
            if section.is_discarded() {
                println!(
                    "removing unused section {}:({})",
                    section.coff(),
                    section.name()
                );
            }
        }
    }

    /// Allocate space for COMMON symbols at the end of the .bss
    fn allocate_commons(&mut self) {
        // Take the value out of the OnceCell to make the function idempotent.
        // This function should only run once but may be called multiple times
        let common_section = match self.common_section.take() {
            Some(section) => section,
            None => return,
        };

        // Get the COMMON symbols along with the maximum definition value for
        // each symbol.
        let mut common_symbols = IndexMap::<&str, &SymbolNode>::from_iter(
            common_section
                .definitions()
                .iter()
                .map(|definition| (definition.source().name().as_str(), definition.source())),
        )
        .into_values()
        .map(|symbol| {
            let max_value = symbol
                .definitions()
                .iter()
                .max_by_key(|definition| definition.weight().address())
                .unwrap_or_else(|| {
                    unreachable!("COMMON symbol should have at least 1 definition associated to it")
                })
                .weight()
                .address();

            (symbol, max_value)
        })
        .collect::<Vec<_>>();

        // Sort the symbols by descending size. Larger symbols should be
        // allocated at the beginning to minimize padding.
        common_symbols.sort_by_key(|(_, value)| std::cmp::Reverse(*value));

        let align = common_section
            .characteristics()
            .alignment()
            .unwrap_or_else(|| {
                unreachable!("COMMON section characteristics should have the alignment flag set")
            }) as u32;

        // Assign addresses to each symbol.
        let mut symbol_addr: u32 = 0;

        for (symbol, symbol_size) in &common_symbols {
            symbol_addr = symbol_addr.next_multiple_of(align);

            // Get the first definition edge from the symbol's edge list.
            // This will be re-used as the real definition edge with the symbol
            // address
            let common_def = symbol.definitions().pop_front().unwrap_or_else(|| {
                unreachable!("COMMON symbol should have at least 1 definition associated to it")
            });

            // Set the address of the symbol definition to the new value
            common_def.weight().set_address(symbol_addr);

            // Clear out the remaining definitions connected to the symbol
            symbol.definitions().clear();

            // Re insert the definition back into the symbol's edge list
            symbol.definitions().push_back(common_def);

            // Increment the address for the next symbol
            symbol_addr += symbol_size;
        }

        // At this point, all of the COMMON symbols should have a single
        // definition edge with the address for the symbol.
        // The COMMON section still has all of the old definition edges linked
        // to its edge list. The COMMON section's edge list needs to be cleared
        // and updated with the real definition edges from the symbols.

        // Clear the list of edges associated with the COMMON section
        common_section.definitions().clear();

        // Re insert the definition edges from the COMMON symbols into the
        // COMMON section edge list
        for (symbol, _) in common_symbols {
            let definition = symbol.definitions().front().unwrap_or_else(|| {
                unreachable!("COMMON symbol should have at least 1 definition associated to it")
            });
            common_section.definitions().push_back(definition);
        }

        // Set the size of the COMMON section
        common_section.set_uninitialized_size(symbol_addr);

        // Add the COMMON section to the end of the .bss output section
        let bss_entry = self
            .sections
            .entry(".bss")
            .or_insert_with(|| OutputSection {
                header: SectionHeader {
                    characteristics: common_section.characteristics().bits(),
                    ..Default::default()
                },
                nodes: Vec::with_capacity(1),
            });

        bss_entry.nodes.push(common_section);
    }

    fn apply_import_thunks(&mut self) {
        let mut thunk_symbols: LinkedList<(&SymbolNode, SymbolName)> = LinkedList::new();

        for library_node in self.api_node.iter().chain(self.library_nodes.values()) {
            for import_edge in library_node.imports() {
                let import_name = import_edge.weight().import_name();
                let symbol = import_edge.source();
                if symbol
                    .name()
                    .strip_dllimport()
                    .is_none_or(|unprefixed| unprefixed != import_name.as_str())
                    && !symbol.is_unreferenced()
                {
                    thunk_symbols.push_back((symbol, import_name));
                }
            }
        }

        if !thunk_symbols.is_empty() {
            // jmp [rip + $<symbol>]
            const CODE_THUNK: [u8; 8] = [0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90];

            let code_section_data: &mut [u8] = self
                .arena
                .alloc_slice_fill_default(CODE_THUNK.len() * thunk_symbols.len());

            for data_chunk in code_section_data.chunks_mut(CODE_THUNK.len()) {
                data_chunk.copy_from_slice(&CODE_THUNK);
            }

            let code_section = self.arena.alloc_with(|| {
                SectionNode::new(
                    ".text$zzz",
                    SectionNodeCharacteristics::CntCode
                        | SectionNodeCharacteristics::MemExecute
                        | SectionNodeCharacteristics::MemRead
                        | SectionNodeCharacteristics::Align8Bytes,
                    SectionNodeData::Initialized(code_section_data),
                    0,
                    self.root_coff,
                )
            });

            let thunk_reloc = match self.machine {
                LinkerTargetArch::Amd64 => RelocationEdgeWeight::new(2, IMAGE_REL_AMD64_REL32),
                LinkerTargetArch::I386 => RelocationEdgeWeight::new(2, IMAGE_REL_I386_DIR32),
            };

            for (symbol_num, (symbol_node, import_name)) in thunk_symbols.iter().enumerate() {
                let symbol_addr = symbol_num as u32 * 8;

                // Add a definition edge for the existing symbol
                let definition_edge = self.arena.alloc_with(|| {
                    Edge::new(
                        *symbol_node,
                        code_section,
                        DefinitionEdgeWeight::new(symbol_addr, None),
                    )
                });

                symbol_node.definitions().push_back(definition_edge);
                code_section.definitions().push_back(definition_edge);

                // Add a new thunk import symbol for this symbol
                let thunk_import_symbol = self.arena.alloc_with(|| {
                    SymbolNode::new(
                        &*self
                            .arena
                            .alloc_str(&format!("__imp_{}", import_name.as_str())),
                        SymbolNodeStorageClass::External,
                        false,
                        SymbolNodeType::Value(0),
                    )
                });

                // Add a relocation to the thunk import symbol
                let relocation_edge = self.arena.alloc_with(|| {
                    Edge::new(
                        code_section,
                        thunk_import_symbol,
                        RelocationEdgeWeight::new(
                            thunk_reloc.address() + symbol_addr,
                            thunk_reloc.typ(),
                        ),
                    )
                });

                code_section.relocations().push_back(relocation_edge);
                thunk_import_symbol.references().push_back(relocation_edge);

                // Unlink the import edge from the existing symbol
                let removed_import_edge = symbol_node.imports().pop_front().unwrap();
                // Set the source node for the edge to the new thunk import
                // symbol
                removed_import_edge.replace_source(thunk_import_symbol);

                // Link the edge to the thunk symbol
                thunk_import_symbol.imports().push_back(removed_import_edge);
            }

            // Add the new code section to the list of sections
            self.sections
                .entry(code_section.name().group_name())
                .or_default()
                .nodes
                .push(code_section);
        }
    }

    /// Handles discarding/keeping sections for COMDAT symbols
    fn handle_comdats(&self) {
        for symbol in self.external_symbols.values() {
            let mut definition_iter = symbol.definitions().iter().peekable();

            let first_definition = match definition_iter.peek() {
                Some(definition) => definition,
                None => continue,
            };

            let selection = match first_definition.weight().selection {
                Some(sel) => sel,
                None => continue,
            };

            if selection == ComdatSelection::Any
                || selection == ComdatSelection::SameSize
                || selection == ComdatSelection::ExactMatch
            {
                // Keep the first section but discard the rest.
                let _ = definition_iter.next();

                for remaining in definition_iter {
                    let section = remaining.target();
                    debug!(
                        "{}: discarding COMDAT {} ({selection:?})",
                        section.coff(),
                        section.name(),
                    );
                    section.discard();
                }
            } else if selection == ComdatSelection::Largest {
                // Find the largest size and discard the rest.
                let mut largest_section: Option<&'arena SectionNode<'arena, 'data>> = None;

                for definition in definition_iter {
                    let section = definition.target();

                    if let Some(largest) = &mut largest_section {
                        if largest.data().len() < section.data().len() {
                            debug!(
                                "{}: discarding COMDAT {} ({selection:?})",
                                largest.coff(),
                                largest.name()
                            );
                            largest.discard();
                            *largest = section;
                        }
                    } else {
                        largest_section = Some(section);
                    }
                }
            } else if selection == ComdatSelection::Associative {
                // Associative COMDAT symbols are handled by traversing the
                // root of the COMDAT chain.
                continue;
            }

            for definition in symbol.definitions() {
                let root_section = definition.target();

                // Discard or keep the associated sections depending on if
                // the root section was kept or discarded.
                let root_discarded = root_section.is_discarded();

                for associative_section in root_section.associative_bfs() {
                    if !associative_section.is_discarded() && root_discarded {
                        debug!(
                            "{}: discarding COMDAT {}. associative to discarded root ({}:{})",
                            associative_section.coff(),
                            associative_section.name(),
                            root_section.coff().short_name(),
                            root_section.name()
                        );
                    }

                    associative_section.set_discarded(root_discarded);
                }
            }
        }
    }

    /// Links the graph components together and builds the final COFF.
    pub fn link(mut self) -> Result<Vec<u8>, LinkGraphLinkError> {
        self.apply_import_thunks();
        self.handle_comdats();
        self.allocate_commons();

        // Remove discarded section nodes.
        // Discard output sections which no longer have any input sections.
        self.sections.retain(|section_name, section| {
            section.nodes.retain(|node| !node.is_discarded());
            if section.nodes.is_empty() {
                debug!("discarding output section '{section_name}'");
                false
            } else {
                true
            }
        });

        let mut built_coff = Vec::new();
        let mut coff_writer = Writer::new(&mut built_coff);

        coff_writer.reserve_file_header();

        for (section_name, section) in self.sections.iter_mut() {
            section.header.name = coff_writer.add_name(section_name.as_bytes());
            let mut section_alignment: u32 = 0;

            let mut section_nodes_iter = section.nodes.iter().peekable();

            // Get the characteristics from the first node and use them if not
            // already set
            if section.header.characteristics == 0 {
                if let Some(first_node) = section_nodes_iter.peek() {
                    let mut flags = first_node.characteristics().zero_align();

                    // Remove the COMDAT flag
                    flags.remove(SectionNodeCharacteristics::LnkComdat);
                    section.header.characteristics = flags.bits();
                }
            }

            // Assign virtual addresses to each section
            for node in section_nodes_iter {
                // Include alignment needed to satisfy input section node
                // alignment
                if let Some(align) = node.characteristics().alignment() {
                    let align = align as u32;
                    section.header.size_of_raw_data =
                        section.header.size_of_raw_data.next_multiple_of(align);
                    section_alignment = section_alignment.max(align);
                }

                debug!(
                    "{}: mapping section '{}' to '{}' at address {:#x} with size {:#x}",
                    node.coff(),
                    node.name(),
                    section_name,
                    section.header.size_of_raw_data,
                    node.data().len(),
                );

                node.assign_virtual_address(section.header.size_of_raw_data);
                section.header.size_of_raw_data += node.data().len() as u32;
            }

            // Set the alignment needed for this section
            if section_alignment != 0 {
                section.header.characteristics |=
                    (section_alignment.ilog2() + 1) << SECTION_ALIGN_SHIFT;
            }
        }

        // Reserve section headers
        coff_writer.reserve_section_headers(self.sections.len().try_into().unwrap());

        // Reserve section data only if the data is initialized
        for section in self.sections.values_mut() {
            if section.header.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA == 0 {
                section.header.pointer_to_raw_data =
                    coff_writer.reserve_section(section.header.size_of_raw_data as usize);
            }
        }

        // Reserve relocations skipping relocations to the same output section
        for (section_name, section) in self.sections.iter_mut() {
            let mut reloc_count = 0usize;

            for section_node in &section.nodes {
                for reloc in section_node.relocations() {
                    let symbol = reloc.target();

                    if let Some(definition) = symbol
                        .definitions()
                        .iter()
                        .find(|definition| !definition.target().is_discarded())
                    {
                        if definition.target().name().group_name() == *section_name {
                            continue;
                        }
                    } else if symbol.imports().is_empty() {
                        // Symbol has no imports and all definitions are in
                        // discarded sections. Return an error.

                        let coff_name = section_node.coff().to_string();

                        let symbol_defs = BTreeMap::from_iter(
                            section_node.definitions().iter().filter_map(|definition| {
                                let ref_symbol = definition.source();
                                if ref_symbol.is_section_symbol() || ref_symbol.is_label() {
                                    None
                                } else {
                                    Some((definition.weight().address(), ref_symbol.name()))
                                }
                            }),
                        );

                        if let Some(reference_symbol) =
                            symbol_defs.range(0..=reloc.weight().address()).next_back()
                        {
                            return Err(LinkGraphLinkError::DiscardedSection {
                                coff_name,
                                reference: reference_symbol.1.demangle().to_string(),
                                symbol: symbol.name().demangle().to_string(),
                            });
                        } else {
                            return Err(LinkGraphLinkError::DiscardedSection {
                                coff_name,
                                reference: format!(
                                    "{}+{:#x}",
                                    section_node.name(),
                                    reloc.weight().address()
                                ),
                                symbol: symbol.name().demangle().to_string(),
                            });
                        }
                    }

                    reloc_count += 1;
                }
            }

            section.header.number_of_relocations = reloc_count.try_into().unwrap();
            section.header.pointer_to_relocations = coff_writer.reserve_relocations(reloc_count);
        }

        // Reserve symbols defined in sections
        for section in self.sections.values() {
            // Reserve the section symbol
            let section_symbol_index = coff_writer.reserve_symbol_index();
            let _ = coff_writer.reserve_aux_section();

            for section_node in &section.nodes {
                // Assign table indicies to defined symbols
                for definition in section_node.definitions() {
                    let symbol = definition.source();

                    // Section symbol already reserved. Set the index to the
                    // existing one
                    if symbol.is_section_symbol() {
                        symbol
                            .assign_table_index(section_symbol_index)
                            .unwrap_or_else(|v| {
                                panic!(
                                    "symbol {} already assigned to symbol table index {v}",
                                    symbol.name().demangle()
                                )
                            });
                    } else if symbol.is_label() {
                        // Associate labels with the section symbol
                        symbol
                            .assign_table_index(section_symbol_index)
                            .unwrap_or_else(|v| {
                                panic!(
                                    "symbol {} already assigned to symbol table index {v}",
                                    symbol.name().demangle()
                                )
                            });
                    } else {
                        let _ = symbol.output_name().get_or_init(|| {
                            coff_writer.add_name(symbol.name().as_str().as_bytes())
                        });

                        // Reserve an index for this symbol
                        symbol
                            .assign_table_index(coff_writer.reserve_symbol_index())
                            .unwrap_or_else(|v| {
                                panic!(
                                    "symbol {} already assigned to symbol table index {v}",
                                    symbol.name().demangle()
                                )
                            });
                    }
                }
            }
        }

        // Reserve API imported symbols
        if let Some(api_node) = self.api_node {
            for import in api_node.imports() {
                let symbol = import.source();

                let _ = symbol
                    .output_name()
                    .get_or_init(|| coff_writer.add_name(symbol.name().as_str().as_bytes()));

                symbol
                    .assign_table_index(coff_writer.reserve_symbol_index())
                    .unwrap_or_else(|v| {
                        panic!(
                            "symbol {} already assigned to symbol table index {v}",
                            symbol.name().demangle()
                        )
                    });
            }
        }

        // Reserve library imported symbols
        for library in self.library_nodes.values() {
            for import in library.imports() {
                let symbol = import.source();

                let name = self.arena.alloc_str(&format!(
                    "__imp_{}${}",
                    library.name().trim_dll_suffix(),
                    import.weight().import_name()
                ));

                let _ = symbol
                    .output_name()
                    .get_or_init(|| coff_writer.add_name(name.as_bytes()));

                symbol
                    .assign_table_index(coff_writer.reserve_symbol_index())
                    .unwrap_or_else(|v| {
                        panic!(
                            "symbol {} already assigned to symbol table index {v}",
                            symbol.name().demangle()
                        )
                    });
            }
        }

        // Finish reserving COFF data
        coff_writer.reserve_symtab_strtab();

        // Write out the file header
        coff_writer
            .write_file_header(object::write::coff::FileHeader {
                machine: self.machine.into(),
                time_date_stamp: 0,
                characteristics: IMAGE_FILE_LINE_NUMS_STRIPPED,
            })
            .unwrap();

        // Write out the section headers
        for section in self.sections.values() {
            coff_writer.write_section_header(section.header.clone());
        }

        // Write out the section data
        for section in self.sections.values() {
            if section.header.size_of_raw_data > 0
                && section.header.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA == 0
            {
                coff_writer.write_section_align();

                let alignment_byte = if (section.header.characteristics & IMAGE_SCN_CNT_CODE) != 0 {
                    0x90u8
                } else {
                    0x00u8
                };

                let mut data_written = 0;
                let mut alignment_buffer = vec![alignment_byte; 16];

                for node in section.nodes.iter() {
                    // Write alignment padding
                    let needed = node.virtual_address() - data_written;
                    if needed > 0 {
                        alignment_buffer.resize(needed as usize, alignment_byte);
                        coff_writer.write(&alignment_buffer);
                        data_written += needed;
                    }

                    let section_data = match node.data() {
                        SectionNodeData::Initialized(data) => data,
                        SectionNodeData::Uninitialized(size) => {
                            // This node contains uninitialized data but the
                            // output section should be initialized.
                            // Write out padding bytes to satisfy the size
                            // requested
                            alignment_buffer.resize(size as usize, alignment_byte);
                            alignment_buffer.as_slice()
                        }
                    };

                    coff_writer.write(section_data);
                    data_written += section_data.len() as u32;
                }
            }
        }

        // Write out the relocations skipping relocations to the same section
        for (section_name, section) in self.sections.iter() {
            for section_node in &section.nodes {
                for reloc in section_node.relocations() {
                    let target_symbol = reloc.target();

                    if let Some(symbol_definition) = target_symbol
                        .definitions()
                        .iter()
                        .find(|definition| !definition.target().is_discarded())
                    {
                        if symbol_definition.target().name().group_name() == *section_name {
                            continue;
                        }
                    }

                    coff_writer.write_relocation(Relocation {
                        virtual_address: section_node.virtual_address() + reloc.weight().address(),
                        symbol: target_symbol.table_index().unwrap_or_else(|| {
                            panic!(
                                "symbol {} was never assigned a symbol table index",
                                target_symbol.name().demangle()
                            )
                        }),
                        typ: reloc.weight().typ(),
                    });
                }
            }
        }

        // Write out symbols defined in sections
        for (section_index, section) in self.sections.values().enumerate() {
            // Write the section symbol
            coff_writer.write_symbol(object::write::coff::Symbol {
                name: section.header.name,
                value: 0,
                section_number: (section_index + 1).try_into().unwrap(),
                typ: IMAGE_SYM_TYPE_NULL,
                storage_class: IMAGE_SYM_CLASS_STATIC,
                number_of_aux_symbols: 1,
            });

            coff_writer.write_aux_section(object::write::coff::AuxSymbolSection {
                length: section.header.size_of_raw_data,
                number_of_relocations: section.header.number_of_relocations,
                number_of_linenumbers: 0,
                // The object crate will calculate the checksum
                check_sum: 0,
                number: (section_index + 1).try_into().unwrap(),
                selection: 0,
            });

            for section_node in &section.nodes {
                for definition in section_node.definitions() {
                    let symbol = definition.source();

                    // Skip labels and section symbols
                    if !symbol.is_section_symbol() && !symbol.is_label() {
                        coff_writer.write_symbol(object::write::coff::Symbol {
                            name: symbol.output_name().get().copied().unwrap_or_else(|| {
                                panic!(
                                    "symbol {} never had the name reserved in the output COFF",
                                    symbol.name().demangle()
                                )
                            }),
                            value: definition.weight().address() + section_node.virtual_address(),
                            section_number: (section_index + 1).try_into().unwrap(),
                            typ: match symbol.typ() {
                                SymbolNodeType::Value(typ) => typ,
                                _ => unreachable!(),
                            },
                            storage_class: symbol.storage_class().into(),
                            number_of_aux_symbols: 0,
                        });
                    }
                }
            }
        }

        // Write out API imported symbols
        if let Some(api_node) = self.api_node {
            for import in api_node.imports() {
                let symbol = import.source();
                coff_writer.write_symbol(object::write::coff::Symbol {
                    name: symbol.output_name().get().copied().unwrap_or_else(|| {
                        panic!(
                            "symbol {} never had the name reserved in the output COFF",
                            symbol.name().demangle()
                        )
                    }),
                    value: 0,
                    section_number: 0,
                    typ: 0,
                    storage_class: IMAGE_SYM_CLASS_EXTERNAL,
                    number_of_aux_symbols: 0,
                });
            }
        }

        // Write out library imported symbols
        for library in self.library_nodes.values() {
            for import in library.imports() {
                let symbol = import.source();
                coff_writer.write_symbol(object::write::coff::Symbol {
                    name: symbol.output_name().get().copied().unwrap_or_else(|| {
                        panic!(
                            "symbol {} never had the name reserved in the output COFF",
                            symbol.name().demangle()
                        )
                    }),
                    value: 0,
                    section_number: 0,
                    typ: 0,
                    storage_class: IMAGE_SYM_CLASS_EXTERNAL,
                    number_of_aux_symbols: 0,
                });
            }
        }

        // Finish writing the COFF
        coff_writer.write_strtab();

        // Fixup relocations
        for section in self.sections.values() {
            let section_data_base = section.header.pointer_to_raw_data as usize;
            for section_node in &section.nodes {
                let section_data_ptr = section_data_base + section_node.virtual_address() as usize;

                let section_data =
                    &mut built_coff[section_data_ptr..section_data_ptr + section_node.data().len()];

                for reloc_edge in section_node.relocations() {
                    let target_symbol = reloc_edge.target();

                    let symbol_definition = match target_symbol
                        .definitions()
                        .iter()
                        .find(|definition| !definition.target().is_discarded())
                    {
                        Some(definition) => definition,
                        None => continue,
                    };

                    let target_section = symbol_definition.target();
                    let reloc = reloc_edge.weight();

                    // Return an error if the relocation is out of bounds.
                    if reloc.virtual_address + 4 > section_node.data().len() as u32 {
                        return Err(LinkGraphLinkError::RelocationBounds {
                            coff_name: section_node.coff().to_string(),
                            section: section_node.name().to_string(),
                            address: reloc.virtual_address,
                            size: section_node.data().len() as u32,
                        });
                    }

                    // The relocation bounds check above checks the relocation
                    // in the graph. This indexes into the built COFF after
                    // everything is merged. The slice index should always
                    // be in bounds but if it is not, there is some logic
                    // error above. Panic with a verbose error message if that
                    // is the case.

                    let reloc_data: [u8; 4] = section_data
                        .get(reloc.address() as usize..reloc.address() as usize + 4)
                        .map(|data| data.try_into().unwrap_or_else(|_| unreachable!()))
                        .unwrap_or_else(|| {
                            unreachable!(
                                "relocation in section '{}' is out of bounds",
                                section_node.name()
                            )
                        });

                    // Update relocations
                    let relocated_val = if target_symbol.is_section_symbol()
                        && (section_node.name().group_name() != target_section.name().group_name())
                    {
                        // Target symbol is a section symbol. Relocations need to
                        // be adjusted to account for the section shift.
                        let reloc_val = u32::from_le_bytes(reloc_data);

                        reloc_val
                            .checked_add(target_section.virtual_address())
                            .ok_or_else(|| LinkGraphLinkError::RelocationOverflow {
                                coff_name: section_node.coff().to_string(),
                                section: section_node.name().to_string(),
                                address: reloc.address(),
                            })?
                    } else if section_node.name().group_name() == target_section.name().group_name()
                    {
                        // Relocation targets a symbol defined in the same section.
                        // Apply the relocation to the symbol address.

                        let reloc_addr = reloc.address() + section_node.virtual_address();
                        let symbol_addr =
                            symbol_definition.weight().address() + target_section.virtual_address();

                        let reloc_val = u32::from_be_bytes(reloc_data);
                        let delta = symbol_addr.wrapping_sub(reloc_addr + 4);
                        reloc_val.wrapping_add(delta)
                    } else if target_symbol.is_label() {
                        // Old relocation target symbol is a label. The current
                        // relocation points to the section symbol and the label
                        // was discarded.
                        // Handle this like a section symbol relocation but
                        // shift it to point to the label's virtual address in
                        // the section.
                        let reloc_val = u32::from_le_bytes(reloc_data);
                        let symbol_addr = symbol_definition.weight().address();

                        reloc_val
                            .checked_add(target_section.virtual_address())
                            .and_then(|reloc_val| reloc_val.checked_add(symbol_addr))
                            .ok_or_else(|| LinkGraphLinkError::RelocationOverflow {
                                coff_name: section_node.coff().to_string(),
                                section: section_node.name().to_string(),
                                address: reloc.address(),
                            })?
                    } else {
                        // Relocation target is symbolic and does not need
                        // updating
                        continue;
                    };

                    // Write the new reloc
                    section_data[reloc.address() as usize..reloc.address() as usize + 4]
                        .copy_from_slice(&relocated_val.to_le_bytes());
                }
            }
        }

        Ok(built_coff)
    }
}
