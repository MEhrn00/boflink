use std::{
    cell::OnceCell,
    collections::{BTreeMap, HashSet},
};

use indexmap::IndexMap;
use log::{debug, warn};
use object::pe::{IMAGE_REL_AMD64_REL32, IMAGE_REL_I386_DIR32};

use crate::linker::{LinkerTargetArch, error::LinkError};

use super::{
    edge::{ComdatSelection, DefinitionEdgeWeight, Edge, RelocationEdgeWeight},
    link::{LinkGraph, LinkGraphArena},
    node::{
        CoffNode, LibraryNode, ReachableDfs, SectionName, SectionNode, SectionNodeCharacteristics,
        SectionNodeData, SectionType, SymbolNode, SymbolNodeStorageClass, SymbolNodeType,
    },
    output::{OutputGraph, OutputSection},
};

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

/// Section categories for partitioning sections
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SectionCategory<'a> {
    /// A standard section
    Standard(SectionType),

    /// Other types of section
    Other(SectionName<'a>),
}

/// The built link graph with all of the processed inputs.
///
/// This graph does not allow adding any more inputs and is only used for
/// post-processing and building the linked output file.
pub struct BuiltLinkGraph<'arena, 'data> {
    /// Machine value for the output COFF.
    machine: LinkerTargetArch,

    /// The section nodes partitioned by category.
    section_nodes: BTreeMap<SectionCategory<'arena>, Vec<&'arena SectionNode<'arena, 'data>>>,

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
        // Partition the sections
        let mut partitioned: BTreeMap<SectionCategory<'_>, Vec<&SectionNode<'arena, 'data>>> =
            BTreeMap::new();

        let mut gccmetadata_hashes = HashSet::new();

        for section_node in link_graph.section_nodes {
            // Discard debug and lnkremove sections
            if section_node.is_debug() {
                debug!(
                    "{}: discarding debug {}",
                    section_node.coff(),
                    section_node.name()
                );
                section_node.discard();
            } else if section_node
                .characteristics()
                .contains(SectionNodeCharacteristics::LnkRemove)
            {
                debug!(
                    "{}: discarding 'IMAGE_SCN_LNK_REMOVE' section {}",
                    section_node.coff(),
                    section_node.name()
                );
                section_node.discard();
            }

            // Discard equivalent GCC metadata sections
            if section_node.is_gccmetadata() && gccmetadata_hashes.insert(section_node.checksum()) {
                section_node.discard();
            }

            if section_node.is_discarded() {
                continue;
            }

            let section_type = section_node.typ();
            let category = if section_type == SectionType::Other {
                SectionCategory::Other(section_node.name())
            } else {
                SectionCategory::Standard(section_type)
            };

            let section_entry = partitioned.entry(category).or_default();
            section_entry.push(section_node);
        }

        // Create the built link graph
        Self {
            machine: link_graph.machine,
            section_nodes: partitioned,
            common_section: link_graph.common_section,
            library_nodes: link_graph.library_nodes,
            root_coff: link_graph.root_coff,
            api_node: link_graph.api_node,
            external_symbols: link_graph.external_symbols,
            arena: link_graph.arena,
        }
    }

    /// Merge uninitialized data sections with the initialized data sections
    /// and initialize the data.
    pub fn merge_bss(&mut self) {
        self.allocate_commons();

        let uninitialized_sections = self
            .section_nodes
            .entry(SectionCategory::Standard(SectionType::UninitializedData))
            .or_default();

        let mut uninitialized_sections = std::mem::take(uninitialized_sections);

        let initialized_data_sections = self
            .section_nodes
            .entry(SectionCategory::Standard(SectionType::InitializedData))
            .or_default();

        initialized_data_sections.append(&mut uninitialized_sections);
        debug!("'.bss' sections merged with '.data' sections");
    }

    /// Discards all sections which are not reachable by the specified symbols.
    ///
    /// This method should only be called once since it does not save state.
    pub fn gc_sections<S: AsRef<str>>(
        &mut self,
        entrypoint: Option<impl AsRef<str>>,
        roots: impl Iterator<Item = S>,
    ) -> Result<(), LinkError> {
        let mut section_count = 0usize;

        // Mark all sections as discarded
        self.section_nodes
            .values()
            .flat_map(|section_list| {
                section_count += section_list.len();
                section_list.iter()
            })
            .for_each(|section| {
                section.discard();
            });

        // Setup the GC roots
        let mut section_dfs = ReachableDfs::with_capacity(section_count);

        if let Some(entrypoint_symbol) = entrypoint {
            if let Some(entrypoint_definition) = self
                .external_symbols
                .get(&entrypoint_symbol.as_ref())
                .and_then(|symbol| symbol.definitions().front())
            {
                section_dfs.visit(entrypoint_definition.target());
            }
        }

        for gc_symbol in roots {
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

        // Return an error if the GC roots could not be established.
        if section_dfs.remaining() == 0 {
            return Err(LinkError::EmptyGcRoots);
        }

        // Keep all sections reachable by the GC roots
        section_dfs.for_each(|section| section.keep());
        Ok(())
    }

    /// Print discarded sections
    pub fn print_discarded_sections(&self) {
        for section in self
            .section_nodes
            .values()
            .flat_map(|sections| sections.iter())
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

        // Add the COMMON section to the end of the uninitialized data sections
        let uninitialized_data_sections = self
            .section_nodes
            .entry(SectionCategory::Standard(SectionType::UninitializedData))
            .or_insert_with(|| Vec::with_capacity(1));

        uninitialized_data_sections.push(common_section);
    }

    fn apply_import_thunks(&mut self) {
        let code_sections = self
            .section_nodes
            .entry(SectionCategory::Standard(SectionType::Code))
            .or_default();

        // Data to insert for code thunk sections
        // jmp [rip + $<symbol>]
        const CODE_THUNK_DATA: [u8; 8] = [0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90];

        for library_node in self.api_node.iter().chain(self.library_nodes.values()) {
            for import_edge in library_node.imports() {
                let import_name = import_edge.weight().import_name();
                let symbol = import_edge.source();

                // Skip over unreferenced symbols and symbols that already have the proper
                // __declspec(dllimport) prefix
                if symbol.is_unreferenced()
                    || (symbol.name().is_dllimport() && symbol.name() != import_name)
                {
                    continue;
                }

                // Create a new section for the code thunk data but using the
                // .text$<symbol> format.
                let section_name = self
                    .arena
                    .alloc_str(&format!(".text${}", import_name.as_str()));

                let thunk_section = self.arena.alloc_with(|| {
                    SectionNode::new(
                        &*section_name,
                        SectionNodeCharacteristics::CntCode
                            | SectionNodeCharacteristics::MemExecute
                            | SectionNodeCharacteristics::MemRead
                            | SectionNodeCharacteristics::Align8Bytes,
                        SectionNodeData::Initialized(&CODE_THUNK_DATA),
                        0,
                        self.root_coff,
                    )
                });

                // Add a definition edge from the symbol to the new thunk
                // section
                let definition_edge = self.arena.alloc_with(|| {
                    Edge::new(symbol, thunk_section, DefinitionEdgeWeight::new(0, None))
                });

                symbol.definitions().push_back(definition_edge);
                thunk_section.definitions().push_back(definition_edge);

                // Add a new import symbol for the thunk definition
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

                // Add a relocation from the thunk section to the thunk import
                // symbol
                let relocation_edge = self.arena.alloc_with(|| {
                    Edge::new(
                        thunk_section,
                        thunk_import_symbol,
                        match self.machine {
                            LinkerTargetArch::Amd64 => {
                                RelocationEdgeWeight::new(2, IMAGE_REL_AMD64_REL32)
                            }
                            LinkerTargetArch::I386 => {
                                RelocationEdgeWeight::new(2, IMAGE_REL_I386_DIR32)
                            }
                        },
                    )
                });

                thunk_section.relocations().push_back(relocation_edge);
                thunk_import_symbol.references().push_back(relocation_edge);

                // Unlink the import edge from the existing symbol
                let removed_import_edge = symbol.imports().pop_front().unwrap();
                // Set the source node for the edge to the new thunk import
                // symbol
                removed_import_edge.replace_source(thunk_import_symbol);

                // Link the edge to the thunk symbol
                thunk_import_symbol.imports().push_back(removed_import_edge);

                // Add the thunk section to the set of code sections
                code_sections.push(thunk_section);
            }
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
                            "{}: discarding COMDAT {}. associative to {}({})",
                            associative_section.coff(),
                            associative_section.name(),
                            root_section.coff(),
                            root_section.name()
                        );
                    }

                    associative_section.set_discarded(root_discarded);
                }
            }
        }
    }

    /// Links the graph components together and merges grouped sections.
    pub fn link_merge_groups(mut self) -> Result<Vec<u8>, LinkGraphLinkError> {
        self.prelink();

        let section_count = self
            .section_nodes
            .values()
            .fold(0, |acc, section_nodes| acc + section_nodes.len());

        // Build the list of output sections
        let mut output_sections: Vec<OutputSection> = Vec::with_capacity(section_count);

        // Add the code sections
        let code_sections = self
            .section_nodes
            .remove(&SectionCategory::Standard(SectionType::Code));

        let mut code_output_section = OutputSection::new(
            SectionName::from(".text"),
            SectionNodeCharacteristics::CntCode
                | SectionNodeCharacteristics::MemExecute
                | SectionNodeCharacteristics::MemRead,
            Vec::new(),
        );

        let mut section_groups: BTreeMap<&str, Vec<&SectionNode>> = BTreeMap::new();
        for section in code_sections.into_iter().flatten() {
            if section.is_discarded() {
                continue;
            }

            let group_entry = section_groups
                .entry(section.name().group_ordering().unwrap_or_default())
                .or_default();
            group_entry.push(section);
        }

        code_output_section
            .nodes
            .extend(section_groups.into_values().flatten());
        output_sections.push(code_output_section);

        // Add the data sections
        let data_sections = self
            .section_nodes
            .remove(&SectionCategory::Standard(SectionType::InitializedData));

        let mut data_output_section = OutputSection::new(
            SectionName::from(".data"),
            SectionNodeCharacteristics::CntInitializedData
                | SectionNodeCharacteristics::MemRead
                | SectionNodeCharacteristics::MemWrite,
            Vec::new(),
        );

        let mut section_groups: BTreeMap<&str, Vec<&SectionNode>> = BTreeMap::new();
        for section in data_sections.into_iter().flatten() {
            if section.is_discarded() {
                continue;
            }

            let group_entry = section_groups
                .entry(section.name().group_ordering().unwrap_or_default())
                .or_default();
            group_entry.push(section);
        }

        data_output_section
            .nodes
            .extend(section_groups.into_values().flatten());
        output_sections.push(data_output_section);

        // Add the uninitialized data sections
        let uninitialized_data_sections = self
            .section_nodes
            .remove(&SectionCategory::Standard(SectionType::UninitializedData));

        let mut uninitialized_data_output_section = OutputSection::new(
            SectionName::from(".bss"),
            SectionNodeCharacteristics::CntUninitializedData
                | SectionNodeCharacteristics::MemRead
                | SectionNodeCharacteristics::MemWrite,
            Vec::new(),
        );

        let mut section_groups: BTreeMap<&str, Vec<&SectionNode>> = BTreeMap::new();
        for section in uninitialized_data_sections.into_iter().flatten() {
            if section.is_discarded() {
                continue;
            }

            let group_entry = section_groups
                .entry(section.name().group_ordering().unwrap_or_default())
                .or_default();
            group_entry.push(section);
        }

        uninitialized_data_output_section
            .nodes
            .extend(section_groups.into_values().flatten());
        output_sections.push(uninitialized_data_output_section);

        // Add the remaining sections
        for section_nodes in self.section_nodes.values_mut() {
            let mut section_map: IndexMap<&str, BTreeMap<&str, Vec<&SectionNode>>> =
                IndexMap::new();
            for section in std::mem::take(section_nodes) {
                if section.is_discarded() {
                    continue;
                }

                let group_entry = section_map.entry(section.name().group_name()).or_default();
                let ordering_entry = group_entry
                    .entry(section.name().group_ordering().unwrap_or_default())
                    .or_default();
                ordering_entry.push(section);
            }

            for (section_name, sections) in section_map.iter_mut() {
                let mut output_section = match sections.first_entry() {
                    Some(section_entry) => {
                        let first_section = match section_entry.get().first() {
                            Some(section) => section,
                            None => continue,
                        };

                        OutputSection::new(
                            SectionName::from(*section_name),
                            first_section.characteristics(),
                            Vec::with_capacity(sections.len()),
                        )
                    }
                    None => continue,
                };

                for section_group in sections.values_mut() {
                    output_section.nodes.append(section_group);
                }

                output_sections.push(output_section);
            }
        }

        self.link_final(output_sections)
    }

    /// Links the graph components together and builds the final COFF.
    pub fn link(mut self) -> Result<Vec<u8>, LinkGraphLinkError> {
        self.prelink();

        let section_count = self
            .section_nodes
            .values()
            .fold(0, |acc, section_nodes| acc + section_nodes.len());

        // Build the list of output sections
        let mut output_sections: Vec<OutputSection> = Vec::with_capacity(section_count);

        // Add the code sections
        let code_sections = self
            .section_nodes
            .remove(&SectionCategory::Standard(SectionType::Code));

        let mut code_output_section = OutputSection::new(
            SectionName::from(".text"),
            SectionNodeCharacteristics::CntCode
                | SectionNodeCharacteristics::MemExecute
                | SectionNodeCharacteristics::MemRead,
            Vec::new(),
        );

        let mut section_groups: BTreeMap<&str, Vec<&SectionNode>> = BTreeMap::new();
        for section in code_sections.into_iter().flatten() {
            if section.is_discarded() {
                continue;
            }

            let group_entry = section_groups
                .entry(section.name().group_ordering().unwrap_or_default())
                .or_default();
            group_entry.push(section);
        }

        if let Some(sections) = section_groups.remove("") {
            code_output_section.nodes.extend(sections);
        }

        output_sections.push(code_output_section);

        for remaining in section_groups.into_values() {
            let name = match remaining.first() {
                Some(section) => section.name(),
                None => continue,
            };

            output_sections.push(OutputSection::new(
                name,
                SectionNodeCharacteristics::CntCode
                    | SectionNodeCharacteristics::MemExecute
                    | SectionNodeCharacteristics::MemRead,
                remaining,
            ));
        }

        // Add the data sections
        let data_sections = self
            .section_nodes
            .remove(&SectionCategory::Standard(SectionType::InitializedData));

        let mut data_output_section = OutputSection::new(
            SectionName::from(".data"),
            SectionNodeCharacteristics::CntInitializedData
                | SectionNodeCharacteristics::MemRead
                | SectionNodeCharacteristics::MemWrite,
            Vec::new(),
        );

        let mut section_groups: BTreeMap<&str, Vec<&SectionNode>> = BTreeMap::new();
        for section in data_sections.into_iter().flatten() {
            if section.is_discarded() {
                continue;
            }

            let group_entry = section_groups
                .entry(section.name().group_ordering().unwrap_or_default())
                .or_default();
            group_entry.push(section);
        }

        if let Some(sections) = section_groups.remove("") {
            data_output_section.nodes.extend(sections);
        }

        output_sections.push(data_output_section);

        for remaining in section_groups.into_values() {
            let mut name = match remaining.first() {
                Some(section) => section.name(),
                None => continue,
            };

            // Rename the section in case the .bss section was merged with the
            // .data section
            if name.group_name() != ".data" {
                name = SectionName::from(&*self.arena.alloc_str(&format!(
                    ".data${}",
                    name.group_ordering().unwrap_or_default()
                )));
            }

            output_sections.push(OutputSection::new(
                name,
                SectionNodeCharacteristics::CntInitializedData
                    | SectionNodeCharacteristics::MemRead
                    | SectionNodeCharacteristics::MemWrite,
                remaining,
            ));
        }

        // Add the uninitialized data sections
        let uninitialized_data_sections = self
            .section_nodes
            .remove(&SectionCategory::Standard(SectionType::UninitializedData));

        let mut uninitialized_data_output_section = OutputSection::new(
            SectionName::from(".bss"),
            SectionNodeCharacteristics::CntUninitializedData
                | SectionNodeCharacteristics::MemRead
                | SectionNodeCharacteristics::MemWrite,
            Vec::new(),
        );

        let mut section_groups: BTreeMap<&str, Vec<&SectionNode>> = BTreeMap::new();
        for section in uninitialized_data_sections.into_iter().flatten() {
            if section.is_discarded() {
                continue;
            }

            let group_entry = section_groups
                .entry(section.name().group_ordering().unwrap_or_default())
                .or_default();
            group_entry.push(section);
        }

        if let Some(sections) = section_groups.remove("") {
            uninitialized_data_output_section.nodes.extend(sections);
        }

        output_sections.push(uninitialized_data_output_section);

        for remaining in section_groups.into_values() {
            let name = match remaining.first() {
                Some(section) => section.name(),
                None => continue,
            };

            output_sections.push(OutputSection::new(
                name,
                SectionNodeCharacteristics::CntUninitializedData
                    | SectionNodeCharacteristics::MemRead
                    | SectionNodeCharacteristics::MemWrite,
                remaining,
            ));
        }

        // Add the remaining sections
        for section_nodes in self.section_nodes.values_mut() {
            let mut section_map: BTreeMap<SectionName, Vec<&SectionNode>> = BTreeMap::new();
            for section in std::mem::take(section_nodes) {
                if section.is_discarded() {
                    continue;
                }

                let entry = section_map.entry(section.name()).or_default();
                entry.push(section);
            }

            for sections in section_map.into_values() {
                let mut output_section = match sections.first() {
                    Some(section) => OutputSection::new(
                        section.name(),
                        section.characteristics(),
                        Vec::with_capacity(sections.len()),
                    ),
                    None => continue,
                };

                output_section.nodes.extend(sections);
                output_sections.push(output_section);
            }
        }

        self.link_final(output_sections)
    }

    fn prelink(&mut self) {
        self.handle_comdats();
        self.apply_import_thunks();
        self.allocate_commons();
    }

    fn link_final(
        self,
        output_sections: Vec<OutputSection<'arena, 'data>>,
    ) -> Result<Vec<u8>, LinkGraphLinkError> {
        OutputGraph::new(
            self.machine,
            output_sections,
            self.api_node,
            self.library_nodes,
            self.arena,
        )
        .build_output()
    }
}
