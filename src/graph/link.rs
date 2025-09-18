use std::{
    cell::OnceCell,
    collections::{HashMap, HashSet, LinkedList, hash_map},
    fmt::Write,
    hash::{DefaultHasher, Hasher},
    path::Path,
    sync::LazyLock,
};

use indexmap::{IndexMap, IndexSet};
use log::warn;
use object::{
    Architecture, Object, ObjectSection, ObjectSymbol, SectionIndex, SymbolIndex,
    coff::{CoffFile, CoffHeader, ImageSymbol},
};

use crate::{
    graph::{
        edge::{TryFromWeakDefaultSearch, WeakDefaultEdgeWeight, WeakDefaultSearch},
        node::{SymbolName, SymbolNodeType},
    },
    linker::LinkerTargetArch,
    linkobject::import::{ImportMember, ImportName},
};

use super::{
    BuiltLinkGraph, SpecLinkGraph,
    cache::LinkGraphCache,
    edge::{
        AssociativeSectionEdgeWeight, ComdatSelection, DefinitionEdgeWeight, Edge,
        ImportEdgeWeight, RelocationEdgeWeight, TryFromComdatSelectionError,
    },
    node::{
        CoffNode, LibraryNode, LibraryNodeWeight, SectionNode, SectionNodeCharacteristics,
        SectionNodeData, SymbolNode, TryFromSymbolError,
    },
};

pub type LinkGraphArena = bumpalo::Bump;

pub(super) static ROOT_COFF: LazyLock<CoffNode> =
    LazyLock::new(|| CoffNode::new(Path::new("<root>"), None));

#[derive(Debug, thiserror::Error)]
pub enum LinkGraphAddError {
    #[error("invalid architecture '{found:?}', expected '{expected:?}'")]
    ArchitectureMismatch {
        expected: Architecture,
        found: Architecture,
    },

    #[error("could not parse symbol '{name}' at table index {index}: {error}")]
    Symbol {
        name: String,
        index: SymbolIndex,
        error: TryFromSymbolError,
    },

    #[error(
        "symbol '{symbol_name}' at table index {symbol_index} references invalid section number {section_num}"
    )]
    SymbolSectionIndex {
        symbol_name: String,
        symbol_index: SymbolIndex,
        section_num: SectionIndex,
    },

    #[error(
        "{section}+{address:#x} relocation references invalid target symbol index {symbol_index}"
    )]
    RelocationTarget {
        section: String,
        address: u32,
        symbol_index: SymbolIndex,
    },

    #[error("could not parse symbol '{name}' at table index {index}: {error}")]
    ComdatSymbol {
        name: String,
        index: SymbolIndex,
        error: TryFromComdatSelectionError,
    },

    #[error("COMDAT symbol '{0}' is missing a section symbol")]
    MissingComdatSectionSymbol(String),

    #[error("COMDAT section symbol '{symbol}' is missing associative section {associative_index}")]
    MissingComdatAssociativeSection {
        symbol: String,
        associative_index: SectionIndex,
    },

    #[error(
        "weak external symbol '{symbol}' auxiliary record tag index {tag_index} references an invalid symbol"
    )]
    WeakTagIndex {
        symbol: String,
        tag_index: SymbolIndex,
    },

    #[error("could not parse symbol '{symbol}' at table index {index}: {error}")]
    WeakCharacteristics {
        symbol: String,
        index: SymbolIndex,
        error: TryFromWeakDefaultSearch,
    },

    #[error("{0}")]
    Object(#[from] object::read::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum SymbolError<'arena, 'data> {
    #[error("duplicate symbol: {0}")]
    Duplicate(DuplicateSymbolError<'arena, 'data>),

    #[error("undefined symbol: {0}")]
    Undefined(UndefinedSymbolError<'arena, 'data>),

    #[error("multiply defined symbol: {0}")]
    MultiplyDefined(MultiplyDefinedSymbolError<'arena, 'data>),
}

#[derive(Debug, thiserror::Error)]
pub struct DuplicateSymbolError<'arena, 'data>(&'arena SymbolNode<'arena, 'data>);

impl<'arena, 'data> DuplicateSymbolError<'arena, 'data> {
    pub fn symbol(&self) -> &'arena SymbolNode<'arena, 'data> {
        self.0
    }
}

impl std::fmt::Display for DuplicateSymbolError<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        display_symbol_definitions(f, self.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub struct UndefinedSymbolError<'arena, 'data>(&'arena SymbolNode<'arena, 'data>);

impl<'arena, 'data> UndefinedSymbolError<'arena, 'data> {
    pub fn symbol(&self) -> &'arena SymbolNode<'arena, 'data> {
        self.0
    }
}

impl std::fmt::Display for UndefinedSymbolError<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.name().quoted_demangle())?;

        let mut reference_iter = self.0.symbol_references().peekable();
        let mut logged_references = 0;

        while logged_references < 5 {
            let reference = match reference_iter.next() {
                Some(reference) => reference,
                None => break,
            };

            let reloc = reference.relocation();
            let section = reloc.source();
            let coff = section.coff();

            if reference.source_symbol().is_section_symbol() {
                if reference_iter.peek().is_some_and(|next_reference| {
                    next_reference.source_symbol().is_section_symbol()
                }) {
                    write!(
                        f,
                        "\n>>> referenced by {coff}:({}+{:#x})",
                        section.name(),
                        reloc.weight().address()
                    )?;
                    logged_references += 1;
                }
            } else {
                write!(
                    f,
                    "\n>>> referenced by {coff}:({})",
                    reference.source_symbol().name().quoted_demangle()
                )?;
                logged_references += 1;
            }
        }

        let remaining = self.0.references().len().saturating_sub(logged_references);
        if remaining > 0 {
            write!(f, "\n>>> referenced {remaining} more times")?;
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub struct MultiplyDefinedSymbolError<'arena, 'data>(&'arena SymbolNode<'arena, 'data>);

impl<'arena, 'data> MultiplyDefinedSymbolError<'arena, 'data> {
    pub fn symbol(&self) -> &'arena SymbolNode<'arena, 'data> {
        self.0
    }
}

impl std::fmt::Display for MultiplyDefinedSymbolError<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        display_symbol_definitions(f, self.0)
    }
}

fn display_symbol_definitions<'arena, 'data>(
    f: &mut std::fmt::Formatter<'_>,
    symbol: &'arena SymbolNode<'arena, 'data>,
) -> std::fmt::Result {
    write!(f, "{}", symbol.name().quoted_demangle())?;

    let definitions = symbol.definitions();
    if !definitions.is_empty() {
        let mut definition_iter = definitions.iter();
        for definition in definition_iter.by_ref().take(5) {
            write!(f, "\n>>> defined at {}", definition.target().coff())?;
        }

        let remaining = definitions.len().saturating_sub(5);
        if remaining > 0 {
            write!(f, "\n>>> defined {remaining} more times")?;
        }
    }

    Ok(())
}

/// The link graph.
pub struct LinkGraph<'arena, 'data> {
    /// Target architecture.
    pub(super) machine: LinkerTargetArch,

    /// List of section nodes in the graph.
    pub(super) section_nodes: Vec<&'arena SectionNode<'arena, 'data>>,

    /// The node for the COMMON section.
    pub(super) common_section: OnceCell<&'arena SectionNode<'arena, 'data>>,

    /// Pseudo-COFF for holding metadata sections.
    pub(super) root_coff: &'arena CoffNode<'data>,

    /// List of library nodes in the graph.
    pub(super) library_nodes: IndexMap<&'data str, &'arena LibraryNode<'arena, 'data>>,

    /// List of COFF nodes in the graph.
    pub(super) coff_nodes: IndexSet<&'arena CoffNode<'data>>,

    /// The API node if it exists.
    pub(super) api_node: Option<&'arena LibraryNode<'arena, 'data>>,

    /// List of symbols with external storage class.
    pub(super) external_symbols: IndexMap<&'data str, &'arena SymbolNode<'arena, 'data>>,

    /// Local symbols without any definition (absolute/debug symbols)
    pub(super) extraneous_symbols: LinkedList<&'arena SymbolNode<'arena, 'data>>,

    /// Number of nodes in the graph.
    pub(super) node_count: usize,

    /// COFF insertion cache.
    pub(super) cache: LinkGraphCache<'arena, 'data>,

    /// Graph arena allocator.
    pub(super) arena: &'arena LinkGraphArena,
}

impl<'arena, 'data> LinkGraph<'arena, 'data> {
    /// Constructs a new empty [`LinkGraph`] using the specified `arena` for
    /// holding graph components.
    pub fn new(
        arena: &'arena LinkGraphArena,
        machine: LinkerTargetArch,
    ) -> LinkGraph<'arena, 'data> {
        Self {
            machine,
            section_nodes: Vec::new(),
            common_section: OnceCell::new(),
            library_nodes: IndexMap::new(),
            coff_nodes: IndexSet::new(),
            root_coff: &*ROOT_COFF,
            api_node: None,
            external_symbols: IndexMap::new(),
            extraneous_symbols: LinkedList::new(),
            node_count: 0,
            cache: LinkGraphCache::new(),
            arena,
        }
    }

    /// Creates a new [`super::SpecLinkGraph`] for pre-calculating the memory
    /// needed for building the graph.
    pub fn spec() -> SpecLinkGraph {
        Default::default()
    }

    /// Returns the number of bytes allocated internally for holding the graph
    /// components.
    #[allow(unused)]
    #[inline]
    pub fn allocated_bytes(&self) -> usize {
        self.arena.allocated_bytes()
    }

    /// Returns `true` if the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.node_count == 0
    }

    /// Adds a COFF to the graph.
    pub fn add_coff<C: CoffHeader>(
        &mut self,
        file_path: &'data Path,
        member_path: Option<&'data Path>,
        coff: &CoffFile<'data, &'data [u8], C>,
    ) -> Result<(), LinkGraphAddError> {
        if Architecture::from(self.machine) != coff.architecture() {
            return Err(LinkGraphAddError::ArchitectureMismatch {
                expected: self.machine.into(),
                found: coff.architecture(),
            });
        }

        let coff_node = CoffNode::new(file_path, member_path);

        if self.coff_nodes.contains(&coff_node) {
            return Ok(());
        }

        let coff_node = self.arena.alloc(coff_node);
        self.node_count += 1;
        self.coff_nodes.insert(coff_node);

        let symbol_table = coff.coff_symbol_table();

        self.cache.clear();

        self.cache.reserve_sections(coff.coff_section_table().len());
        self.cache.reserve_symbols(coff.coff_symbol_table().len());
        let mut comdat_count = 0;

        for section in coff.sections() {
            let section_name = section.name()?;
            let coff_section = section.coff_section();

            let characteristics = SectionNodeCharacteristics::from_bits_truncate(
                coff_section.characteristics.get(object::LittleEndian),
            );

            let section_data =
                if characteristics.contains(SectionNodeCharacteristics::CntUninitializedData) {
                    SectionNodeData::Uninitialized(
                        coff_section.size_of_raw_data.get(object::LittleEndian),
                    )
                } else {
                    SectionNodeData::Initialized(section.data()?)
                };

            if characteristics.contains(SectionNodeCharacteristics::LnkComdat) {
                comdat_count += 1;
            }

            let section_node = self.arena.alloc_with(|| {
                SectionNode::new(section_name, characteristics, section_data, 0, coff_node)
            });

            self.node_count += 1;

            self.cache.insert_section(section.index(), section_node);
            if characteristics.contains(SectionNodeCharacteristics::CntCode) {
                self.cache
                    .insert_code_section(section.index(), section_node);
            }

            self.section_nodes.push(section_node);
        }

        self.cache.reserve_comdat_selections(comdat_count);

        for symbol in coff.symbols() {
            let symbol_name = symbol.name()?;
            let coff_symbol = symbol.coff_symbol();

            let graph_symbol = SymbolNode::try_from_symbol::<C>(
                SymbolName::new(symbol_name, self.machine == LinkerTargetArch::I386),
                coff_symbol,
            )
            .map_err(|e| LinkGraphAddError::Symbol {
                name: symbol_name.to_string(),
                index: symbol.index(),
                error: e,
            })?;

            let graph_symbol = if symbol.is_global() {
                *self
                    .external_symbols
                    .entry(symbol_name)
                    .and_modify(|existing| {
                        if symbol.is_definition() {
                            existing.set_type(coff_symbol.typ());
                        }
                    })
                    .or_insert_with(|| {
                        self.arena.alloc_with(|| {
                            self.node_count += 1;
                            graph_symbol
                        })
                    })
            } else {
                self.arena.alloc_with(|| {
                    self.node_count += 1;
                    graph_symbol
                })
            };

            self.cache.insert_symbol(symbol.index(), graph_symbol);

            let section_idx = match symbol.section_index() {
                Some(idx) => idx,
                None => {
                    if symbol.is_common() {
                        // Add a definition link for COMMON symbols to hold the
                        // symbol value
                        let common_section = *self.common_section.get_or_init(|| {
                            self.arena.alloc_with(|| {
                                SectionNode::new(
                                    "COMMON data",
                                    SectionNodeCharacteristics::CntUninitializedData
                                        | SectionNodeCharacteristics::MemRead
                                        | SectionNodeCharacteristics::MemWrite
                                        | match self.machine {
                                            LinkerTargetArch::Amd64 => {
                                                SectionNodeCharacteristics::Align8Bytes
                                            }
                                            LinkerTargetArch::I386 => {
                                                SectionNodeCharacteristics::Align4Bytes
                                            }
                                        },
                                    SectionNodeData::Uninitialized(0),
                                    0,
                                    self.root_coff,
                                )
                            })
                        });

                        let definition_edge = self.arena.alloc_with(|| {
                            Edge::new(
                                graph_symbol,
                                common_section,
                                DefinitionEdgeWeight::new(coff_symbol.value(), None),
                            )
                        });

                        graph_symbol.definitions().push_back(definition_edge);
                        common_section.definitions().push_back(definition_edge);
                    } else if symbol.is_local() {
                        self.extraneous_symbols.push_back(graph_symbol);
                    } else if coff_symbol.has_aux_weak_external() {
                        self.cache.add_weak_external(symbol.index());
                    }

                    continue;
                }
            };

            let graph_section = self.cache.get_section(section_idx).ok_or_else(|| {
                LinkGraphAddError::SymbolSectionIndex {
                    symbol_name: symbol_name.to_string(),
                    symbol_index: symbol.index(),
                    section_num: section_idx,
                }
            })?;

            let mut definition_edge = Edge::new(
                graph_symbol,
                graph_section,
                DefinitionEdgeWeight::new(coff_symbol.value(), None),
            );

            if coff_symbol.has_aux_section() {
                let aux_section = symbol_table.aux_section(symbol.index())?;
                let mut checksum = aux_section.check_sum.get(object::LittleEndian);

                if graph_section.is_comdat() {
                    let selection =
                        ComdatSelection::try_from(aux_section.selection).map_err(|e| {
                            LinkGraphAddError::ComdatSymbol {
                                name: symbol_name.to_string(),
                                index: symbol.index(),
                                error: e,
                            }
                        })?;

                    // If this is a COMDAT to an associative section, add an
                    // associative edge from the section specified in the
                    // selection number to this section
                    if selection == ComdatSelection::Associative {
                        let aux_section_number = aux_section.number.get(object::LittleEndian);

                        let associative_section_index = SectionIndex(aux_section_number as usize);
                        let associative_section = self
                            .cache
                            .get_section(associative_section_index)
                            .ok_or_else(|| LinkGraphAddError::MissingComdatAssociativeSection {
                                symbol: symbol_name.to_string(),
                                associative_index: associative_section_index,
                            })?;

                        associative_section
                            .associative_edges()
                            .push_back(self.arena.alloc_with(|| {
                                Edge::new(
                                    associative_section,
                                    graph_section,
                                    AssociativeSectionEdgeWeight,
                                )
                            }));
                    }

                    // Store the selection value for this section.
                    self.cache.insert_comdat_selection(section_idx, selection);
                }

                // Calculate the checksum value for the .rdata$zzz section since
                // it is used to dedup those sections in the output
                if graph_section.name().as_str() == ".rdata$zzz" && checksum == 0 {
                    // Calculate and set the auxiliary checksum value if needed
                    if let SectionNodeData::Initialized(data) = graph_section.data() {
                        let mut h = jamcrc::Hasher::new_with_initial(!0);
                        h.update(data);
                        checksum = h.finalize();
                    }
                }

                graph_section.replace_checksum(checksum);
            } else if graph_section.is_comdat() {
                // Add the selection to the COMDAT symbol definition.
                let selection = self
                    .cache
                    .get_comdat_selection(section_idx)
                    .ok_or_else(|| {
                        LinkGraphAddError::MissingComdatSectionSymbol(symbol_name.to_string())
                    })?;

                definition_edge.weight_mut().selection = Some(selection);
            }

            let definition_edge = self.arena.alloc(definition_edge);

            // Link the definition to the symbol
            graph_symbol.definitions().push_back(definition_edge);

            // Link the definition to the section
            graph_section.definitions().push_back(definition_edge);
        }

        for symbol_idx in self.cache.iter_weak_externals() {
            let graph_symbol = self
                .cache
                .get_symbol(symbol_idx)
                .unwrap_or_else(|| unreachable!());

            let weak_aux = symbol_table
                .aux_weak_external(symbol_idx)
                .unwrap_or_else(|_| unreachable!());

            let default_symbol = self
                .cache
                .get_symbol(weak_aux.default_symbol())
                .ok_or_else(|| LinkGraphAddError::WeakTagIndex {
                    symbol: graph_symbol.name().to_string(),
                    tag_index: weak_aux.default_symbol(),
                })?;

            let weak_search =
                WeakDefaultSearch::try_from(weak_aux.weak_search_type.get(object::LittleEndian))
                    .map_err(|e| LinkGraphAddError::WeakCharacteristics {
                        symbol: graph_symbol.name().to_string(),
                        index: symbol_idx,
                        error: e,
                    })?;

            let default_edge = self.arena.alloc_with(|| {
                Edge::new(
                    graph_symbol,
                    default_symbol,
                    WeakDefaultEdgeWeight::new(weak_search),
                )
            });

            graph_symbol.weak_defaults().push_back(&*default_edge);
        }

        for section in coff.sections() {
            let graph_section = self
                .cache
                .get_section(section.index())
                .unwrap_or_else(|| unreachable!());

            for reloc in section.coff_relocations()? {
                let target_symbol = self.cache.get_symbol(reloc.symbol()).ok_or_else(|| {
                    LinkGraphAddError::RelocationTarget {
                        section: graph_section.name().to_string(),
                        address: reloc.virtual_address.get(object::LittleEndian),
                        symbol_index: reloc.symbol(),
                    }
                })?;

                let reloc_edge = self.arena.alloc_with(|| {
                    Edge::new(
                        graph_section,
                        target_symbol,
                        RelocationEdgeWeight::new(
                            reloc.virtual_address.get(object::LittleEndian),
                            reloc.typ.get(object::LittleEndian),
                        ),
                    )
                });

                graph_section.relocations().push_back(reloc_edge);
                target_symbol.references().push_back(reloc_edge);
            }
        }

        // Add associative edges to code sections to link them to the .pdata
        // section with the exception information.
        //
        // This is so that the associated .pdata section does not get discarded
        // if the code section is kept.
        for code_section in self.cache.iter_code_sections() {
            // If this is a non-COMDAT code section, add an associative edge to
            // the .pdata section which contains the exception information
            if !code_section.is_comdat() {
                if let Some(pdata_section) = code_section.find_associated_pdata_section() {
                    // Only add the associative edge if it does not already exist
                    if !code_section
                        .associative_edges()
                        .iter()
                        .any(|edge| edge.target().name().group_name() == ".pdata")
                    {
                        code_section
                            .associative_edges()
                            .push_back(self.arena.alloc_with(|| {
                                Edge::new(code_section, pdata_section, AssociativeSectionEdgeWeight)
                            }));
                    }
                }
            }
        }

        Ok(())
    }

    /// Returns an iterator over the defined external symbols
    pub fn defined_externals(&self) -> impl Iterator<Item = &'data str> + use<'_, 'data, 'arena> {
        self.external_symbols
            .iter()
            .filter_map(|(name, symbol)| symbol.is_defined().then_some(*name))
    }

    /// Returns an iterator over the names of the symbols which should be searched
    /// during archive symbol resolution
    pub fn archive_resolvable_externals(
        &self,
    ) -> impl Iterator<Item = &'data str> + use<'_, 'data, 'arena> {
        self.external_symbols
            .iter()
            .filter_map(|(name, symbol)| symbol.is_archive_visible().then_some(*name))
    }

    /// Associates `symbol` as an API imported symbol with metadata from the
    /// specified [`ImportMember`].
    ///
    /// # Panics
    /// Panics if `symbol` does not exist.
    #[inline]
    pub fn add_api_import(
        &mut self,
        symbol: &str,
        import: &ImportMember<'data>,
    ) -> Result<(), LinkGraphAddError> {
        let api_node = *self.api_node.get_or_insert_with(|| {
            self.arena
                .alloc_with(|| LibraryNode::new(LibraryNodeWeight::new(import.dll)))
        });

        self.add_import_edge(symbol, api_node, import)
    }

    /// Associates `symbol` with the specified [`ImportMember`].
    ///
    /// # Panics
    /// Panics if `symbol` does not exist.
    #[inline]
    pub fn add_library_import(
        &mut self,
        symbol: &str,
        import: &ImportMember<'data>,
    ) -> Result<(), LinkGraphAddError> {
        let library_node = *self.library_nodes.entry(import.dll).or_insert_with(|| {
            self.arena
                .alloc_with(|| LibraryNode::new(LibraryNodeWeight::new(import.dll)))
        });

        self.add_import_edge(symbol, library_node, import)
    }

    fn add_import_edge(
        &mut self,
        symbol: &str,
        library: &'arena LibraryNode<'arena, 'data>,
        import: &ImportMember<'data>,
    ) -> Result<(), LinkGraphAddError> {
        let symbol_node = self
            .external_symbols
            .get(symbol)
            .copied()
            .unwrap_or_else(|| panic!("symbol {symbol} does not exist"));

        if import.architecture != self.machine.into() {
            return Err(LinkGraphAddError::ArchitectureMismatch {
                expected: self.machine.into(),
                found: import.architecture,
            });
        }

        let import_name = match import.import {
            ImportName::Name(name) => name,
            ImportName::Ordinal(o) => {
                warn!(
                    "found ordinal import value '{o}' for symbol \"{symbol}\". Linking public symbol name."
                );
                import.symbol
            }
        };

        let import_edge = self.arena.alloc_with(|| {
            Edge::new(
                symbol_node,
                library,
                ImportEdgeWeight::new(SymbolName::new(
                    import_name,
                    self.machine == LinkerTargetArch::I386,
                )),
            )
        });

        symbol_node.imports().push_back(import_edge);
        library.imports().push_back(import_edge);

        Ok(())
    }

    /// Finishes building the link graph.
    pub fn finish(
        self,
        ignored_unresolved: &HashSet<String>,
    ) -> Result<BuiltLinkGraph<'arena, 'data>, Vec<SymbolError<'arena, 'data>>> {
        let mut symbol_errors = Vec::new();

        for symbol in self.external_symbols.values().copied() {
            if symbol.is_undefined()
                && !symbol.references().is_empty()
                && !ignored_unresolved.contains(symbol.name().as_str())
            {
                symbol_errors.push(SymbolError::Undefined(UndefinedSymbolError(symbol)));
            } else if symbol.is_duplicate() {
                symbol_errors.push(SymbolError::Duplicate(DuplicateSymbolError(symbol)));
            } else if symbol.is_multiply_defined() {
                symbol_errors.push(SymbolError::MultiplyDefined(MultiplyDefinedSymbolError(
                    symbol,
                )));
            }
        }

        if !symbol_errors.is_empty() {
            return Err(symbol_errors);
        }

        Ok(BuiltLinkGraph::new(self))
    }

    /// Finishes building the link graph and warns on unresolved symbols.
    ///
    /// Warnings are reported here so that they appear above errors in the
    /// printed output.
    pub fn finish_unresolved(
        self,
        ignored_unresolved: &HashSet<String>,
    ) -> Result<BuiltLinkGraph<'arena, 'data>, Vec<SymbolError<'arena, 'data>>> {
        let mut symbol_errors = Vec::new();
        let mut unresolved_symbols = Vec::new();

        for symbol in self.external_symbols.values().copied() {
            if symbol.is_undefined()
                && !symbol.references().is_empty()
                && !ignored_unresolved.contains(symbol.name().as_str())
            {
                unresolved_symbols.push(SymbolError::Undefined(UndefinedSymbolError(symbol)));
            } else if symbol.is_duplicate() {
                symbol_errors.push(SymbolError::Duplicate(DuplicateSymbolError(symbol)));
            } else if symbol.is_multiply_defined() {
                symbol_errors.push(SymbolError::MultiplyDefined(MultiplyDefinedSymbolError(
                    symbol,
                )));
            }
        }

        if !unresolved_symbols.is_empty() {
            let mut log_buffer = String::new();
            let mut unresolved_iter = unresolved_symbols.iter();

            for unresolved_symbol in unresolved_iter
                .by_ref()
                .take(unresolved_symbols.len().saturating_sub(1))
            {
                writeln!(log_buffer, "{unresolved_symbol}").unwrap();
                log::warn!("{log_buffer}");
                log_buffer.clear();
            }

            if let Some(unresolved_symbol) = unresolved_iter.next() {
                write!(log_buffer, "{unresolved_symbol}").unwrap();
                if !symbol_errors.is_empty() {
                    log_buffer.push('\n');
                }

                log::warn!("{log_buffer}");
            }
        }

        if !symbol_errors.is_empty() {
            return Err(symbol_errors);
        }

        Ok(BuiltLinkGraph::new(self))
    }

    /// Writes out the GraphViz dot representation of this graph to the specified
    /// [`std::io::Write`]er.
    pub fn write_dot_graph(&self, mut w: impl std::io::Write) -> std::io::Result<()> {
        writeln!(w, "digraph {{")?;

        let pad = "    ";

        let mut idx_val = 0;
        let mut node_ids: HashMap<u64, u32> = HashMap::with_capacity(self.node_count);

        let mut section_flags = String::new();

        // Write out the section nodes and neighboring static symbol nodes.
        for section in self
            .section_nodes
            .iter()
            .copied()
            .chain(self.common_section.get().into_iter().copied())
        {
            let section_idx = idx_val;

            let mut h = DefaultHasher::new();
            std::ptr::hash(section, &mut h);
            let hid = h.finish();
            node_ids.insert(hid, section_idx);

            idx_val += 1;

            section_flags.clear();
            bitflags::parser::to_writer(
                &section.characteristics().zero_align(),
                &mut section_flags,
            )
            .unwrap();

            writeln!(
                w,
                "{pad}{section_idx} [ label=\"{{ {} | {} | {{ Size: {:#x}\\l | Align: {:#x}\\l | Checksum: {:#x}\\l }} | {{ {} }} }}\" shape=record ]",
                section.name(),
                section.coff().short_name(),
                section.data().len(),
                section.characteristics().alignment().unwrap_or(0),
                section.checksum(),
                section_flags,
            )?;

            for symbol in section
                .relocations()
                .iter()
                .map(|edge| edge.target())
                .chain(section.definitions().iter().map(|edge| edge.source()))
                .filter(|symbol| !symbol.is_external())
            {
                let mut h = DefaultHasher::new();
                std::ptr::hash(symbol, &mut h);
                let hid = h.finish();

                if let hash_map::Entry::Vacant(e) = node_ids.entry(hid) {
                    let symbol_idx = idx_val;
                    idx_val += 1;

                    writeln!(w, "{pad}{symbol_idx} [ label=\"{}\" ]", symbol.name())?;
                    e.insert(symbol_idx);
                }
            }
        }

        let mut weak_default_edges = LinkedList::new();

        // Write out external symbols.
        for symbol in self.external_symbols.values().copied() {
            let mut h = DefaultHasher::new();
            std::ptr::hash(symbol, &mut h);
            let hid = h.finish();

            if let hash_map::Entry::Vacant(e) = node_ids.entry(hid) {
                let symbol_idx = idx_val;
                idx_val += 1;

                write!(w, "{pad}{symbol_idx} [ label=\"{}\"", symbol.name())?;

                if !(matches!(symbol.typ(), SymbolNodeType::Absolute(_))
                    || matches!(symbol.typ(), SymbolNodeType::Debug))
                    && (symbol.is_undefined()
                        || symbol.is_duplicate()
                        || symbol.is_multiply_defined())
                {
                    write!(w, " color=red")?;
                }

                writeln!(w, " ]")?;

                e.insert(symbol_idx);
            }

            weak_default_edges.extend(symbol.weak_defaults().iter());
        }

        // Write out unreferenced extraneous symbols.
        for symbol in self.extraneous_symbols.iter().copied() {
            if !symbol.references().is_empty() {
                continue;
            }

            let symbol_idx = idx_val;

            let mut h = DefaultHasher::new();
            std::ptr::hash(symbol, &mut h);
            let hid = h.finish();
            node_ids.insert(hid, symbol_idx);

            writeln!(w, "{pad}{symbol_idx} [ label=\"{}\" ]", symbol.name())?;

            idx_val += 1;
        }

        // Write out the library nodes.
        for library in self.library_nodes.values().copied() {
            let mut h = DefaultHasher::new();
            std::ptr::hash(library, &mut h);

            if let hash_map::Entry::Vacant(e) = node_ids.entry(h.finish()) {
                let library_idx = idx_val;
                idx_val += 1;

                writeln!(
                    w,
                    "{pad}{library_idx} [ label=\"{}\" shape=diamond ]",
                    library.name(),
                )?;

                e.insert(library_idx);
            }
        }

        let mut api_idx = None;

        // Write out the API node if it exists.
        if let Some(api_node) = self.api_node {
            let api_idx_val = idx_val;

            writeln!(
                w,
                "{pad}{api_idx_val} [ label=\"{}\" shape=triangle ]",
                api_node.name().trim_dll_suffix()
            )?;

            api_idx = Some(api_idx_val);
        }

        // Write out relocations, definitions and COMDAT associations.
        for section in self
            .section_nodes
            .iter()
            .copied()
            .chain(self.common_section.get().into_iter().copied())
        {
            let mut h = DefaultHasher::new();
            std::ptr::hash(section, &mut h);
            let hid = h.finish();
            let section_idx = node_ids.get(&hid).copied().unwrap();

            // Relocations
            for reloc in section.relocations().iter() {
                let target_symbol = reloc.target();
                let mut h = DefaultHasher::new();
                std::ptr::hash(target_symbol, &mut h);
                let hid = h.finish();
                let symbol_idx = node_ids.get(&hid).copied().unwrap();

                writeln!(
                    w,
                    "{pad}{section_idx} -> {symbol_idx} [ label=\"relocation (addr {:#x})\" ]",
                    reloc.weight().address(),
                )?;
            }

            // Definitions
            for definition in section.definitions().iter() {
                let target_symbol = definition.source();
                let mut h = DefaultHasher::new();
                std::ptr::hash(target_symbol, &mut h);
                let hid = h.finish();
                let symbol_idx = node_ids.get(&hid).copied().unwrap();

                write!(
                    w,
                    "{pad}{symbol_idx} -> {section_idx} [ label=\"defined at {:#x}",
                    definition.weight().address()
                )?;

                if let Some(selection) = definition.weight().selection() {
                    write!(w, " ({selection:?})")?;
                }

                write!(w, "\"")?;

                if target_symbol.is_duplicate() || target_symbol.is_multiply_defined() {
                    write!(w, " color=red")?;
                }

                writeln!(w, " ]")?;
            }

            // COMDAT associations
            for assocation in section.associative_edges().iter() {
                let target_section = assocation.target();
                let mut h = DefaultHasher::new();
                std::ptr::hash(target_section, &mut h);
                let hid = h.finish();
                let target_idx = node_ids.get(&hid).copied().unwrap();

                writeln!(
                    w,
                    "{pad}{section_idx} -> {target_idx} [ label=\"associative\" ]"
                )?;
            }
        }

        // Write out weak external default edges.
        for weak_edge in weak_default_edges {
            let source_symbol = weak_edge.source();
            let mut h = DefaultHasher::new();
            std::ptr::hash(source_symbol, &mut h);
            let hid = h.finish();
            let source_idx = node_ids.get(&hid).copied().unwrap();

            let target_symbol = weak_edge.target();
            let mut h = DefaultHasher::new();
            std::ptr::hash(target_symbol, &mut h);
            let hid = h.finish();
            let target_idx = node_ids.get(&hid).copied().unwrap();

            writeln!(
                w,
                "{pad}{source_idx} -> {target_idx} [ label=\"weak default ({:?})\" ]",
                weak_edge.weight().search()
            )?;
        }

        // Write out API import edges.
        if let Some(api_node) = self.api_node {
            let api_node_idx = api_idx.unwrap();

            for import in api_node.imports().iter() {
                let target_symbol = import.source();
                let mut h = DefaultHasher::new();
                std::ptr::hash(target_symbol, &mut h);
                let symbol_idx = node_ids.get(&h.finish()).copied().unwrap();

                writeln!(
                    w,
                    "{pad}{symbol_idx} -> {api_node_idx} [ label=\"import \\\"{}\\\"\" ]",
                    import.weight().import_name()
                )?;
            }
        }

        // Write out import edges.
        for library in self.library_nodes.values().copied() {
            let mut h = DefaultHasher::new();
            std::ptr::hash(library, &mut h);
            let library_idx = node_ids.get(&h.finish()).copied().unwrap();

            for import in library.imports().iter() {
                let target_symbol = import.source();
                let mut h = DefaultHasher::new();
                std::ptr::hash(target_symbol, &mut h);
                let symbol_idx = node_ids.get(&h.finish()).copied().unwrap();

                writeln!(
                    w,
                    "{pad}{symbol_idx} -> {library_idx} [ label=\"import \\\"{}\\\"\" ]",
                    import.weight().import_name(),
                )?;
            }
        }

        writeln!(w, "}}")?;

        Ok(())
    }
}
