use std::{cell::OnceCell, collections::LinkedList};

use indexmap::{IndexMap, IndexSet};
use object::{
    Object, ObjectSection, ObjectSymbol,
    coff::{CoffFile, CoffHeader, ImageSymbol},
};

use crate::linker::LinkerTargetArch;

use super::{
    LinkGraph, ROOT_COFF,
    cache::LinkGraphCache,
    edge::{DefinitionEdgeWeight, Edge, RelocationEdgeWeight},
    link::LinkGraphArena,
    node::{CoffNode, SectionNode, SymbolNode},
};

#[cfg(target_pointer_width = "16")]
const SYSTEM_ALIGNMENT: usize = 2;

#[cfg(target_pointer_width = "32")]
const SYSTEM_ALIGNMENT: usize = 4;

#[cfg(target_pointer_width = "64")]
const SYSTEM_ALIGNMENT: usize = 8;

/// Structure for speculatively calculating the amount of memory needed for
/// building the main link graph.
pub struct SpecLinkGraph {
    coffs: usize,
    externals: usize,
    sections: usize,
    max_sections: usize,
    max_symbols: usize,
    alloc_size: usize,
}

impl SpecLinkGraph {
    /// Creates a new [`SpecLinkGraph`].
    pub fn new() -> SpecLinkGraph {
        Self {
            coffs: 0,
            externals: 0,
            sections: 0,
            max_sections: 0,
            max_symbols: 0,
            alloc_size: 0usize,
        }
    }

    /// Returns the calculated number of bytes needed to hold graph components.
    pub fn byte_capacity(&self) -> usize {
        self.alloc_size
    }

    /// Adds a COFF to the [`LinkGraph`] allocation calculation.
    pub fn add_coff<'a, C: CoffHeader>(&mut self, coff: &CoffFile<'a, &'a [u8], C>) {
        self.coffs += 1;

        self.max_sections = self.max_sections.max(coff.coff_section_table().len());
        self.max_symbols = self.max_symbols.max(coff.coff_symbol_table().len());
        self.sections += coff.coff_section_table().len();

        self.alloc_size += std::mem::size_of::<CoffNode>();
        self.alloc_size = self.alloc_size.next_multiple_of(SYSTEM_ALIGNMENT);

        for _ in coff.sections() {
            self.alloc_size += std::mem::size_of::<SectionNode>();
            self.alloc_size = self.alloc_size.next_multiple_of(SYSTEM_ALIGNMENT);
        }

        for symbol in coff.symbols() {
            self.alloc_size += std::mem::size_of::<SymbolNode>();
            self.alloc_size = self.alloc_size.next_multiple_of(SYSTEM_ALIGNMENT);

            if symbol.is_global() {
                self.externals += 1;
            }

            if symbol.is_definition() || symbol.coff_symbol().has_aux_section() {
                self.alloc_size +=
                    std::mem::size_of::<Edge<'_, SymbolNode, SectionNode, DefinitionEdgeWeight>>();
                self.alloc_size = self.alloc_size.next_multiple_of(SYSTEM_ALIGNMENT);
            }
        }

        for section in coff.sections() {
            for _ in section.relocations() {
                self.alloc_size +=
                    std::mem::size_of::<Edge<'_, SectionNode, SymbolNode, RelocationEdgeWeight>>();
                self.alloc_size = self.alloc_size.next_multiple_of(SYSTEM_ALIGNMENT);
            }
        }
    }

    /// Allocates the arena for the [`LinkGraph`].
    pub fn alloc_arena(&self) -> LinkGraphArena {
        LinkGraphArena::with_capacity(self.byte_capacity())
    }

    /// Allocates the [`LinkGraph`] using the specified `arena`.
    pub fn alloc_graph<'data>(
        self,
        arena: &LinkGraphArena,
        machine: LinkerTargetArch,
    ) -> LinkGraph<'_, 'data> {
        LinkGraph {
            machine,
            section_nodes: Vec::with_capacity(self.sections),
            common_section: OnceCell::new(),
            library_nodes: IndexMap::new(),
            coff_nodes: IndexSet::with_capacity(self.coffs),
            root_coff: &ROOT_COFF,
            api_node: None,
            external_symbols: IndexMap::with_capacity(self.externals),
            extraneous_symbols: LinkedList::new(),
            cache: LinkGraphCache::with_capacity(self.max_symbols, self.max_sections),
            node_count: 0,
            arena,
        }
    }
}

impl Default for SpecLinkGraph {
    fn default() -> Self {
        Self::new()
    }
}
