use std::collections::HashMap;

use indexmap::IndexMap;
use object::{SectionIndex, SymbolIndex};

use super::{
    edge::ComdatSelection,
    node::{SectionNode, SymbolNode},
};

/// Cache for inserting COFFs into the graph.
pub struct LinkGraphCache<'arena, 'data> {
    /// Cached symbols.
    symbols: HashMap<SymbolIndex, &'arena SymbolNode<'arena, 'data>>,

    /// Cached sections.
    sections: HashMap<SectionIndex, &'arena SectionNode<'arena, 'data>>,

    /// The cached code sections.
    code_sections: IndexMap<SectionIndex, &'arena SectionNode<'arena, 'data>>,

    /// Cached selection and section symbol values for COMDAT symbols.
    comdat_selections: HashMap<SectionIndex, ComdatSelection>,
}

impl<'arena, 'data> LinkGraphCache<'arena, 'data> {
    #[inline]
    pub fn new() -> LinkGraphCache<'arena, 'data> {
        Self {
            symbols: HashMap::new(),
            sections: HashMap::new(),
            comdat_selections: HashMap::new(),
            code_sections: IndexMap::new(),
        }
    }

    #[inline]
    pub fn with_capacity(symbols: usize, sections: usize) -> LinkGraphCache<'arena, 'data> {
        Self {
            symbols: HashMap::with_capacity(symbols),
            sections: HashMap::with_capacity(sections),
            code_sections: IndexMap::new(),
            comdat_selections: HashMap::new(),
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.symbols.clear();
        self.sections.clear();
        self.comdat_selections.clear();
        self.code_sections.clear();
    }

    #[inline]
    pub fn reserve_symbols(&mut self, additional: usize) {
        self.symbols.reserve(additional);
    }

    #[inline]
    pub fn reserve_sections(&mut self, additional: usize) {
        self.sections.reserve(additional);
    }

    #[inline]
    pub fn reserve_comdat_selections(&mut self, additional: usize) {
        self.comdat_selections.reserve(additional);
    }

    #[inline]
    pub fn insert_section(
        &mut self,
        idx: SectionIndex,
        section: &'arena SectionNode<'arena, 'data>,
    ) {
        let _ = self.sections.insert(idx, section);
    }

    #[inline]
    pub fn insert_symbol(&mut self, idx: SymbolIndex, symbol: &'arena SymbolNode<'arena, 'data>) {
        let _ = self.symbols.insert(idx, symbol);
    }

    #[inline]
    pub fn insert_comdat_selection(&mut self, idx: SectionIndex, selection: ComdatSelection) {
        let _ = self.comdat_selections.insert(idx, selection);
    }

    #[inline]
    pub fn insert_code_section(
        &mut self,
        idx: SectionIndex,
        section: &'arena SectionNode<'arena, 'data>,
    ) {
        let _ = self.code_sections.insert(idx, section);
    }

    #[inline]
    pub fn get_symbol(&self, idx: SymbolIndex) -> Option<&'arena SymbolNode<'arena, 'data>> {
        self.symbols.get(&idx).copied()
    }

    #[inline]
    pub fn get_section(&self, idx: SectionIndex) -> Option<&'arena SectionNode<'arena, 'data>> {
        self.sections.get(&idx).copied()
    }

    #[inline]
    pub fn get_comdat_selection(&self, idx: SectionIndex) -> Option<ComdatSelection> {
        self.comdat_selections.get(&idx).copied()
    }

    #[inline]
    pub fn iter_code_sections(&self) -> impl Iterator<Item = &'arena SectionNode<'arena, 'data>> {
        self.code_sections.values().copied()
    }
}
