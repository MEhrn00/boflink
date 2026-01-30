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
    comdat_selections: HashMap<SectionIndex, Option<ComdatSelection>>,

    /// List of symbols with weak external auxiliary records.
    weak_symbols: Vec<SymbolIndex>,
}

impl<'arena, 'data> LinkGraphCache<'arena, 'data> {
    pub fn with_capacity(symbols: usize, sections: usize) -> LinkGraphCache<'arena, 'data> {
        Self {
            symbols: HashMap::with_capacity(symbols),
            sections: HashMap::with_capacity(sections),
            code_sections: IndexMap::new(),
            comdat_selections: HashMap::new(),
            weak_symbols: Vec::new(),
        }
    }

    pub fn clear(&mut self) {
        self.symbols.clear();
        self.sections.clear();
        self.comdat_selections.clear();
        self.code_sections.clear();
        self.weak_symbols.clear();
    }

    pub fn reserve_symbols(&mut self, additional: usize) {
        self.symbols.reserve(additional);
    }

    pub fn reserve_sections(&mut self, additional: usize) {
        self.sections.reserve(additional);
    }

    pub fn reserve_comdat_selections(&mut self, additional: usize) {
        self.comdat_selections.reserve(additional);
    }

    pub fn insert_section(
        &mut self,
        idx: SectionIndex,
        section: &'arena SectionNode<'arena, 'data>,
    ) {
        let _ = self.sections.insert(idx, section);
    }

    pub fn insert_symbol(&mut self, idx: SymbolIndex, symbol: &'arena SymbolNode<'arena, 'data>) {
        let _ = self.symbols.insert(idx, symbol);
    }

    pub fn insert_comdat_leader_selection(
        &mut self,
        idx: SectionIndex,
        selection: ComdatSelection,
    ) {
        let _ = self.comdat_selections.insert(idx, Some(selection));
    }

    pub fn insert_code_section(
        &mut self,
        idx: SectionIndex,
        section: &'arena SectionNode<'arena, 'data>,
    ) {
        let _ = self.code_sections.insert(idx, section);
    }

    pub fn add_weak_external(&mut self, idx: SymbolIndex) {
        self.weak_symbols.push(idx);
    }

    pub fn get_symbol(&self, idx: SymbolIndex) -> Option<&'arena SymbolNode<'arena, 'data>> {
        self.symbols.get(&idx).copied()
    }

    pub fn get_section(&self, idx: SectionIndex) -> Option<&'arena SectionNode<'arena, 'data>> {
        self.sections.get(&idx).copied()
    }

    /// Returns a reference to the COMDAT selection entry for the specified section
    /// index.
    ///
    /// Returns `None` if a COMDAT selection was never added for the section index.
    ///
    /// If the returned value is `&mut None`, this means that the COMDAT leader
    /// has already been handled.
    pub fn get_comdat_leader_selection(
        &mut self,
        idx: SectionIndex,
    ) -> Option<&mut Option<ComdatSelection>> {
        self.comdat_selections.get_mut(&idx)
    }

    pub fn iter_code_sections(&self) -> impl Iterator<Item = &'arena SectionNode<'arena, 'data>> {
        self.code_sections.values().copied()
    }

    pub fn iter_weak_externals(&self) -> impl Iterator<Item = SymbolIndex> {
        self.weak_symbols.iter().copied()
    }
}
