use std::{
    cell::{Cell, OnceCell},
    collections::{BTreeMap, HashSet, VecDeque},
    ops::Deref,
};

use object::{
    ComdatKind,
    coff::{CoffHeader, ImageSymbol},
    pe,
};

use crate::graph::edge::{
    DefinitionEdge, EdgeList, EdgeListIter, ImportEdge, IncomingEdges, OutgoingEdges,
    RelocationEdge, WeakDefaultEdge, WeakDefaultSearch,
};

use super::{SectionNode, SectionType};

/// A symbol node in the graph.
pub struct SymbolNode<'arena, 'data> {
    /// The list of outgoing definition edges for this symbol.
    definition_edges: EdgeList<'arena, DefinitionEdge<'arena, 'data>, OutgoingEdges>,

    /// The list of outgoing import edges for this symbol.
    import_edges: EdgeList<'arena, ImportEdge<'arena, 'data>, OutgoingEdges>,

    /// The incoming relocation edges for this symbol.
    relocation_edges: EdgeList<'arena, RelocationEdge<'arena, 'data>, IncomingEdges>,

    /// The list of outgoing weak external default edges for this symbol.
    weak_default_edges: EdgeList<'arena, WeakDefaultEdge<'arena, 'data>, OutgoingEdges>,

    /// The symbol table index when inserted into the output COFF.
    table_index: OnceCell<u32>,

    /// The symbol name for the output COFF.
    output_name: OnceCell<object::write::coff::Name>,

    /// The name of the symbol.
    name: BorrowedSymbolName<'arena>,

    /// The storage class of the symbol.
    storage_class: u8,

    /// If this is a section symbol.
    section: bool,

    /// The type of symbol.
    typ: Cell<SymbolNodeType>,
}

impl<'arena, 'data> SymbolNode<'arena, 'data> {
    pub fn new(
        name: impl Into<BorrowedSymbolName<'arena>>,
        storage_class: u8,
        section: bool,
        typ: SymbolNodeType,
    ) -> SymbolNode<'arena, 'data> {
        Self {
            definition_edges: EdgeList::new(),
            import_edges: EdgeList::new(),
            relocation_edges: EdgeList::new(),
            weak_default_edges: EdgeList::new(),
            table_index: OnceCell::new(),
            output_name: OnceCell::new(),
            name: name.into(),
            storage_class,
            section,
            typ: Cell::new(typ),
        }
    }

    pub fn try_from_symbol<'file, C: CoffHeader>(
        name: impl Into<BorrowedSymbolName<'arena>>,
        coff_symbol: &'arena C::ImageSymbol,
    ) -> anyhow::Result<SymbolNode<'arena, 'data>> {
        Ok(Self {
            definition_edges: EdgeList::new(),
            import_edges: EdgeList::new(),
            relocation_edges: EdgeList::new(),
            weak_default_edges: EdgeList::new(),
            table_index: OnceCell::new(),
            output_name: OnceCell::new(),
            name: name.into(),
            storage_class: coff_symbol.storage_class(),
            section: coff_symbol.has_aux_section(),
            typ: Cell::new(match coff_symbol.section_number() {
                pe::IMAGE_SYM_ABSOLUTE => SymbolNodeType::Absolute(coff_symbol.value()),
                pe::IMAGE_SYM_DEBUG => SymbolNodeType::Debug,
                _ => SymbolNodeType::Value(coff_symbol.typ()),
            }),
        })
    }

    /// Returns the list of adjacent outgoing definition edges for this symbol
    /// node.
    pub fn definitions(&self) -> &EdgeList<'arena, DefinitionEdge<'arena, 'data>, OutgoingEdges> {
        &self.definition_edges
    }

    /// Returns the list of adjacent incoming relocation edges for this symbol
    /// node.
    pub fn references(&self) -> &EdgeList<'arena, RelocationEdge<'arena, 'data>, IncomingEdges> {
        &self.relocation_edges
    }

    /// Returns an iterator over the symbols that reference this symbol.
    pub fn symbol_references(&self) -> SymbolReferencesIter<'arena, 'data> {
        SymbolReferencesIter::new(self.references().iter())
    }

    /// Returns the list of adjacent outgoing import edges for this symbol
    /// node.
    pub fn imports(&self) -> &EdgeList<'arena, ImportEdge<'arena, 'data>, OutgoingEdges> {
        &self.import_edges
    }

    /// Returns the list of adjacent outgoing weak external default edges for
    /// this symbol.
    pub fn weak_defaults(
        &self,
    ) -> &EdgeList<'arena, WeakDefaultEdge<'arena, 'data>, OutgoingEdges> {
        &self.weak_default_edges
    }

    /// Returns an iterator over the definition edges associated with weak default
    /// symbols.
    pub fn weak_default_definitions(
        &self,
    ) -> impl Iterator<Item = &'arena DefinitionEdge<'arena, 'data>> {
        self.weak_default_edges
            .iter()
            .flat_map(|edge| edge.target().definitions().iter())
    }

    /// Returns the name of the symbol.
    pub fn name(&self) -> &BorrowedSymbolName<'arena> {
        &self.name
    }

    /// Returns the storage class of the symbol.
    pub fn storage_class(&self) -> u8 {
        self.storage_class
    }

    /// Returns `true` if this is a section symbol.
    pub fn is_section_symbol(&self) -> bool {
        self.section
    }

    /// Returns `true` if this symbol is externally visible.
    pub fn is_external(&self) -> bool {
        self.storage_class == pe::IMAGE_SYM_CLASS_EXTERNAL
            || self.storage_class == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
    }

    /// Returns `true` if this symbol is a label.
    pub fn is_label(&self) -> bool {
        self.storage_class == pe::IMAGE_SYM_CLASS_LABEL || self.is_msvc_label()
    }

    /// Returns `true` if this is an MSVC .data label.
    ///
    /// These are symbols with static storage class, have a name format of
    /// `$SG<number>` and are defined in a data section.
    pub fn is_msvc_label(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_STATIC
            && self
                .name()
                .as_str()
                .strip_prefix("$SG")
                .is_some_and(|unprefixed| unprefixed.parse::<usize>().is_ok())
            && self
                .definitions()
                .front()
                .is_some_and(|definition| definition.target().typ() == SectionType::InitializedData)
    }

    /// Returns `true` if this symbol has no references or all sections
    /// referencing this symbol have been discarded.
    pub fn is_unreferenced(&self) -> bool {
        self.references().is_empty()
            || self
                .references()
                .iter()
                .all(|reloc| reloc.source().is_discarded())
    }

    /// Returns `true` if this symbol has a strong definition.
    ///
    /// A strongly defined symbol is a symbol that has at least one definition
    /// or import edge.
    pub fn is_strong_defined(&self) -> bool {
        !self.definitions().is_empty() || !self.imports().is_empty()
    }

    /// Returns `true` if this symbol has a weak definition.
    ///
    /// A weakly defined symbol is a weak symbol with an associated default
    /// symbol that is strongly defined.
    pub fn is_weak_defined(&self) -> bool {
        self.weak_default_definitions().next().is_some()
    }

    /// Returns `true` if this symbol is either [`SymbolNode::is_strong_defined()`]
    /// or [`SymbolNode::is_weakly_defined()`].
    pub fn is_defined(&self) -> bool {
        self.is_strong_defined() || self.is_weak_defined()
    }

    /// Returns `true` if this symbol is not defined.
    pub fn is_undefined(&self) -> bool {
        !self.is_defined()
    }

    /// Returns `true` if this symbol has multiple non-COMDAT definitions.
    pub fn is_duplicate(&self) -> bool {
        self.definitions()
            .iter()
            .filter(|definition| definition.weight().selection() == ComdatKind::Unknown)
            .count()
            > 1
    }

    /// Returns `true` if this symbol is multiply defined.
    pub fn is_multiply_defined(&self) -> bool {
        let mut noduplicates = false;
        let mut samesize = false;
        let mut exact_match = false;

        let mut sizes = HashSet::with_capacity(self.definitions().len());
        let mut checksums = HashSet::with_capacity(self.definitions().len());

        for definition in self.definitions().iter() {
            let selection = match definition.weight().selection() {
                ComdatKind::Unknown => continue,
                k => k,
            };

            match selection {
                ComdatKind::NoDuplicates => {
                    noduplicates = true;
                }
                ComdatKind::SameSize => {
                    sizes.insert(definition.target().data().len());
                    samesize = true;
                }
                ComdatKind::ExactMatch => {
                    // TODO: This will just check if the section data matches.
                    // Also need to check that the relocations and definitions
                    // match.
                    checksums.insert(definition.target().checksum());
                    exact_match = true;
                }
                _ => (),
            }
        }

        (noduplicates && self.definitions().len() > 1)
            || (samesize && sizes.len() > 1)
            || (exact_match && checksums.len() > 1)
    }

    /// Returns `true` if this symbol is a weak symbol.
    pub fn is_weak(&self) -> bool {
        !self.weak_default_edges.is_empty()
    }

    /// Returns `true` if this symbol should be visible during archive searches.
    ///
    /// An archive visible symbol is a symbol that is external ([`SymbolNode::is_external()`])
    /// and undefined (see [`SymbolNode::is_undefined()`]).
    ///
    /// If this is a weak undefined symbol, it will be visible if any of the
    /// [`SymbolNode::weak_defaults()`] have a search characteristic value of
    /// [`WeakDefaultSearch::Library`].
    pub fn is_archive_visible(&self) -> bool {
        if !self.is_external() {
            return false;
        }

        if self.is_strong_defined() {
            return false;
        }

        if !self.is_weak() {
            return true;
        }

        let mut has_weak_library_search = false;

        for weak_edge in self.weak_defaults() {
            if weak_edge.target().is_strong_defined() {
                return false;
            } else if weak_edge.weight().search() == WeakDefaultSearch::Library {
                has_weak_library_search = true;
            }
        }

        has_weak_library_search
    }

    /// Returns the type associated with this symbol.
    pub fn typ(&self) -> SymbolNodeType {
        self.typ.get()
    }

    /// Sets the type to the specified value for this symbol.
    pub fn set_type(&self, val: u16) {
        self.typ.set(SymbolNodeType::Value(val));
    }

    /// Sets the symbol table index for this symbol.
    ///
    /// This can only be set once.
    pub fn assign_table_index(&self, value: u32) -> Result<(), u32> {
        self.table_index.set(value)
    }

    /// Gets the assigned symbol table index for this symbol.
    ///
    /// Returns `None` if this symbol has not been assigned an index.
    pub fn table_index(&self) -> Option<u32> {
        self.table_index.get().copied()
    }

    /// Gets the name of the symbol for the output COFF.
    ///
    /// Returns `None` if the name of the symbol was never added to the COFF.
    pub fn output_name(&self) -> &OnceCell<object::write::coff::Name> {
        &self.output_name
    }
}

impl std::fmt::Debug for SymbolNode<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolNode")
            .field("name", &self.name)
            .field("storage_class", &self.storage_class)
            .field("section", &self.section)
            .field("typ", &self.typ)
            .finish_non_exhaustive()
    }
}

/// A generic symbol name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymbolName<T: Deref<Target = str>> {
    name: T,
    i386: bool,
}

impl<T: Deref<Target = str>> SymbolName<T> {
    pub fn new(name: T, i386: bool) -> SymbolName<T> {
        Self { name, i386 }
    }

    /// Returns a [`SymbolNameDemangler`] for demangling the name of the symbol.
    pub fn demangle(&self) -> SymbolNameDemangler<'_, T> {
        SymbolNameDemangler(self)
    }

    /// Returns a formatter for formatting the demangled symbol name with the
    /// mangled name in quotes.
    pub fn quoted_demangle(&self) -> QuotedSymbolNameDemangler<'_, T> {
        QuotedSymbolNameDemangler(self)
    }

    /// Returns the symbol name but without the `__declspec(dllimport)` prefix
    /// if it exists.
    pub fn strip_dllimport(&self) -> Option<&str> {
        self.name.strip_prefix("__imp_")
    }

    /// Returns `true` if the symbol name contains the `__declspec(dllimport)`
    /// prefix
    pub fn is_dllimport(&self) -> bool {
        self.name.starts_with("__imp_")
    }

    /// Returns `true` if this symbol is an i386 symbol.
    pub fn is_i386(&self) -> bool {
        self.i386
    }

    /// Returns `true` if this is mangled C++ symbol.
    pub fn is_cxx_mangled(&self) -> bool {
        let name = self.name.trim_start_matches("__imp_");

        #[cfg(windows)]
        if name.starts_with('?') {
            return true;
        }

        (self.is_i386() && name.starts_with("__Z")) || name.starts_with("_Z")
    }

    /// Converts the symbol name into an [`OwnedSymbolName`].
    pub fn into_owned(self) -> OwnedSymbolName {
        SymbolName {
            i386: self.i386,
            name: self.name.to_owned(),
        }
    }
}

impl<'a> SymbolName<&'a str> {
    pub fn as_str(&self) -> &'a str {
        self.name
    }
}

impl<T: Deref<Target = str>> std::fmt::Display for SymbolName<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.name.fmt(f)
    }
}

pub type BorrowedSymbolName<'a> = SymbolName<&'a str>;
pub type OwnedSymbolName = SymbolName<String>;

/// Wrapper around a [`SymbolName`] for demangling the name string.
#[derive(Debug, Clone, Copy)]
pub struct SymbolNameDemangler<'a, T: Deref<Target = str>>(&'a SymbolName<T>);

impl<T: Deref<Target = str>> std::fmt::Display for SymbolNameDemangler<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let symbol_name = if let Some(unprefixed) = self.0.strip_dllimport() {
            write!(f, "__declspec(dllimport) ")?;
            unprefixed
        } else {
            &self.0.name
        };

        #[cfg(windows)]
        if symbol_name.starts_with('?') {
            use crate::undname::UndnameFlags;

            let mut flags = UndnameFlags::NoPtr64Expansion;
            if self.0.is_i386() {
                flags |= UndnameFlags::ThirtyTwoBitDecode;
            }

            if let Ok(demangled) = crate::undname::undname_demangle(symbol_name, flags) {
                write!(f, "{demangled}")?;
                return Ok(());
            }
        }

        if ((self.0.is_i386() && symbol_name.starts_with("__Z")) || symbol_name.starts_with("_Z"))
            && let Ok(cpp_symbol) = cpp_demangle::Symbol::new(symbol_name)
            && let Ok(demangled) = cpp_symbol.demangle()
        {
            write!(f, "{demangled}")?;
            return Ok(());
        }

        write!(f, "{symbol_name}")
    }
}

/// Formatter for formatting a demangled [`SymbolName`] along with the mangled
/// name in quotes
pub struct QuotedSymbolNameDemangler<'a, T: Deref<Target = str>>(&'a SymbolName<T>);

impl<T: Deref<Target = str>> std::fmt::Display for QuotedSymbolNameDemangler<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", SymbolNameDemangler(self.0))?;
        if self.0.is_cxx_mangled() {
            write!(f, " \"{}\"", self.0)?;
        }

        Ok(())
    }
}

/// The type of symbol.
#[derive(Debug, Copy, Clone)]
pub enum SymbolNodeType {
    /// A debug symbol.
    Debug,

    /// An absolute symbol.
    Absolute(#[allow(unused)] u32),

    /// A defined symbol type value.
    Value(u16),
}

/// Iterator for symbol references.
///
/// This will return the section symbol with the reference before other symbols.
pub struct SymbolReferencesIter<'arena, 'data> {
    /// The incoming relocation edge references for the symbol.
    reference_iter: EdgeListIter<'arena, RelocationEdge<'arena, 'data>, IncomingEdges>,

    /// Queue with the list of references for the visited section.
    queue: VecDeque<SymbolReference<'arena, 'data>>,
}

impl<'arena, 'data> SymbolReferencesIter<'arena, 'data> {
    pub fn new(
        references: EdgeListIter<'arena, RelocationEdge<'arena, 'data>, IncomingEdges>,
    ) -> Self {
        let queue = VecDeque::with_capacity(3);

        Self {
            reference_iter: references,
            queue,
        }
    }

    /// Consumes the iterator and returns the remaining number of references.
    pub fn remaining(self) -> usize {
        self.reference_iter.count()
    }
}

impl<'arena, 'data> Iterator for SymbolReferencesIter<'arena, 'data> {
    type Item = SymbolReference<'arena, 'data>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(reference) = self.queue.pop_front() {
            return Some(reference);
        }

        while self.queue.is_empty() {
            // Get the next reference for the symbol from the iterator.
            let reference = self.reference_iter.next()?;

            // Get the section
            let section = reference.source();

            // Get the symbols and labels defined in this section ordered by
            // virtual address.
            let mut symbol_defs = BTreeMap::new();
            let mut label_defs = BTreeMap::new();
            for definition in section.definitions().iter() {
                let ref_symbol = definition.source();

                if ref_symbol.is_section_symbol() {
                    self.queue.push_back(SymbolReference {
                        source_definition: definition,
                        referent_relocation: reference,
                    });
                } else if ref_symbol.is_label() {
                    label_defs.insert(definition.weight().address(), definition);
                } else {
                    symbol_defs.insert(definition.weight().address(), definition);
                }
            }

            if let Some((_, reference_definition)) = symbol_defs
                .range(0..=reference.weight().address())
                .next_back()
            {
                self.queue.push_back(SymbolReference {
                    source_definition: reference_definition,
                    referent_relocation: reference,
                });

                // Include any associated labels
                for (_, label_definition) in label_defs
                    .range(reference_definition.weight().address()..=reference.weight().address())
                {
                    self.queue.push_back(SymbolReference {
                        source_definition: label_definition,
                        referent_relocation: reference,
                    });
                }
            }
        }

        self.queue.pop_front()
    }
}

/// A symbol that references another symbol.
pub struct SymbolReference<'arena, 'data> {
    /// The definition edge of the source symbol.
    source_definition: &'arena DefinitionEdge<'arena, 'data>,

    /// The relocation which references the target symbol.
    referent_relocation: &'arena RelocationEdge<'arena, 'data>,
}

impl<'arena, 'data> SymbolReference<'arena, 'data> {
    /// Returns the definition for the  symbol which references the referent
    /// symbol.
    pub fn definition(&self) -> &'arena DefinitionEdge<'arena, 'data> {
        self.source_definition
    }

    /// Returns the relocation for the referenced target symbol.
    pub fn relocation(&self) -> &'arena RelocationEdge<'arena, 'data> {
        self.referent_relocation
    }

    /// Returns the target symbol for the reference.
    pub fn target_symbol(&self) -> &'arena SymbolNode<'arena, 'data> {
        self.referent_relocation.target()
    }

    /// Returns the source symbol for the reference.
    pub fn source_symbol(&self) -> &'arena SymbolNode<'arena, 'data> {
        self.source_definition.source()
    }

    /// Returns the section that references the symbol.
    pub fn section(&self) -> &'arena SectionNode<'arena, 'data> {
        self.referent_relocation.source()
    }
}
