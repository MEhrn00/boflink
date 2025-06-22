use std::{
    cell::{Cell, OnceCell},
    collections::HashSet,
};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use object::{
    coff::{CoffHeader, ImageSymbol},
    pe::{
        IMAGE_SYM_ABSOLUTE, IMAGE_SYM_CLASS_ARGUMENT, IMAGE_SYM_CLASS_AUTOMATIC,
        IMAGE_SYM_CLASS_BIT_FIELD, IMAGE_SYM_CLASS_BLOCK, IMAGE_SYM_CLASS_CLR_TOKEN,
        IMAGE_SYM_CLASS_END_OF_FUNCTION, IMAGE_SYM_CLASS_END_OF_STRUCT, IMAGE_SYM_CLASS_ENUM_TAG,
        IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_EXTERNAL_DEF, IMAGE_SYM_CLASS_FILE,
        IMAGE_SYM_CLASS_FUNCTION, IMAGE_SYM_CLASS_LABEL, IMAGE_SYM_CLASS_MEMBER_OF_ENUM,
        IMAGE_SYM_CLASS_MEMBER_OF_STRUCT, IMAGE_SYM_CLASS_MEMBER_OF_UNION, IMAGE_SYM_CLASS_NULL,
        IMAGE_SYM_CLASS_REGISTER, IMAGE_SYM_CLASS_REGISTER_PARAM, IMAGE_SYM_CLASS_SECTION,
        IMAGE_SYM_CLASS_STATIC, IMAGE_SYM_CLASS_STRUCT_TAG, IMAGE_SYM_CLASS_TYPE_DEFINITION,
        IMAGE_SYM_CLASS_UNDEFINED_LABEL, IMAGE_SYM_CLASS_UNDEFINED_STATIC,
        IMAGE_SYM_CLASS_UNION_TAG, IMAGE_SYM_CLASS_WEAK_EXTERNAL, IMAGE_SYM_DEBUG,
    },
};

use crate::graph::edge::{
    ComdatSelection, DefinitionEdgeWeight, EdgeList, ImportEdgeWeight, IncomingEdges,
    OutgoingEdges, RelocationEdgeWeight,
};

use super::{LibraryNode, SectionNode};

#[derive(Debug, Copy, Clone, thiserror::Error)]
#[error("unknown storage class value ({0})")]
pub struct TryFromStorageClassError(u8);

#[derive(Debug, thiserror::Error)]
pub enum TryFromSymbolError {
    #[error("{0}")]
    StorageClass(#[from] TryFromStorageClassError),
}

/// A symbol node in the graph.
pub struct SymbolNode<'arena, 'data> {
    /// The list of outgoing definition edges for this symbol.
    definition_edges:
        EdgeList<'arena, Self, SectionNode<'arena, 'data>, DefinitionEdgeWeight, OutgoingEdges>,

    /// The list of outgoing import edges for this symbol.
    import_edges:
        EdgeList<'arena, Self, LibraryNode<'arena, 'data>, ImportEdgeWeight<'data>, OutgoingEdges>,

    /// The incoming relocation edges for this symbol.
    relocation_edges:
        EdgeList<'arena, SectionNode<'arena, 'data>, Self, RelocationEdgeWeight, IncomingEdges>,

    /// The symbol table index when inserted into the output COFF.
    table_index: OnceCell<u32>,

    /// The symbol name for the output COFF.
    output_name: OnceCell<object::write::coff::Name>,

    /// The name of the symbol.
    name: SymbolName<'arena>,

    /// The storage class of the symbol.
    storage_class: SymbolNodeStorageClass,

    /// If this is a section symbol.
    section: bool,

    /// The type of symbol.
    typ: Cell<SymbolNodeType>,
}

impl<'arena, 'data> SymbolNode<'arena, 'data> {
    #[inline]
    pub fn new(
        name: impl Into<SymbolName<'arena>>,
        storage_class: SymbolNodeStorageClass,
        section: bool,
        typ: SymbolNodeType,
    ) -> SymbolNode<'arena, 'data> {
        Self {
            definition_edges: EdgeList::new(),
            import_edges: EdgeList::new(),
            relocation_edges: EdgeList::new(),
            table_index: OnceCell::new(),
            output_name: OnceCell::new(),
            name: name.into(),
            storage_class,
            section,
            typ: Cell::new(typ),
        }
    }

    pub fn try_from_symbol<'file, C: CoffHeader>(
        name: impl Into<SymbolName<'arena>>,
        coff_symbol: &'arena C::ImageSymbol,
    ) -> Result<SymbolNode<'arena, 'data>, TryFromSymbolError> {
        Ok(Self {
            definition_edges: EdgeList::new(),
            import_edges: EdgeList::new(),
            relocation_edges: EdgeList::new(),
            table_index: OnceCell::new(),
            output_name: OnceCell::new(),
            name: name.into(),
            storage_class: coff_symbol.storage_class().try_into()?,
            section: coff_symbol.has_aux_section(),
            typ: Cell::new(match coff_symbol.section_number() {
                IMAGE_SYM_ABSOLUTE => SymbolNodeType::Absolute(coff_symbol.value()),
                IMAGE_SYM_DEBUG => SymbolNodeType::Debug,
                _ => SymbolNodeType::Value(coff_symbol.typ()),
            }),
        })
    }

    /// Returns the list of adjacent outgoing definition edges for this symbol
    /// node.
    #[inline]
    pub fn definitions(
        &self,
    ) -> &EdgeList<'arena, Self, SectionNode<'arena, 'data>, DefinitionEdgeWeight, OutgoingEdges>
    {
        &self.definition_edges
    }

    /// Returns the list of adjacent incoming relocation edges for this symbol
    /// node.
    #[inline]
    pub fn references(
        &self,
    ) -> &EdgeList<'arena, SectionNode<'arena, 'data>, Self, RelocationEdgeWeight, IncomingEdges>
    {
        &self.relocation_edges
    }

    /// Returns the list of adjacent outgoing import edges for this symbol
    /// node.
    #[inline]
    pub fn imports(
        &self,
    ) -> &EdgeList<'arena, Self, LibraryNode<'arena, 'data>, ImportEdgeWeight<'data>, OutgoingEdges>
    {
        &self.import_edges
    }

    /// Returns the name of the symbol.
    #[inline]
    pub fn name(&self) -> SymbolName<'arena> {
        self.name
    }

    /// Returns the storage class of the symbol.
    #[inline]
    pub fn storage_class(&self) -> SymbolNodeStorageClass {
        self.storage_class
    }

    /// Returns `true` if this is a section symbol.
    #[inline]
    pub fn is_section_symbol(&self) -> bool {
        self.section
    }

    /// Returns `true` if this symbol is a label.
    pub fn is_label(&self) -> bool {
        self.storage_class == SymbolNodeStorageClass::Label || self.is_msvc_label()
    }

    /// Returns `true` if this is an MSVC .data label.
    ///
    /// These are symbols with static storage class, have a name format of
    /// `$SG<number>` and are defined in a data section.
    pub fn is_msvc_label(&self) -> bool {
        self.storage_class() == SymbolNodeStorageClass::Static
            && self
                .name()
                .as_str()
                .strip_prefix("$SG")
                .is_some_and(|unprefixed| unprefixed.parse::<usize>().is_ok())
            && self
                .definitions()
                .front()
                .is_some_and(|definition| definition.target().name().group_name() == ".data")
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

    /// Returns `true` if this symbol is undefined.
    #[inline]
    pub fn is_undefined(&self) -> bool {
        self.imports().is_empty() && self.definitions().is_empty()
    }

    /// Returns `true` if this symbol has multiple non-COMDAT definitions.
    pub fn is_duplicate(&self) -> bool {
        self.definitions()
            .iter()
            .filter(|definition| definition.weight().selection().is_none())
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
                Some(sel) => sel,
                None => continue,
            };

            match selection {
                ComdatSelection::NoDuplicates => {
                    noduplicates = true;
                }
                ComdatSelection::SameSize => {
                    sizes.insert(definition.target().data().len());
                    samesize = true;
                }
                ComdatSelection::ExactMatch => {
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

    /// Returns the type associated with this symbol.
    #[inline]
    pub fn typ(&self) -> SymbolNodeType {
        self.typ.get()
    }

    /// Sets the type to the specified value for this symbol.
    #[inline]
    pub fn set_type(&self, val: u16) {
        self.typ.set(SymbolNodeType::Value(val));
    }

    /// Sets the symbol table index for this symbol.
    ///
    /// This can only be set once.
    #[inline]
    pub fn assign_table_index(&self, value: u32) -> Result<(), u32> {
        self.table_index.set(value)
    }

    /// Gets the assigned symbol table index for this symbol.
    ///
    /// Returns `None` if this symbol has not been assigned an index.
    #[inline]
    pub fn table_index(&self) -> Option<u32> {
        self.table_index.get().copied()
    }

    /// Gets the name of the symbol for the output COFF.
    ///
    /// Returns `None` if the name of the symbol was never added to the COFF.
    #[inline]
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

/// A symbol name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymbolName<'data>(&'data str);

impl<'data> SymbolName<'data> {
    #[inline]
    pub fn as_str(&self) -> &'data str {
        self.0
    }

    /// Returns a [`SymbolNameDemangler`] for demangling the name of the symbol.
    #[inline]
    pub fn demangle(&self) -> SymbolNameDemangler<'_, 'data> {
        SymbolNameDemangler(self)
    }

    /// Returns the symbol name but without the `__declspec(dllimport)` prefix
    /// if it exists.
    pub fn strip_dllimport(&self) -> Option<&'data str> {
        self.0.strip_prefix("__imp_")
    }

    /// Returns `true` if the symbol name contains the `__declspec(dllimport)`
    /// prefix
    pub fn is_dllimport(&self) -> bool {
        self.0.starts_with("__imp_")
    }
}

impl<'data> From<&'data str> for SymbolName<'data> {
    fn from(value: &'data str) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for SymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Wrapper around a [`SymbolName`] for demangling the name string.
#[derive(Debug, Clone, Copy)]
pub struct SymbolNameDemangler<'a, 'data>(&'a SymbolName<'data>);

impl std::fmt::Display for SymbolNameDemangler<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(unprefixed) = self.0.strip_dllimport() {
            write!(f, "__declspec(dllimport) {unprefixed}")
        } else {
            write!(f, "{}", self.0.0)
        }
    }
}

/// The storage class of a symbol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[num_enum(error_type(name = TryFromStorageClassError, constructor = TryFromStorageClassError))]
#[repr(u8)]
pub enum SymbolNodeStorageClass {
    EndOfFunction = IMAGE_SYM_CLASS_END_OF_FUNCTION,
    Null = IMAGE_SYM_CLASS_NULL,
    Automatic = IMAGE_SYM_CLASS_AUTOMATIC,
    External = IMAGE_SYM_CLASS_EXTERNAL,
    Static = IMAGE_SYM_CLASS_STATIC,
    Register = IMAGE_SYM_CLASS_REGISTER,
    ExternalDef = IMAGE_SYM_CLASS_EXTERNAL_DEF,
    Label = IMAGE_SYM_CLASS_LABEL,
    UndefinedLabel = IMAGE_SYM_CLASS_UNDEFINED_LABEL,
    MemberOfStruct = IMAGE_SYM_CLASS_MEMBER_OF_STRUCT,
    Argument = IMAGE_SYM_CLASS_ARGUMENT,
    StructTag = IMAGE_SYM_CLASS_STRUCT_TAG,
    MemberOfUnion = IMAGE_SYM_CLASS_MEMBER_OF_UNION,
    UnionTag = IMAGE_SYM_CLASS_UNION_TAG,
    TypeDefinition = IMAGE_SYM_CLASS_TYPE_DEFINITION,
    UndefinedStatic = IMAGE_SYM_CLASS_UNDEFINED_STATIC,
    EnumTag = IMAGE_SYM_CLASS_ENUM_TAG,
    MemberOfEnum = IMAGE_SYM_CLASS_MEMBER_OF_ENUM,
    RegisterParam = IMAGE_SYM_CLASS_REGISTER_PARAM,
    BitField = IMAGE_SYM_CLASS_BIT_FIELD,
    Block = IMAGE_SYM_CLASS_BLOCK,
    Function = IMAGE_SYM_CLASS_FUNCTION,
    EndOfStruct = IMAGE_SYM_CLASS_END_OF_STRUCT,
    File = IMAGE_SYM_CLASS_FILE,
    Section = IMAGE_SYM_CLASS_SECTION,
    WeakExternal = IMAGE_SYM_CLASS_WEAK_EXTERNAL,
    ClrToken = IMAGE_SYM_CLASS_CLR_TOKEN,
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
