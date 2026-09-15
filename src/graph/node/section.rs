use std::{
    cell::{Cell, OnceCell},
    collections::{HashSet, VecDeque},
    hash::{DefaultHasher, Hasher},
};

use object::pe;

use crate::graph::edge::{
    AssociativeEdge, DefinitionEdge, EdgeList, IncomingEdges, OutgoingEdges, RelocationEdge,
};

use super::CoffNode;

/// Shift value for extracting the alignment value from section characteristic
/// flags
const IMAGE_SCN_ALIGN_SHIFT: u32 = 20;

/// The types of sections
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SectionType {
    /// Executable code
    Code,

    /// Initialized data
    InitializedData,

    /// Uninitialized data
    UninitializedData,

    /// Exception unwind information
    ExceptionUnwind,

    /// Exception information
    Exception,

    /// Read-only initialized data
    ReadOnlyData,

    /// CLR metadata
    ClrMetadata,

    /// Section contains precompiled debug types
    PrecompiledDebugTypes,

    /// Section contains debug symbols
    DebugSymbols,

    /// Section contains debug types
    DebugTypes,

    /// Section contains linker options
    LinkerOptions,

    /// Section contains export tables
    ExportTables,

    /// Section contains import tables
    ImportTables,

    /// Resource directory
    ResourceDirectory,

    /// GP-relative uninitialized data
    GPRelUninitialized,

    /// GP-relative initialized data
    GPRelInitialized,

    /// GP-relative read-only data
    GPRelReadOnly,

    /// Registered exception handler data
    RegisteredExceptionHandler,

    /// Thread-local storage
    Tls,

    /// Other type of section
    Other,
}

impl SectionType {
    fn from_name_and_flags(name: SectionName<'_>, scn_flags: ImageScn) -> SectionType {
        if !name.as_str().starts_with('.') {
            return Self::Other;
        }

        let group_name = name.group_name();
        let oflags = scn_flags.output_flags();

        let code = ImageScn::CNT_CODE;
        let data = ImageScn::CNT_INITIALIZED_DATA;
        let bss = ImageScn::CNT_UNINITIALIZED_DATA;
        let r = ImageScn::MEM_READ;
        let w = ImageScn::MEM_WRITE;
        let x = ImageScn::MEM_EXECUTE;
        let discard = ImageScn::MEM_DISCARDABLE;

        let flags = |v: ImageScn| -> bool { oflags.contains(v) };

        if scn_flags.contains(ImageScn::LNK_INFO) {
            // Linker Options (.drectve)
            if group_name == ".drectve" {
                return SectionType::LinkerOptions;
            }

            if group_name == ".cormeta" {
                return SectionType::ClrMetadata;
            }

            return SectionType::Other;
        }

        if scn_flags.contains(ImageScn::GPREL) {
            if flags(bss | r | w) && group_name == ".sbss" {
                return SectionType::GPRelUninitialized;
            }
            if flags(data | r | w) && group_name == ".sdata" {
                return SectionType::GPRelInitialized;
            }
            if flags(data | r) && group_name == ".srdata" {
                return SectionType::GPRelReadOnly;
            }
            return SectionType::Other;
        }

        // Code (.text)
        if flags(code | r | x) && group_name == ".text" {
            return SectionType::Code;
        }

        // Initialized data (.data)
        if flags(data | r | w) && group_name == ".data" {
            return SectionType::InitializedData;
        }

        // Uninitialized data (.bss)
        if flags(bss | r | w) && group_name == ".bss" {
            return SectionType::UninitializedData;
        }

        // Read only (.rdata)
        if flags(data | r) && group_name == ".rdata" {
            return SectionType::ReadOnlyData;
        }

        // Exception (.pdata)
        if flags(data | r) && group_name == ".pdata" {
            return SectionType::Exception;
        }

        // Unwind (.xdata)
        if flags(data | r) && group_name == ".xdata" {
            return SectionType::ExceptionUnwind;
        }

        // Debug Symbols (.debug$S)
        if flags(discard | data | r) && group_name == ".debug$S" {
            return SectionType::DebugSymbols;
        }

        // Import tables (.idata)
        if flags(data | r | w) && group_name == ".idata" {
            return SectionType::ImportTables;
        }

        // TLS (.tls)
        if flags(data | r | w) && group_name == ".tls" {
            return SectionType::Tls;
        }

        if flags(discard | data | r) && group_name == ".debug$P" {
            return SectionType::PrecompiledDebugTypes;
        }

        if flags(discard | data | r) && group_name == ".debug$T" {
            return SectionType::PrecompiledDebugTypes;
        }

        if flags(data | r) && group_name == ".rsrc" {
            return SectionType::ResourceDirectory;
        }

        Self::Other
    }
}

/// A section node in the graph.
pub struct SectionNode<'arena, 'data> {
    /// The list of outgoing relocation edges for this section.
    relocation_edges: EdgeList<'arena, RelocationEdge<'arena, 'data>, OutgoingEdges>,

    /// The list of incoming definition edges for this section.
    definition_edges: EdgeList<'arena, DefinitionEdge<'arena, 'data>, IncomingEdges>,

    /// The list of outgoing COMDAT associative edges for this section.
    associative_edges: EdgeList<'arena, AssociativeEdge<'arena, 'data>, OutgoingEdges>,

    /// The COFF this section is from.
    coff: &'arena CoffNode<'data>,

    /// The rebased virtual address of the section.
    virtual_address: Cell<u32>,

    /// If this section is to be discarded.
    discarded: Cell<bool>,

    /// The name of the section.
    name: SectionName<'arena>,

    /// The characteristics of the section.
    characteristics: ImageScn,

    /// The section data.
    data: Cell<SectionNodeData<'arena>>,

    /// The data checksum
    checksum: Cell<u32>,

    /// The cached section type.
    ///
    /// This can be kept as a `OnceCell` unless the section name or section
    /// characteristics get wrapped in a Cell.
    kind: OnceCell<SectionType>,
}

impl<'arena, 'data> SectionNode<'arena, 'data> {
    pub fn new(
        name: impl Into<SectionName<'arena>>,
        characteristics: ImageScn,
        data: SectionNodeData<'arena>,
        checksum: u32,
        coff: &'arena CoffNode<'data>,
    ) -> SectionNode<'arena, 'data> {
        Self {
            relocation_edges: EdgeList::new(),
            definition_edges: EdgeList::new(),
            associative_edges: EdgeList::new(),
            virtual_address: Cell::new(0),
            discarded: Cell::new(false),
            coff,
            data: Cell::new(data),
            characteristics,
            checksum: Cell::from(checksum),
            name: name.into(),
            kind: OnceCell::new(),
        }
    }

    /// Returns the list of outgoing relocation edges for this section.
    pub fn relocations(&self) -> &EdgeList<'arena, RelocationEdge<'arena, 'data>, OutgoingEdges> {
        &self.relocation_edges
    }

    /// Returns the list of incoming relocation edges for this section.
    pub fn definitions(&self) -> &EdgeList<'arena, DefinitionEdge<'arena, 'data>, IncomingEdges> {
        &self.definition_edges
    }

    /// If this is a code section, attempts to find the associated .pdata section
    /// with the exception information.
    pub fn find_associated_pdata_section(&self) -> Option<&'arena SectionNode<'arena, 'data>> {
        if !self.characteristics.contains(ImageScn::CNT_CODE) {
            return None;
        }

        // Check to see if the associative edge was already added to this code
        // section
        if let Some(pdata_section) = self.associative_edges().iter().find_map(|edge| {
            let target_section = edge.target();
            (target_section.name().group_name() == ".pdata").then_some(target_section)
        }) {
            return Some(pdata_section);
        }

        // Traverse through incoming relocations to find the .pdata section
        // which references this code section.
        for possible_joined_symbol in self.definitions().iter().filter_map(|edge| {
            let defined_symbol = edge.source();
            (defined_symbol.storage_class() == pe::IMAGE_SYM_CLASS_LABEL
                || defined_symbol.is_section_symbol())
            .then_some(defined_symbol)
        }) {
            if let Some(pdata_section) =
                possible_joined_symbol.references().iter().find_map(|edge| {
                    let source_section = edge.source();
                    (source_section.name().group_name() == ".pdata").then_some(source_section)
                })
            {
                return Some(pdata_section);
            }
        }

        None
    }

    /// Returns the list of output associative section edges for this section.
    /// If this section is linked, the adjacent sections must also be linked.
    pub fn associative_edges(
        &self,
    ) -> &EdgeList<'arena, AssociativeEdge<'arena, 'data>, OutgoingEdges> {
        &self.associative_edges
    }

    /// Returns an iterator over all of the adjacent section nodes.
    ///
    /// This only returns outgoing adjacency and not incoming.
    ///
    ///
    /// Adjacent sections are all section nodes which have a direct outgoing
    /// connection
    /// - section node -> associative edge -> section node
    ///
    /// A "next-hop" connection through a symbol node
    /// - section node -> relocation edge -> symbol node -> definition edge -> section node.
    ///
    /// A "next-hop" connection through a symbol's weak default definition
    /// - "section node" -> relocation edge -> symbol node -> weak default edge
    ///   -> symbol node -> section node.
    pub fn adjacent_sections(&self) -> impl Iterator<Item = &'arena SectionNode<'arena, 'data>> {
        self.associative_edges()
            .iter()
            .map(|associative_edge| associative_edge.target())
            .chain(self.relocations().iter().flat_map(|relocation_edge| {
                let symbol = relocation_edge.target();

                symbol
                    .definitions()
                    .iter()
                    .chain(symbol.weak_default_definitions())
                    .take(1)
                    .map(|definition_edge| definition_edge.target())
            }))
    }

    /// Perform a BFS traversal over the associative section edges starting
    /// from this section.
    pub fn associative_bfs(&'arena self) -> AssociativeBfs<'arena, 'data> {
        let queue = VecDeque::from([self]);
        let mut h = DefaultHasher::new();
        std::ptr::hash(self, &mut h);
        let visited = HashSet::from([h.finish()]);
        AssociativeBfs { queue, visited }
    }

    /// Perform a DFS traversal over reachable sections.
    ///
    /// Reachable sections are sections which have some form of outgoing
    /// connection. This includes direct outgoing connections (i.e. associative
    /// section edge connections) and indirect, single-hop,
    /// relocation -> symbol -> definition -> section connections.
    pub fn reachable_dfs(&'arena self) -> ReachableDfs<'arena, 'data> {
        ReachableDfs {
            stack: VecDeque::from([self]),
            visited: HashSet::new(),
        }
    }

    /// Returns the COFF associated with this section.
    ///
    /// This is the COFF where the section node was sourced from.
    pub fn coff(&self) -> &'arena CoffNode<'data> {
        self.coff
    }

    /// Marks this section as being discarded.
    pub fn discard(&self) {
        self.discarded.set(true);
    }

    /// Sets the discarded value for the section.
    pub fn set_discarded(&self, val: bool) {
        self.discarded.set(val);
    }

    /// Keeps this section.
    pub fn keep(&self) {
        self.discarded.set(false);
    }

    /// Returns `true` if this section was discarded.
    pub fn is_discarded(&self) -> bool {
        self.discarded.get()
    }

    /// Returns `true` if this is a debug section.
    pub fn is_debug(&self) -> bool {
        self.name().group_name() == ".debug"
            && self
                .name()
                .group_ordering()
                .is_some_and(|val| val == "S" || val == "T" || val == "P" || val == "F")
    }

    /// Returns `true` if this is a COMDAT section.
    pub fn is_comdat(&self) -> bool {
        self.characteristics.contains(ImageScn::LNK_COMDAT)
    }

    /// Returns the name of the section.
    pub fn name(&self) -> SectionName<'arena> {
        self.name
    }

    /// Returns the characteristics flags associated with this section.
    pub fn characteristics(&self) -> ImageScn {
        self.characteristics
    }

    /// Returns the section alignment from the section flags
    pub fn alignment(&self) -> P2Align {
        self.characteristics.alignment()
    }

    /// Returns the data associated with this section.
    pub fn data(&self) -> SectionNodeData<'arena> {
        self.data.get()
    }

    /// Sets the size value if this section contains uninitialized data.
    pub fn set_uninitialized_size(&self, val: u32) {
        if matches!(self.data(), SectionNodeData::Uninitialized(_)) {
            self.data.set(SectionNodeData::Uninitialized(val));
        }
    }

    /// Returns the checksum value for the section data.
    pub fn checksum(&self) -> u32 {
        self.checksum.get()
    }

    /// Replaces the checksum value for the section data.
    pub fn replace_checksum(&self, val: u32) {
        self.checksum.set(val);
    }

    /// Returns the assigned virtual address of the section.
    pub fn virtual_address(&self) -> u32 {
        self.virtual_address.get()
    }

    /// Assigns a virtual address for the section.
    pub fn assign_virtual_address(&self, val: u32) {
        self.virtual_address.set(val);
    }

    /// Returns the type of section.
    pub fn typ(&self) -> SectionType {
        *self
            .kind
            .get_or_init(|| SectionType::from_name_and_flags(self.name(), self.characteristics()))
    }

    /// Returns `true` if this is a section with GCC metadata.
    pub fn is_gccmetadata(&self) -> bool {
        self.name().as_str() == ".rdata$zzz"
            && self.relocations().is_empty()
            && self.definitions().len() == 1
    }
}

impl std::fmt::Debug for SectionNode<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SectionNode")
            .field("name", &self.name)
            .field("characteristics", &self.characteristics)
            .field("virtual_address", &self.virtual_address)
            .field("discarded", &self.discarded)
            .field("checksum", &self.checksum)
            .field("data", &self.data)
            .finish_non_exhaustive()
    }
}

/// A section name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionName<'data>(&'data str);

impl<'data> SectionName<'data> {
    pub fn as_str(&self) -> &'data str {
        self.0
    }

    /// Returns the `group name` value (`<group name>$<group ordering>`) from
    /// the section name.
    pub fn group_name(&self) -> &'data str {
        self.0
            .split_once('$')
            .map(|(group_name, _)| group_name)
            .unwrap_or(self.0)
    }

    /// Returns the `group ordering` value (`<group name>$<group ordering>`)
    /// from the section name if this is a grouped section.
    pub fn group_ordering(&self) -> Option<&'data str> {
        self.0
            .split_once('$')
            .map(|(_, group_ordering)| group_ordering)
    }
}

impl<'data> From<&'data str> for SectionName<'data> {
    fn from(value: &'data str) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for SectionName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Section node characteristic bit flags
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ImageScn(u32);

bitflags::bitflags! {
    impl ImageScn: u32 {
        const TYPE_NO_PAD = pe::IMAGE_SCN_TYPE_NO_PAD;
        const CNT_CODE = pe::IMAGE_SCN_CNT_CODE;
        const CNT_INITIALIZED_DATA = pe::IMAGE_SCN_CNT_INITIALIZED_DATA;
        const CNT_UNINITIALIZED_DATA = pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA;
        const LNK_OTHER = pe::IMAGE_SCN_LNK_OTHER;
        const LNK_INFO = pe::IMAGE_SCN_LNK_INFO;
        const LNK_REMOVE = pe::IMAGE_SCN_LNK_REMOVE;
        const LNK_COMDAT = pe::IMAGE_SCN_LNK_COMDAT;
        const GPREL = pe::IMAGE_SCN_GPREL;
        const MEM_PURGEABLE = pe::IMAGE_SCN_MEM_PURGEABLE;
        const MEM_LOCKED = pe::IMAGE_SCN_MEM_LOCKED;
        const MEM_PRELOAD = pe::IMAGE_SCN_MEM_PRELOAD;
        const LNK_NRELOC_OVFL = pe::IMAGE_SCN_LNK_NRELOC_OVFL;
        const MEM_DISCARDABLE = pe::IMAGE_SCN_MEM_DISCARDABLE;
        const MEM_NOT_CACHED = pe::IMAGE_SCN_MEM_NOT_CACHED;
        const MEM_NOT_PAGED = pe::IMAGE_SCN_MEM_NOT_PAGED;
        const MEM_SHARED = pe::IMAGE_SCN_MEM_SHARED;
        const MEM_EXECUTE = pe::IMAGE_SCN_MEM_EXECUTE;
        const MEM_READ = pe::IMAGE_SCN_MEM_READ;
        const MEM_WRITE = pe::IMAGE_SCN_MEM_WRITE;
        const _ = !0;
    }
}

impl ImageScn {
    /// Returns the alignment portion of the section flags.
    pub fn alignment(&self) -> P2Align {
        if self.contains(Self::TYPE_NO_PAD) {
            P2Align::zeroed()
        } else {
            let v = (self.0 & pe::IMAGE_SCN_ALIGN_MASK) >> IMAGE_SCN_ALIGN_SHIFT;
            if v > 0 {
                P2Align((v - 1) as u8)
            } else {
                P2Align(0)
            }
        }
    }

    /// Returns a new set of flags without any alignment value.
    pub fn without_align(self) -> Self {
        Self(self.0 & !pe::IMAGE_SCN_ALIGN_MASK)
    }

    /// Returns a new set of flags with the specified alignment.
    pub fn with_align(self, align: P2Align) -> Self {
        let align_flags = ((align.0 as u32) + 1) << IMAGE_SCN_ALIGN_SHIFT;
        Self(self.without_align().0 | align_flags)
    }

    /// Returns a new set of flags with only the `IMAGE_SCN_CNT_*` flags set.
    pub fn contents_flags(self) -> Self {
        Self(self.0 & 0xe0)
    }

    /// Returns a new set of flags with only the `IMAGE_SCN_MEM_*` flags set.
    pub fn memory_flags(self) -> Self {
        Self(self.0 & 0xfe000000)
    }

    /// Returns the output section flags for this set of section flags.
    ///
    /// This is `self.memory_flags() | self.contents_flags()`
    pub fn output_flags(self) -> Self {
        self.memory_flags() | self.contents_flags()
    }
}

/// A section alignment value represented in log2 form.
///
/// The value stored is `log2(a)` where `a` is the real alignment value. This
/// representation of section alignment makes it easier to convert between the
/// real alignment value and the alignment value inside the characteristic flags
/// of a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct P2Align(u8);

impl P2Align {
    /// Creates a new [`P2Align`] value with the specified alignment.
    ///
    /// Alignment values of 0 are treated as 1.
    ///
    /// # Panics
    /// This will panic if the alignment value is not a power of 2 between 0
    /// and 8192 inclusive.
    pub fn new(align: u32) -> Self {
        assert!(align <= 8182, "P2Align value must be >= 0 and <= 8192");
        if align == 0 {
            Self(0)
        } else {
            assert!(
                align.is_power_of_two(),
                "P2Align value must be a power of 2"
            );
            Self(align.ilog2() as u8)
        }
    }

    /// Creates a new [`P2Align`] value that holds an alignment of 1
    pub const fn zeroed() -> Self {
        Self(0)
    }

    /// Returns the alignment value
    pub fn value(&self) -> u32 {
        1 << self.0
    }
}

impl std::fmt::Display for P2Align {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value().fmt(f)
    }
}

impl std::fmt::LowerHex for P2Align {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value().fmt(f)
    }
}

/// The section data.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SectionNodeData<'arena> {
    Initialized(&'arena [u8]),
    Uninitialized(u32),
}

impl SectionNodeData<'_> {
    pub fn len(&self) -> usize {
        match self {
            Self::Initialized(data) => data.len(),
            Self::Uninitialized(size) => *size as usize,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// BFS traversal over sections with associative edges
pub struct AssociativeBfs<'arena, 'data> {
    queue: VecDeque<&'arena SectionNode<'arena, 'data>>,
    visited: HashSet<u64>,
}

impl<'arena, 'data> Iterator for AssociativeBfs<'arena, 'data> {
    type Item = &'arena SectionNode<'arena, 'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let next_section = self.queue.pop_front()?;

        for edge in next_section.associative_edges() {
            let target = edge.target();
            let mut h = DefaultHasher::new();
            std::ptr::hash(target, &mut h);
            if self.visited.insert(h.finish()) {
                self.queue.push_back(target);
            }
        }

        Some(next_section)
    }
}

/// DFS traversal over reachable sections.
#[derive(Default)]
pub struct ReachableDfs<'arena, 'data> {
    stack: VecDeque<&'arena SectionNode<'arena, 'data>>,
    visited: HashSet<u64>,
}

impl<'arena, 'data> ReachableDfs<'arena, 'data> {
    /// Creates a new empty [`ReachableDfs`] with the specified capacity.
    ///
    /// The list of section nodes to visit should be added before performing the
    /// DFS traversal.
    pub fn with_capacity(capacity: usize) -> ReachableDfs<'arena, 'data> {
        Self {
            stack: VecDeque::with_capacity(capacity),
            visited: HashSet::with_capacity(capacity),
        }
    }

    /// Returns the number of nodes left in the visit stack.
    ///
    /// This is not the number of nodes that need to be visited since the stack
    /// may include already visited nodes.
    pub fn remaining(&self) -> usize {
        self.stack.len()
    }

    /// Adds a section node to visit during the DFS traversal.
    pub fn visit(&mut self, section: &'arena SectionNode<'arena, 'data>) {
        self.stack.push_front(section);
    }
}

impl<'arena, 'data> Iterator for ReachableDfs<'arena, 'data> {
    type Item = &'arena SectionNode<'arena, 'data>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(next_section) = self.stack.pop_back() {
            let mut h = DefaultHasher::new();
            std::ptr::hash(next_section, &mut h);
            if self.visited.insert(h.finish()) {
                self.stack.reserve(next_section.adjacent_sections().count());
                self.stack.extend(next_section.adjacent_sections());
                return Some(next_section);
            }
        }

        None
    }
}
