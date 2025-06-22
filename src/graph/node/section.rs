use std::{
    cell::Cell,
    collections::{HashSet, VecDeque},
    hash::{DefaultHasher, Hasher},
};

use log::debug;
use object::pe::{
    IMAGE_SCN_ALIGN_1BYTES, IMAGE_SCN_ALIGN_2BYTES, IMAGE_SCN_ALIGN_4BYTES, IMAGE_SCN_ALIGN_8BYTES,
    IMAGE_SCN_ALIGN_16BYTES, IMAGE_SCN_ALIGN_32BYTES, IMAGE_SCN_ALIGN_64BYTES,
    IMAGE_SCN_ALIGN_128BYTES, IMAGE_SCN_ALIGN_256BYTES, IMAGE_SCN_ALIGN_512BYTES,
    IMAGE_SCN_ALIGN_1024BYTES, IMAGE_SCN_ALIGN_2048BYTES, IMAGE_SCN_ALIGN_4096BYTES,
    IMAGE_SCN_ALIGN_8192BYTES, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_GPREL, IMAGE_SCN_LNK_COMDAT, IMAGE_SCN_LNK_INFO,
    IMAGE_SCN_LNK_NRELOC_OVFL, IMAGE_SCN_LNK_OTHER, IMAGE_SCN_LNK_REMOVE,
    IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_LOCKED,
    IMAGE_SCN_MEM_NOT_CACHED, IMAGE_SCN_MEM_NOT_PAGED, IMAGE_SCN_MEM_PRELOAD,
    IMAGE_SCN_MEM_PURGEABLE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_SHARED, IMAGE_SCN_MEM_WRITE,
    IMAGE_SCN_TYPE_NO_PAD,
};

use crate::graph::edge::{
    AssociativeSectionEdgeWeight, DefinitionEdgeWeight, EdgeList, IncomingEdges, OutgoingEdges,
    RelocationEdgeWeight,
};

use super::{CoffNode, SymbolNode, SymbolNodeStorageClass};

/// Shift value for section alignment flags
const SECTION_ALIGN_SHIFT: u32 = 20;

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

/// A section node in the graph.
pub struct SectionNode<'arena, 'data> {
    /// The list of outgoing relocation edges for this section.
    relocation_edges:
        EdgeList<'arena, Self, SymbolNode<'arena, 'data>, RelocationEdgeWeight, OutgoingEdges>,

    /// The list of incoming definition edges for this section.
    definition_edges:
        EdgeList<'arena, SymbolNode<'arena, 'data>, Self, DefinitionEdgeWeight, IncomingEdges>,

    /// The list of outgoing COMDAT associative edges for this section.
    associative_edges: EdgeList<
        'arena,
        Self,
        SectionNode<'arena, 'data>,
        AssociativeSectionEdgeWeight,
        OutgoingEdges,
    >,

    /// The COFF this section is from.
    coff: &'arena CoffNode<'data>,

    /// The rebased virtual address of the section.
    virtual_address: Cell<u32>,

    /// If this section is to be discarded.
    discarded: Cell<bool>,

    /// The name of the section.
    name: SectionName<'arena>,

    /// The characteristics of the section.
    characteristics: SectionNodeCharacteristics,

    /// The section data.
    data: Cell<SectionNodeData<'arena>>,

    /// The data checksum
    checksum: Cell<u32>,
}

impl<'arena, 'data> SectionNode<'arena, 'data> {
    #[inline]
    pub fn new(
        name: impl Into<SectionName<'arena>>,
        characteristics: SectionNodeCharacteristics,
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
        }
    }

    /// Returns the list of outgoing relocation edges for this section.
    #[inline]
    pub fn relocations(
        &self,
    ) -> &EdgeList<'arena, Self, SymbolNode<'arena, 'data>, RelocationEdgeWeight, OutgoingEdges>
    {
        &self.relocation_edges
    }

    /// Returns the list of incoming relocation edges for this section.
    #[inline]
    pub fn definitions(
        &self,
    ) -> &EdgeList<'arena, SymbolNode<'arena, 'data>, Self, DefinitionEdgeWeight, IncomingEdges>
    {
        &self.definition_edges
    }

    /// If this is a code section, attempts to find the associated .pdata section
    /// with the exception information.
    pub fn find_associated_pdata_section(&self) -> Option<&'arena SectionNode<'arena, 'data>> {
        if !self
            .characteristics()
            .contains(SectionNodeCharacteristics::CntCode)
        {
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

        debug!("traversing incoming references to find .pdata section");

        // Traverse through incoming relocations to find the .pdata section
        // which references this code section.
        for possible_joined_symbol in self.definitions().iter().filter_map(|edge| {
            let defined_symbol = edge.source();
            (defined_symbol.storage_class() == SymbolNodeStorageClass::Label
                || defined_symbol.is_section_symbol())
            .then_some(defined_symbol)
        }) {
            debug!("possible symbol '{}'", possible_joined_symbol.name());
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
    #[inline]
    pub fn associative_edges(
        &self,
    ) -> &EdgeList<
        'arena,
        Self,
        SectionNode<'arena, 'data>,
        AssociativeSectionEdgeWeight,
        OutgoingEdges,
    > {
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
    /// Or a "next-hop" connection through a symbol node
    /// - section node -> relocation edge -> symbol node -> definition edge -> section node.
    pub fn adjacent_sections(&self) -> impl Iterator<Item = &'arena SectionNode<'arena, 'data>> {
        self.associative_edges()
            .iter()
            .map(|associative_edge| associative_edge.target())
            .chain(self.relocations().iter().flat_map(|relocation_edge| {
                relocation_edge
                    .target()
                    .definitions()
                    .iter()
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
    #[inline]
    pub fn reachable_dfs(&'arena self) -> ReachableDfs<'arena, 'data> {
        ReachableDfs {
            stack: VecDeque::from([self]),
            visited: HashSet::new(),
        }
    }

    /// Returns the COFF associated with this section.
    ///
    /// This is the COFF where the section node was sourced from.
    #[inline]
    pub fn coff(&self) -> &'arena CoffNode<'data> {
        self.coff
    }

    /// Marks this section as being discarded.
    #[inline]
    pub fn discard(&self) {
        self.discarded.set(true);
    }

    /// Sets the discarded value for the section.
    #[inline]
    pub fn set_discarded(&self, val: bool) {
        self.discarded.set(val);
    }

    /// Keeps this section.
    #[inline]
    #[allow(unused)]
    pub fn keep(&self) {
        self.discarded.set(false);
    }

    /// Returns `true` if this section was discarded.
    #[inline]
    pub fn is_discarded(&self) -> bool {
        self.discarded.get()
    }

    /// Returns `true` if this is a debug section.
    #[inline]
    pub fn is_debug(&self) -> bool {
        self.name().group_name() == ".debug"
            && self
                .name()
                .group_ordering()
                .is_some_and(|val| val == "S" || val == "T" || val == "P" || val == "F")
    }

    /// Returns `true` if this is a COMDAT section.
    #[inline]
    pub fn is_comdat(&self) -> bool {
        self.characteristics()
            .contains(SectionNodeCharacteristics::LnkComdat)
    }

    /// Returns the name of the section.
    #[inline]
    pub fn name(&self) -> SectionName<'arena> {
        self.name
    }

    /// Returns the characteristics flags associated with this section.
    #[inline]
    pub fn characteristics(&self) -> SectionNodeCharacteristics {
        self.characteristics
    }

    /// Returns the data associated with this section.
    #[inline]
    pub fn data(&self) -> SectionNodeData<'arena> {
        self.data.get()
    }

    /// Sets the size value if this section contains uninitialized data.
    #[inline]
    pub fn set_uninitialized_size(&self, val: u32) {
        if matches!(self.data(), SectionNodeData::Uninitialized(_)) {
            self.data.set(SectionNodeData::Uninitialized(val));
        }
    }

    /// Returns the checksum value for the section data.
    #[inline]
    pub fn checksum(&self) -> u32 {
        self.checksum.get()
    }

    /// Replaces the checksum value for the section data.
    #[inline]
    pub fn replace_checksum(&self, val: u32) {
        self.checksum.set(val);
    }

    /// Returns the assigned virtual address of the section.
    #[inline]
    pub fn virtual_address(&self) -> u32 {
        self.virtual_address.get()
    }

    /// Assigns a virtual address for the section.
    #[inline]
    pub fn assign_virtual_address(&self, val: u32) {
        self.virtual_address.set(val);
    }

    /// Returns the type of section.
    pub fn typ(&self) -> SectionType {
        if self.name().group_name() == ".bss"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntUninitializedData
                    | SectionNodeCharacteristics::MemRead
                    | SectionNodeCharacteristics::MemWrite,
            )
        {
            SectionType::UninitializedData
        } else if self.name().group_name() == ".cormeta"
            && self
                .characteristics()
                .contains(SectionNodeCharacteristics::LnkInfo)
        {
            SectionType::ClrMetadata
        } else if self.name().group_name() == ".data"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntInitializedData
                    | SectionNodeCharacteristics::MemRead
                    | SectionNodeCharacteristics::MemWrite,
            )
        {
            SectionType::InitializedData
        } else if self.name().as_str() == ".debug$P"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntInitializedData
                    | SectionNodeCharacteristics::MemRead
                    | SectionNodeCharacteristics::MemDiscardable,
            )
        {
            SectionType::PrecompiledDebugTypes
        } else if self.name().as_str() == ".debug$S"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntInitializedData
                    | SectionNodeCharacteristics::MemRead
                    | SectionNodeCharacteristics::MemDiscardable,
            )
        {
            SectionType::DebugSymbols
        } else if self.name().as_str() == ".debug$T"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntInitializedData
                    | SectionNodeCharacteristics::MemRead
                    | SectionNodeCharacteristics::MemDiscardable,
            )
        {
            SectionType::DebugTypes
        } else if self.name().group_name() == ".drectve"
            && self
                .characteristics()
                .contains(SectionNodeCharacteristics::LnkInfo)
        {
            SectionType::LinkerOptions
        } else if self.name().group_name() == ".idata"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntInitializedData
                    | SectionNodeCharacteristics::MemRead
                    | SectionNodeCharacteristics::MemWrite,
            )
        {
            SectionType::ImportTables
        } else if self.name().group_name() == ".pdata"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntInitializedData
                    | SectionNodeCharacteristics::MemRead,
            )
        {
            SectionType::Exception
        } else if self.name().group_name() == ".rdata"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntInitializedData
                    | SectionNodeCharacteristics::MemRead,
            )
        {
            SectionType::ReadOnlyData
        } else if self.name().group_name() == ".rsrc"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntInitializedData
                    | SectionNodeCharacteristics::MemRead,
            )
        {
            SectionType::ResourceDirectory
        } else if self.name().group_name() == ".sbss"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntUninitializedData
                    | SectionNodeCharacteristics::MemRead
                    | SectionNodeCharacteristics::MemWrite
                    | SectionNodeCharacteristics::GPRel,
            )
        {
            SectionType::GPRelUninitialized
        } else if self.name().group_name() == ".sdata"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntInitializedData
                    | SectionNodeCharacteristics::MemRead
                    | SectionNodeCharacteristics::GPRel,
            )
        {
            SectionType::GPRelInitialized
        } else if self.name().group_name() == ".srdata"
            && self
                .characteristics()
                .contains(SectionNodeCharacteristics::LnkInfo)
        {
            SectionType::RegisteredExceptionHandler
        } else if self.name().group_name() == ".text"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntCode
                    | SectionNodeCharacteristics::MemExecute
                    | SectionNodeCharacteristics::MemRead,
            )
        {
            SectionType::Code
        } else if self.name().group_name() == ".tls"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntInitializedData
                    | SectionNodeCharacteristics::MemRead
                    | SectionNodeCharacteristics::MemWrite,
            )
        {
            SectionType::Tls
        } else if self.name().group_name() == ".xdata"
            && self.characteristics().contains(
                SectionNodeCharacteristics::CntInitializedData
                    | SectionNodeCharacteristics::MemRead,
            )
        {
            SectionType::ExceptionUnwind
        } else {
            SectionType::Other
        }
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
    #[inline]
    pub fn as_str(&self) -> &'data str {
        self.0
    }

    /// Returns the `group name` value (`<group name>$<group ordering>`) from
    /// the section name.
    #[inline]
    pub fn group_name(&self) -> &'data str {
        self.0
            .split_once('$')
            .map(|(group_name, _)| group_name)
            .unwrap_or(self.0)
    }

    /// Returns the `group ordering` value (`<group name>$<group ordering>`)
    /// from the section name if this is a grouped section.
    #[inline]
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

/// Section node characteristic flags
#[derive(Debug, Copy, Clone)]
pub struct SectionNodeCharacteristics(u32);

bitflags::bitflags! {
    impl SectionNodeCharacteristics: u32 {
        const TypeNoPad = IMAGE_SCN_TYPE_NO_PAD;
        const CntCode = IMAGE_SCN_CNT_CODE;
        const CntInitializedData = IMAGE_SCN_CNT_INITIALIZED_DATA;
        const CntUninitializedData = IMAGE_SCN_CNT_UNINITIALIZED_DATA;
        const LnkOther = IMAGE_SCN_LNK_OTHER;
        const LnkInfo = IMAGE_SCN_LNK_INFO;
        const LnkRemove = IMAGE_SCN_LNK_REMOVE;
        const LnkComdat = IMAGE_SCN_LNK_COMDAT;
        const GPRel = IMAGE_SCN_GPREL;
        const MemPurgeable = IMAGE_SCN_MEM_PURGEABLE;
        const MemLocked = IMAGE_SCN_MEM_LOCKED;
        const MemPreload = IMAGE_SCN_MEM_PRELOAD;
        const Align1Bytes = IMAGE_SCN_ALIGN_1BYTES;
        const Align2Bytes = IMAGE_SCN_ALIGN_2BYTES;
        const Align4Bytes = IMAGE_SCN_ALIGN_4BYTES;
        const Align8Bytes = IMAGE_SCN_ALIGN_8BYTES;
        const Align16Bytes = IMAGE_SCN_ALIGN_16BYTES;
        const Align32Bytes = IMAGE_SCN_ALIGN_32BYTES;
        const Align64Bytes = IMAGE_SCN_ALIGN_64BYTES;
        const Align128Bytes = IMAGE_SCN_ALIGN_128BYTES;
        const Align256Bytes = IMAGE_SCN_ALIGN_256BYTES;
        const Align512Bytes = IMAGE_SCN_ALIGN_512BYTES;
        const Align1024Bytes = IMAGE_SCN_ALIGN_1024BYTES;
        const Align2048Bytes = IMAGE_SCN_ALIGN_2048BYTES;
        const Align4096Bytes = IMAGE_SCN_ALIGN_4096BYTES;
        const Align8192Bytes = IMAGE_SCN_ALIGN_8192BYTES;
        const LnkNRelocOvfl = IMAGE_SCN_LNK_NRELOC_OVFL;
        const MemDiscardable = IMAGE_SCN_MEM_DISCARDABLE;
        const MemNotCached = IMAGE_SCN_MEM_NOT_CACHED;
        const MemNotPaged = IMAGE_SCN_MEM_NOT_PAGED;
        const MemShared = IMAGE_SCN_MEM_SHARED;
        const MemExecute = IMAGE_SCN_MEM_EXECUTE;
        const MemRead = IMAGE_SCN_MEM_READ;
        const MemWrite = IMAGE_SCN_MEM_WRITE;
        const _ = !0;
    }
}

impl SectionNodeCharacteristics {
    /// Returns the alignment value if it exists
    pub fn alignment(&self) -> Option<usize> {
        (self.0 & (0xfu32 << 20) != 0).then(|| 2usize.pow(((self.0 >> 20) & 0xf) - 1))
    }

    /// Returns a new [`SectionNodeCharacteristics`] without the alignment
    /// bits set
    pub fn zero_align(&self) -> SectionNodeCharacteristics {
        Self(self.0 & !(0xfu32 << SECTION_ALIGN_SHIFT))
    }

    /// Set the characteristic alignment flag to the specified value.
    ///
    /// The value must be a multiple of two or this has no effect.
    pub fn set_alignment(&mut self, val: u32) {
        if val == 1 || (val != 0 && (val & (val - 1)) == 0) {
            self.insert(SectionNodeCharacteristics::from_bits_truncate(
                (val.ilog2() + 1) << SECTION_ALIGN_SHIFT,
            ));
        }
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
