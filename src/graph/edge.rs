use std::{cell::Cell, marker::PhantomData};

use super::node::SymbolName;

use __private::SealedTrait;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use object::pe::{
    IMAGE_COMDAT_SELECT_ANY, IMAGE_COMDAT_SELECT_ASSOCIATIVE, IMAGE_COMDAT_SELECT_EXACT_MATCH,
    IMAGE_COMDAT_SELECT_LARGEST, IMAGE_COMDAT_SELECT_NODUPLICATES, IMAGE_COMDAT_SELECT_SAME_SIZE,
};

pub trait EdgeListTraversal: SealedTrait {}

pub struct OutgoingEdges;
impl SealedTrait for OutgoingEdges {}
impl EdgeListTraversal for OutgoingEdges {}

pub struct IncomingEdges;
impl SealedTrait for IncomingEdges {}
impl EdgeListTraversal for IncomingEdges {}

pub trait EdgeListEntry<'arena, Source, Target, Weight, Tr: EdgeListTraversal>:
    SealedTrait
{
    fn next_node(&self) -> &Cell<Option<&'arena Edge<'arena, Source, Target, Weight>>>;
}

#[derive(Debug, Copy, Clone, thiserror::Error)]
#[error("invalid COMDAT selection ({0})")]
pub struct TryFromComdatSelectionError(u8);

/// An adjacency list for a node's adjacent edges.
pub struct EdgeList<'arena, Source, Target, Weight, Tr: EdgeListTraversal>
where
    Edge<'arena, Source, Target, Weight>: EdgeListEntry<'arena, Source, Target, Weight, Tr>,
{
    /// The head edge in the list.
    head: Cell<Option<&'arena Edge<'arena, Source, Target, Weight>>>,

    /// The tail edge in the list.
    tail: Cell<Option<&'arena Edge<'arena, Source, Target, Weight>>>,

    /// The number of edges in the list.
    size: Cell<usize>,

    /// The traversal type for this edge list.
    _traversal: PhantomData<Tr>,
}

impl<'arena, Source, Target, Weight, Tr: EdgeListTraversal>
    EdgeList<'arena, Source, Target, Weight, Tr>
where
    Edge<'arena, Source, Target, Weight>: EdgeListEntry<'arena, Source, Target, Weight, Tr>,
{
    /// Creates a new empty [`EdgeList`].
    pub(super) fn new() -> EdgeList<'arena, Source, Target, Weight, Tr> {
        Self {
            head: Cell::new(None),
            tail: Cell::new(None),
            size: Cell::new(0),
            _traversal: PhantomData,
        }
    }

    /// Returns the number of entries in this [`EdgeList`].
    #[inline]
    pub fn len(&self) -> usize {
        self.size.get()
    }

    /// Returns `true` if the list is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.get().is_none()
    }

    /// Returns the first edge in the edge list if the list is non-empty.
    #[inline]
    pub fn front(&self) -> Option<&'arena Edge<'arena, Source, Target, Weight>> {
        self.head.get()
    }

    /// Returns the last edge in the edge list if the list is non-empty.
    #[inline]
    pub fn back(&self) -> Option<&'arena Edge<'arena, Source, Target, Weight>> {
        self.tail.get()
    }

    /// Returns an [`EdgeListIter`] for iterating over the list of edges.
    #[inline]
    pub fn iter(&self) -> EdgeListIter<'arena, Source, Target, Weight, Tr> {
        EdgeListIter((self.head.get(), PhantomData))
    }

    /// Adds an edge to this list with the specified weight and linked to the
    /// target node.
    pub(super) fn push_back(&self, edge: &'arena Edge<'arena, Source, Target, Weight>) {
        if let Some(tail_node) = self.tail.get() {
            tail_node.next_node().set(Some(edge));
            self.tail.set(Some(edge));
        } else {
            self.head.set(Some(edge));
            self.tail.set(Some(edge));
        }

        self.size.set(self.size.get() + 1);
    }

    /// Removes the first item from the edge list and returns it.
    ///
    /// # Note
    /// This will leak the removed edge.
    pub(super) fn pop_front(&self) -> Option<&'arena Edge<'arena, Source, Target, Weight>> {
        let removed_edge = self.head.get()?;
        let size = self.size.get().saturating_sub(1);

        self.head.set(removed_edge.next_node().take());
        if size == 0 {
            self.tail.take();
        }

        self.size.set(size);
        Some(removed_edge)
    }

    /// Removes all of the nodes from the edge list.
    ///
    /// # Note
    /// This does not deallocate the edges since they are handled by the arena.
    pub(super) fn clear(&self) {
        // Remove the next edge links in each edge.
        while let Some(edge) = self.pop_front() {
            edge.next_node().take();
        }

        // Post-condition asserting that pop_front() removed all of the edges
        // correctly
        debug_assert!(self.is_empty());
    }
}

impl<'arena, Source, Target, Weight, T: EdgeListTraversal> IntoIterator
    for EdgeList<'arena, Source, Target, Weight, T>
where
    Edge<'arena, Source, Target, Weight>: EdgeListEntry<'arena, Source, Target, Weight, T>,
    EdgeListIter<'arena, Source, Target, Weight, T>:
        Iterator<Item = &'arena Edge<'arena, Source, Target, Weight>>,
{
    type Item = <Self::IntoIter as Iterator>::Item;
    type IntoIter = EdgeListIter<'arena, Source, Target, Weight, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'arena, Source, Target, Weight, T: EdgeListTraversal> IntoIterator
    for &EdgeList<'arena, Source, Target, Weight, T>
where
    Edge<'arena, Source, Target, Weight>: EdgeListEntry<'arena, Source, Target, Weight, T>,
    EdgeListIter<'arena, Source, Target, Weight, T>:
        Iterator<Item = &'arena Edge<'arena, Source, Target, Weight>>,
{
    type Item = <Self::IntoIter as Iterator>::Item;
    type IntoIter = EdgeListIter<'arena, Source, Target, Weight, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator for iterating over the edges of an [`EdgeList`].
pub struct EdgeListIter<'arena, Source, Target, Weight, T: EdgeListTraversal>(
    (
        Option<&'arena Edge<'arena, Source, Target, Weight>>,
        PhantomData<T>,
    ),
);

impl<Source, Target, Weight, T: EdgeListTraversal> Clone
    for EdgeListIter<'_, Source, Target, Weight, T>
{
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<'arena, Source, Target, Weight, T: EdgeListTraversal> Iterator
    for EdgeListIter<'arena, Source, Target, Weight, T>
where
    Edge<'arena, Source, Target, Weight>: EdgeListEntry<'arena, Source, Target, Weight, T>,
{
    type Item = &'arena Edge<'arena, Source, Target, Weight>;

    fn next(&mut self) -> Option<Self::Item> {
        let curr = self.0.0?;
        self.0.0 = EdgeListEntry::<_, _, _, T>::next_node(curr).get();
        Some(curr)
    }
}

/// A graph edge.
pub struct Edge<'arena, S, T, W> {
    /// The next outgoing edge in the list of outgoing edges for the source
    /// node
    next_outgoing: Cell<Option<&'arena Edge<'arena, S, T, W>>>,

    /// The next incoming edge in the list of incoming edges for the target
    /// node
    next_incoming: Cell<Option<&'arena Edge<'arena, S, T, W>>>,

    /// Reference to the source node for this edge.
    source_node: Cell<&'arena S>,

    /// Reference to the target node for this edge.
    target_node: Cell<&'arena T>,

    /// The edge weight
    weight: W,
}

impl<'arena, S, T, W> Edge<'arena, S, T, W> {
    #[inline]
    pub(super) fn new(
        source_node: &'arena S,
        target_node: &'arena T,
        weight: W,
    ) -> Edge<'arena, S, T, W> {
        Self {
            next_outgoing: Cell::new(None),
            next_incoming: Cell::new(None),
            source_node: Cell::new(source_node),
            target_node: Cell::new(target_node),
            weight,
        }
    }

    /// Replaces the source node joined to this edge. The edge must be removed
    /// from the source node before it can be replaced.
    #[inline]
    pub(super) fn replace_source(&self, source_node: &'arena S) {
        debug_assert!(self.next_outgoing.get().is_none());
        self.source_node.replace(source_node);
    }

    /// Returns a reference to the source node joined to this edge.
    #[inline]
    pub fn source(&self) -> &'arena S {
        self.source_node.get()
    }

    /// Returns a reference to the target node joined to this edge.
    #[inline]
    pub fn target(&self) -> &'arena T {
        self.target_node.get()
    }

    /// Returns a reference to the edge weight
    #[inline]
    pub fn weight(&self) -> &W {
        &self.weight
    }

    /// Returns a mutable reference to the edge weight
    #[inline]
    pub fn weight_mut(&mut self) -> &mut W {
        &mut self.weight
    }
}

impl<S, T, W> SealedTrait for Edge<'_, S, T, W> {}

impl<'arena, Source, Target, Weight> EdgeListEntry<'arena, Source, Target, Weight, OutgoingEdges>
    for Edge<'arena, Source, Target, Weight>
{
    #[inline]
    fn next_node(&self) -> &Cell<Option<&'arena Edge<'arena, Source, Target, Weight>>> {
        &self.next_outgoing
    }
}

impl<'arena, Source, Target, Weight> EdgeListEntry<'arena, Source, Target, Weight, IncomingEdges>
    for Edge<'arena, Source, Target, Weight>
{
    #[inline]
    fn next_node(&self) -> &Cell<Option<&'arena Edge<'arena, Source, Target, Weight>>> {
        &self.next_incoming
    }
}

/// The weight for a definition edge.
pub struct DefinitionEdgeWeight {
    /// The virtual address for the definition.
    virtual_address: Cell<u32>,

    /// The COMDAT selection if the symbol is a COMDAT symbol.
    pub(super) selection: Option<ComdatSelection>,
}

impl DefinitionEdgeWeight {
    #[inline]
    pub(super) fn new(
        virtual_address: u32,
        selection: Option<ComdatSelection>,
    ) -> DefinitionEdgeWeight {
        Self {
            virtual_address: Cell::new(virtual_address),
            selection,
        }
    }

    /// Returns the address of the symbol
    #[inline]
    pub fn address(&self) -> u32 {
        self.virtual_address.get()
    }

    /// Sets the virtual address for the symbol.
    ///
    /// Used for assigning addresses to COMMON symbols.
    #[inline]
    pub fn set_address(&self, val: u32) {
        self.virtual_address.set(val);
    }

    /// Returns the COMDAT selection for the symbol if this is a COMDAT symbol.
    #[inline]
    pub fn selection(&self) -> Option<ComdatSelection> {
        self.selection
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[num_enum(
    error_type(
        name = TryFromComdatSelectionError,
        constructor = TryFromComdatSelectionError,
    )
)]
#[repr(u8)]
pub enum ComdatSelection {
    NoDuplicates = IMAGE_COMDAT_SELECT_NODUPLICATES,
    Any = IMAGE_COMDAT_SELECT_ANY,
    SameSize = IMAGE_COMDAT_SELECT_SAME_SIZE,
    ExactMatch = IMAGE_COMDAT_SELECT_EXACT_MATCH,
    Associative = IMAGE_COMDAT_SELECT_ASSOCIATIVE,
    Largest = IMAGE_COMDAT_SELECT_LARGEST,
}

/// The weight for a relocation edge.
pub struct RelocationEdgeWeight {
    /// The virtual address of the relocation.
    pub(super) virtual_address: u32,

    /// The relocation type.
    typ: u16,
}

impl RelocationEdgeWeight {
    #[inline]
    pub(super) fn new(virtual_address: u32, typ: u16) -> RelocationEdgeWeight {
        Self {
            virtual_address,
            typ,
        }
    }

    #[inline]
    pub fn address(&self) -> u32 {
        self.virtual_address
    }

    #[inline]
    pub fn typ(&self) -> u16 {
        self.typ
    }
}

/// The weight for an import edge.
pub struct ImportEdgeWeight<'data> {
    /// The name to import the symbol as.
    import_name: SymbolName<'data>,
}

impl<'data> ImportEdgeWeight<'data> {
    #[inline]
    pub(super) fn new(import_name: impl Into<SymbolName<'data>>) -> ImportEdgeWeight<'data> {
        Self {
            import_name: import_name.into(),
        }
    }

    #[inline]
    pub fn import_name(&self) -> SymbolName<'data> {
        self.import_name
    }
}

/// The weight for a COMDAT associative section edge.
pub struct AssociativeSectionEdgeWeight;

mod __private {
    pub trait SealedTrait {}
}
