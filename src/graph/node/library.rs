use crate::graph::edge::{EdgeList, ImportEdge, IncomingEdges};

/// A library node in the graph.
pub struct LibraryNode<'arena, 'data> {
    /// The list of incoming import edges for this library node.
    import_edges: EdgeList<'arena, ImportEdge<'arena, 'data>, IncomingEdges>,

    /// The node weight.
    weight: LibraryNodeWeight<'data>,
}

impl<'arena, 'data> LibraryNode<'arena, 'data> {
    pub fn new(weight: LibraryNodeWeight<'data>) -> LibraryNode<'arena, 'data> {
        Self {
            import_edges: EdgeList::new(),
            weight,
        }
    }

    pub fn imports(&self) -> &EdgeList<'arena, ImportEdge<'arena, 'data>, IncomingEdges> {
        &self.import_edges
    }

    pub fn name(&self) -> LibraryName<'data> {
        self.weight.name
    }
}

/// The weight for a library node.
pub struct LibraryNodeWeight<'data> {
    /// The name of the library.
    name: LibraryName<'data>,
}

impl<'data> LibraryNodeWeight<'data> {
    pub fn new(name: impl Into<LibraryName<'data>>) -> LibraryNodeWeight<'data> {
        Self { name: name.into() }
    }
}

/// A library name.
#[derive(Debug, Clone, Copy)]
pub struct LibraryName<'data>(&'data str);

impl LibraryName<'_> {
    pub fn trim_dll_suffix(&self) -> &str {
        self.0
            .rsplit_once('.')
            .and_then(|(prefix, suffix)| suffix.eq_ignore_ascii_case("dll").then_some(prefix))
            .unwrap_or(self.0)
    }
}

impl<'data> From<&'data str> for LibraryName<'data> {
    fn from(value: &'data str) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for LibraryName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
