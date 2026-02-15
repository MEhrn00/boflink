use std::marker::PhantomData;

use private::Sealed;

/// Trait used for deriving a sparse index from a user supplied key.
pub trait SparseKeyBuilder {
    type Key;

    /// Returns the index for the sparse array using the specified key.
    fn sparse_index(key: Self::Key) -> usize;
}

/// Map-like structure which uses the same memory layout as a sparse set.
///
/// Items can be inserted and retrieved using a user-specified key and [`SparseKeyBuilder`]
/// which can be used for turning the key into an index for the sparse array.
pub struct FixedSparseMap<K, V, B: SparseKeyBuilder<Key = K>, D: DenseIndex = u8> {
    /// Sparse array.
    ///
    /// Each element in this array is an index into the dense array.
    sparse: Box<[D]>,

    /// Dense array
    dense: Vec<V>,

    _builder: PhantomData<B>,
}

impl<K, V, B: SparseKeyBuilder<Key = K>, D: DenseIndex> FixedSparseMap<K, V, B, D> {
    /// Creates a sparse map with the specified domain.
    pub fn new(domain: usize) -> Self {
        Self {
            sparse: vec![D::tombstone(); domain].into(),
            dense: Vec::new(),
            _builder: PhantomData,
        }
    }

    /// Inserts the specified `value` at the entry for `key`.
    ///
    /// Returns `Some(V)` with the old value if the value was replaced.
    ///
    /// # Panics
    /// Panics if the derived key index exceeds the sparse domain or inserting the value
    /// into the dense array overflows the maxium elements for `D`
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let dense_idx = &mut self.sparse[B::sparse_index(key)];
        // Existing item
        if *dense_idx != D::tombstone() {
            let item = std::mem::replace(&mut self.dense[dense_idx.dense_index()], value);
            Some(item)
        } else {
            // New item
            *dense_idx = D::new(self.dense.len());
            self.dense.push(value);
            None
        }
    }

    pub fn contains(&self, key: K) -> bool {
        self.sparse
            .get(B::sparse_index(key))
            .is_some_and(|dense| *dense != D::tombstone())
    }

    /// Gets the value at `key` if it exists.
    pub fn get(&self, key: K) -> Option<&V> {
        if let Some(dense) = self.sparse.get(B::sparse_index(key))
            && *dense != D::tombstone()
        {
            Some(&self.dense[dense.dense_index()])
        } else {
            None
        }
    }

    pub fn get_mut(&mut self, key: K) -> Option<&mut V> {
        if let Some(dense) = self.sparse.get(B::sparse_index(key))
            && *dense != D::tombstone()
        {
            Some(&mut self.dense[dense.dense_index()])
        } else {
            None
        }
    }

    pub fn get_or_default(&mut self, key: K) -> &mut V
    where
        V: std::default::Default,
    {
        self.get_or_insert_with(key, std::default::Default::default)
    }

    pub fn get_or_insert_with(&mut self, key: K, default: impl FnOnce() -> V) -> &mut V {
        let dense_idx = &mut self.sparse[B::sparse_index(key)];
        if *dense_idx != D::tombstone() {
            &mut self.dense[dense_idx.dense_index()]
        } else {
            *dense_idx = D::new(self.dense.len());
            self.dense.push(default());
            &mut self.dense[dense_idx.dense_index()]
        }
    }
}

/// Index types used in the sparse array for accessing elements in the dense array.
///
/// Smaller index types allow for more efficient memory usage with larger domains
pub trait DenseIndex: Copy + 'static + Eq + PartialEq + Sealed {
    fn new(idx: usize) -> Self;
    fn dense_index(self) -> usize;
    fn tombstone() -> Self;
}

impl Sealed for u8 {}

impl DenseIndex for u8 {
    fn new(idx: usize) -> Self {
        assert!(idx <= u8::MAX as usize);
        assert!(idx != Self::tombstone().dense_index());
        idx as u8
    }

    fn dense_index(self) -> usize {
        self as usize
    }

    fn tombstone() -> Self {
        u8::MAX
    }
}

impl Sealed for u16 {}

impl DenseIndex for u16 {
    fn new(idx: usize) -> Self {
        assert!(idx <= u16::MAX as usize);
        assert!(idx != Self::tombstone().dense_index());
        idx as u16
    }

    fn dense_index(self) -> usize {
        self as usize
    }

    fn tombstone() -> Self {
        u16::MAX
    }
}

impl Sealed for u32 {}

impl DenseIndex for u32 {
    fn new(idx: usize) -> Self {
        assert!(idx <= u32::MAX as usize);
        assert!(idx != Self::tombstone().dense_index());
        idx as u32
    }

    fn dense_index(self) -> usize {
        self as usize
    }

    fn tombstone() -> Self {
        u32::MAX
    }
}

impl Sealed for usize {}

impl DenseIndex for usize {
    fn new(idx: usize) -> Self {
        assert!(idx != Self::tombstone().dense_index());
        idx
    }

    fn dense_index(self) -> usize {
        self
    }

    fn tombstone() -> Self {
        usize::MAX
    }
}

mod private {
    pub trait Sealed {}
}
