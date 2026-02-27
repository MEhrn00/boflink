mod arena_ref;
mod pool;
mod traits;

pub use arena_ref::*;
pub use pool::*;

#[repr(transparent)]
pub struct TypedArena<T>(typed_arena::Arena<T>);

impl<T> TypedArena<T> {
    /// Constructs a new arena
    #[inline]
    pub fn new() -> Self {
        Self(typed_arena::Arena::new())
    }

    /// Returns the number of objects allocated in this arena
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if this arena is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }

    /// Returns the number of bytes allocated in this arena.
    ///
    /// # Note
    /// This excludes metadata and padding bytes for the underyling `Vec<T>`s
    #[inline]
    pub fn allocated_bytes(&self) -> usize {
        self.len() * std::mem::size_of::<T>()
    }

    /// Allocates `value` in the arena and returns a mutable reference to it
    #[inline]
    pub fn alloc(&self, value: T) -> &mut T {
        self.0.alloc(value)
    }

    /// Allocates the values from `iterable` in the arena and returns a reference
    /// to the allocated slice
    #[inline]
    pub fn alloc_extend(&self, iterable: impl IntoIterator<Item = T>) -> &mut [T] {
        self.0.alloc_extend(iterable)
    }

    /// Converts the items allocated in this arena instance into a `Vec<T>`
    #[inline]
    pub fn into_vec(self) -> Vec<T> {
        self.0.into_vec()
    }
}

impl TypedArena<u8> {
    #[inline]
    pub fn alloc_str(&self, s: &str) -> &mut str {
        self.0.alloc_str(s)
    }

    #[inline]
    pub fn alloc_bytes(&self, b: &[u8]) -> &mut [u8] {
        self.0.alloc_extend(b.iter().copied())
    }
}

impl<T> std::default::Default for TypedArena<T> {
    #[inline]
    fn default() -> Self {
        Self(Default::default())
    }
}
