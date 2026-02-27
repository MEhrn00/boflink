mod boxed;
mod pool;
mod traits;

pub use boxed::*;
pub use pool::*;

#[derive(Debug, Default)]
#[repr(transparent)]
pub struct Bump(bumpalo::Bump);

impl Bump {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn alloc<T>(&self, value: T) -> &mut T {
        self.0.alloc(value)
    }

    #[inline]
    pub fn alloc_with<F, T>(&self, f: F) -> &mut T
    where
        F: FnOnce() -> T,
    {
        self.0.alloc_with(f)
    }

    #[inline]
    pub fn alloc_bytes(&self, b: &[u8]) -> &mut [u8] {
        self.0.alloc_slice_copy(b)
    }

    #[inline]
    pub fn allocated_bytes(&self) -> usize {
        self.0.allocated_bytes()
    }
}
