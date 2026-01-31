use std::{mem::ManuallyDrop, sync::Mutex};

use bumpalo::Bump;
use typed_arena::Arena;

type ArenaPtr<T> = Box<Arena<T>>;

#[allow(
    clippy::vec_box,
    reason = "reduces critical section time by reducing the size of each element in the vec to the size of a pointer"
)]
pub struct SyncArenaPool<T>(Mutex<Vec<ArenaPtr<T>>>);

impl<T> Default for SyncArenaPool<T> {
    fn default() -> Self {
        Self(Mutex::new(Vec::new()))
    }
}

impl<T> SyncArenaPool<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self) -> ArenaRef<'_, T> {
        ArenaRef {
            inner: ManuallyDrop::new(self.0.lock().unwrap().pop().unwrap_or_default()),
            pool: self,
        }
    }
}

pub struct ArenaRef<'a, T> {
    inner: ManuallyDrop<ArenaPtr<T>>,
    pool: &'a SyncArenaPool<T>,
}

impl<'a, T> ArenaRef<'a, T> {
    pub fn alloc(&self, value: T) -> &'a mut T {
        let allocated = self.inner.alloc(value) as *mut _;
        unsafe { &mut *allocated }
    }

    pub fn alloc_extend<I>(&self, iterator: I) -> &'a mut [T]
    where
        I: IntoIterator<Item = T>,
    {
        let allocated = self.inner.alloc_extend(iterator) as *mut _;
        unsafe { &mut *allocated }
    }

    pub fn as_arena(&self) -> &Arena<T> {
        &self.inner
    }
}

impl<'a> ArenaRef<'a, u8> {
    pub fn alloc_str(&self, s: &str) -> &'a mut str {
        let allocated = self.inner.alloc_str(s) as *mut _;
        unsafe { &mut *allocated }
    }
}

impl<T> Drop for ArenaRef<'_, T> {
    fn drop(&mut self) {
        let mut pool = self.pool.0.lock().unwrap();
        pool.push(unsafe { ManuallyDrop::take(&mut self.inner) });
    }
}

/// Box type for data allocated from a bump allocator
pub type BumpBox<'a, T> = bumpalo::boxed::Box<'a, T>;

type BumpPtr = Box<Bump>;

/// Pool of [`Bump`] allocators that is `Sync`.
#[derive(Default)]
#[allow(
    clippy::vec_box,
    reason = "reduces critical section time by reducing the size of each element in the vec to the size of a pointer"
)]
pub struct SyncBumpPool(Mutex<Vec<BumpPtr>>);

impl SyncBumpPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets an exclusive reference to [`Bump`] from the pool.
    ///
    /// This requires locking the underlying pool so this function should only
    /// be called when wanting to acquire a bump allocator from a separate
    /// thread.
    pub fn get(&self) -> BumpRef<'_> {
        BumpRef {
            inner: ManuallyDrop::new(self.0.lock().unwrap().pop().unwrap_or_default()),
            pool: self,
        }
    }
}

/// Exclusive reference to a [`Bump`] from a [`SyncBumpPool`].
///
/// This will reinsert the allocator back into the pool when it goes out of
/// scope.
pub struct BumpRef<'a> {
    inner: ManuallyDrop<BumpPtr>,
    pool: &'a SyncBumpPool,
}

impl<'a> BumpRef<'a> {
    pub fn alloc<T>(&self, val: T) -> &'a mut T {
        let allocated = self.inner.alloc(val) as *mut _;
        unsafe { &mut *allocated }
    }

    pub fn alloc_boxed<T>(&self, val: T) -> BumpBox<'a, T> {
        let allocated = self.inner.alloc(val) as *mut _;
        unsafe { BumpBox::from_raw(allocated) }
    }

    pub fn alloc_str(&self, s: &str) -> &'a mut str {
        let allocated = self.inner.alloc_str(s) as *mut _;
        unsafe { &mut *allocated }
    }

    pub fn alloc_bytes(&self, b: &[u8]) -> &'a mut [u8] {
        let allocated = self.inner.alloc_slice_copy(b) as *mut _;
        unsafe { &mut *allocated }
    }
}

impl Drop for BumpRef<'_> {
    fn drop(&mut self) {
        let mut pool = self.pool.0.lock().unwrap();
        pool.push(unsafe { ManuallyDrop::take(&mut self.inner) });
    }
}
