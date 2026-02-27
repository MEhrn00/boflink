use std::mem::ManuallyDrop;

use crate::sync::Mutex;

use super::{Bump, BumpBox};

#[allow(
    clippy::vec_box,
    reason = "reduces critical section time when acquiring and releasing objects"
)]
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct BumpPool(Mutex<Vec<Box<Bump>>>);

impl BumpPool {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn with_initial(count: usize) -> Self {
        Self(Mutex::new(
            (0..count).map(|_| Box::new(Bump::new())).collect(),
        ))
    }

    #[inline]
    pub fn get(&self) -> BumpHandle<'_> {
        BumpHandle {
            inner: ManuallyDrop::new(self.0.lock().pop().unwrap_or_default()),
            pool: self,
        }
    }
}

pub struct BumpHandle<'a> {
    inner: ManuallyDrop<Box<Bump>>,
    pool: &'a BumpPool,
}

impl<'a> BumpHandle<'a> {
    #[inline]
    pub fn alloc<T>(&self, value: T) -> &'a mut T {
        let allocated = self.inner.alloc(value) as *mut _;
        unsafe { &mut *allocated }
    }

    #[inline]
    pub fn alloc_with<F, T>(&self, f: F) -> &'a mut T
    where
        F: FnOnce() -> T,
    {
        let allocated = self.inner.alloc_with(f) as *mut _;
        unsafe { &mut *allocated }
    }

    #[inline]
    pub fn alloc_bytes(&self, b: &[u8]) -> &'a mut [u8] {
        let allocated = self.inner.alloc_bytes(b) as *mut _;
        unsafe { &mut *allocated }
    }

    #[inline]
    pub fn alloc_boxed<T>(&self, value: T) -> BumpBox<'a, T> {
        let allocated = self.inner.alloc(value) as *mut _;
        unsafe { BumpBox::from_raw(allocated) }
    }

    #[inline]
    pub fn alloc_boxed_with<F, T>(&self, f: F) -> BumpBox<'a, T>
    where
        F: FnOnce() -> T,
    {
        let allocated = self.inner.alloc_with(f) as *mut _;
        unsafe { BumpBox::from_raw(allocated) }
    }

    #[inline]
    pub fn as_bump(&self) -> &Bump {
        &self.inner
    }
}

impl Drop for BumpHandle<'_> {
    #[inline]
    fn drop(&mut self) {
        let mut pool = self.pool.0.lock();
        pool.push(unsafe { ManuallyDrop::take(&mut self.inner) });
    }
}
