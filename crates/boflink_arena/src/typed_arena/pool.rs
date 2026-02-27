use std::mem::ManuallyDrop;

use crate::sync::Mutex;

use super::{TypedArena, TypedArenaRef};

#[allow(
    clippy::vec_box,
    reason = "reduces critical section time when acquiring and releasing objects"
)]
#[repr(transparent)]
pub struct TypedArenaPool<T>(Mutex<Vec<Box<TypedArena<T>>>>);

impl<T> TypedArenaPool<T> {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn with_initial(count: usize) -> Self {
        Self(Mutex::new(
            (0..count).map(|_| Box::new(TypedArena::new())).collect(),
        ))
    }

    #[inline]
    pub fn get(&self) -> TypedArenaHandle<'_, T> {
        TypedArenaHandle {
            inner: ManuallyDrop::new(self.0.lock().pop().unwrap_or_default()),
            pool: self,
        }
    }
}

impl<T> Default for TypedArenaPool<T> {
    #[inline]
    fn default() -> Self {
        Self(Mutex::new(Vec::new()))
    }
}

pub struct TypedArenaHandle<'a, T> {
    inner: ManuallyDrop<Box<TypedArena<T>>>,
    pool: &'a TypedArenaPool<T>,
}

impl<'a, T> TypedArenaHandle<'a, T> {
    #[inline]
    pub fn alloc(&self, value: T) -> &'a mut T {
        let allocated = self.inner.alloc(value) as *mut _;
        unsafe { &mut *allocated }
    }

    pub fn alloc_ref(&self, value: T) -> TypedArenaRef<'a, T> {
        let allocated = self.inner.alloc(value) as *mut _;
        unsafe { TypedArenaRef(&mut *allocated) }
    }

    #[inline]
    pub fn alloc_extend<I>(&self, iterator: I) -> &'a mut [T]
    where
        I: IntoIterator<Item = T>,
    {
        let allocated = self.inner.alloc_extend(iterator) as *mut _;
        unsafe { &mut *allocated }
    }

    #[inline]
    pub fn as_arena(&self) -> &TypedArena<T> {
        &self.inner
    }
}

impl<'a> TypedArenaHandle<'a, u8> {
    #[inline]
    pub fn alloc_str(&self, s: &str) -> &'a mut str {
        let allocated = self.inner.alloc_str(s) as *mut _;
        unsafe { &mut *allocated }
    }

    #[inline]
    pub fn alloc_bytes(&self, b: &[u8]) -> &'a mut [u8] {
        self.alloc_extend(b.iter().copied())
    }
}

impl<T> Drop for TypedArenaHandle<'_, T> {
    #[inline]
    fn drop(&mut self) {
        let mut pool = self.pool.0.lock();
        pool.push(unsafe { ManuallyDrop::take(&mut self.inner) });
    }
}
