//! Module for arena-based memory allocators.
//!
//! Arena allocators provide a lot of utility for this program. Firstly, arena
//! allocators allocate memory a lot quicker than global allocator such as [`std::alloc::Global`]
//! since they do not need to be thread-safe and do not need to manage a free
//! list.
//! Secondly, arena allocators provide a means of "saving" values that need to
//! exist throughout the entire program runtime but are constructed dynamically
//! some time in the middle. An example of this is if a symbol name string
//! needs to have a "__imp_" prefix added. The string with the prefix can be
//! constructed using a long-living arena allocator which allows it to be
//! available later on in the program.
//!
//! Most arena allocator implementations do not allow allocation in a thread-safe
//! manner. This is handled by using a thread-safe [Object pool](https://en.wikipedia.org/wiki/Object_pool_pattern)
//! of arena allocators. A thread that needs a long-living arena can acquire a
//! reference to one in a thread-safe manner from the pool and release it when
//! it is no longer needed. The perk here is that a thread can freely allocate
//! memory without worrying about synchronization but the cost is that acquiring
//! and releasing an arena from the pool requires briefly locking a mutex. Threads
//! should only acquire an arena when needed and keep it active until the end of
//! its runtime.

use std::{ffi::OsStr, marker::PhantomData, mem::ManuallyDrop, sync::Mutex};

#[repr(transparent)]
pub struct TypedArena<T>(typed_arena::Arena<T>);

impl<T> TypedArena<T> {
    pub fn new() -> Self {
        Self(typed_arena::Arena::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn alloc(&self, value: T) -> &mut T {
        self.0.alloc(value)
    }

    pub fn alloc_extend(&self, iterable: impl IntoIterator<Item = T>) -> &mut [T] {
        self.0.alloc_extend(iterable)
    }

    pub fn into_vec(self) -> Vec<T> {
        self.0.into_vec()
    }
}

impl TypedArena<u8> {
    pub fn alloc_str(&self, s: &str) -> &mut str {
        self.0.alloc_str(s)
    }

    pub fn alloc_bytes(&self, b: &[u8]) -> &mut [u8] {
        self.alloc_extend(b.into_iter().copied())
    }

    pub fn alloc_os_str(&self, s: &OsStr) -> InvariantRef<'_, OsStr> {
        let b = self.alloc_bytes(s.as_encoded_bytes());
        let allocd = unsafe { OsStr::from_encoded_bytes_unchecked(b) };
        InvariantRef {
            inner: allocd,
            invariant: PhantomData,
        }
    }
}

impl<T> std::default::Default for TypedArena<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

#[repr(transparent)]
pub struct InvariantRef<'a, T: ?Sized> {
    inner: &'a T,
    invariant: PhantomData<&'a mut T>,
}

impl<'a, T: ?Sized> std::ops::Deref for InvariantRef<'a, T> {
    type Target = &'a T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Object pool of arena allocators which allows concurrently acquiring and
/// releasing exclusive references to an arena.
///
/// # Note
/// Acquiring and releasing an arena requires locking a mutex.
#[allow(
    clippy::vec_box,
    reason = "reduces critical section time by limiting the size of each element copied out during acquire/release operations to only the size of a pointer"
)]
pub struct ArenaPool<T>(Mutex<Vec<Box<TypedArena<T>>>>);

impl<T> Default for ArenaPool<T> {
    fn default() -> Self {
        Self(Mutex::new(Vec::new()))
    }
}

impl<T> ArenaPool<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_initial(count: usize) -> Self {
        Self(Mutex::new(
            (0..count).map(|_| Box::new(TypedArena::new())).collect(),
        ))
    }

    pub fn get(&self) -> ArenaHandle<'_, T> {
        ArenaHandle {
            inner: ManuallyDrop::new(
                self.0
                    .lock()
                    .expect("ArenaPool Mutex poisoned")
                    .pop()
                    .unwrap_or_default(),
            ),
            pool: self,
        }
    }
}

pub struct ArenaHandle<'a, T> {
    inner: ManuallyDrop<Box<TypedArena<T>>>,
    pool: &'a ArenaPool<T>,
}

impl<'a, T> ArenaHandle<'a, T> {
    pub fn alloc(&self, value: T) -> &'a mut T {
        let allocated = self.inner.alloc(value) as *mut _;
        unsafe { &mut *allocated }
    }

    pub fn alloc_ref(&self, value: T) -> ArenaRef<'a, T> {
        let allocated = self.inner.alloc(value) as *mut _;
        unsafe { ArenaRef(&mut *allocated) }
    }

    pub fn alloc_extend<I>(&self, iterator: I) -> &'a mut [T]
    where
        I: IntoIterator<Item = T>,
    {
        let allocated = self.inner.alloc_extend(iterator) as *mut _;
        unsafe { &mut *allocated }
    }

    pub fn as_arena(&self) -> &TypedArena<T> {
        &self.inner
    }
}

impl<'a> ArenaHandle<'a, u8> {
    pub fn alloc_str(&self, s: &str) -> &'a mut str {
        let allocated = self.inner.alloc_str(s) as *mut _;
        unsafe { &mut *allocated }
    }

    pub fn alloc_bytes(&self, b: &[u8]) -> &'a mut [u8] {
        self.alloc_extend(b.into_iter().copied())
    }

    pub fn alloc_os_str(&self, s: &OsStr) -> InvariantRef<'a, OsStr> {
        let b = self.alloc_bytes(s.as_encoded_bytes()) as *mut _;
        InvariantRef {
            inner: unsafe { OsStr::from_encoded_bytes_unchecked(&mut *b) },
            invariant: PhantomData,
        }
    }
}

impl<T> Drop for ArenaHandle<'_, T> {
    fn drop(&mut self) {
        let mut pool = self.pool.0.lock().expect("ArenaPool Mutex poisoned");
        pool.push(unsafe { ManuallyDrop::take(&mut self.inner) });
    }
}

#[repr(transparent)]
pub struct ArenaRef<'a, T: ?Sized>(&'a mut T);

impl<'a, T> ArenaRef<'a, T> {
    pub fn new_in(value: T, arena: &'a TypedArena<T>) -> ArenaRef<'a, T> {
        Self(arena.alloc(value))
    }
}

impl<'a, T: ?Sized> std::ops::Deref for ArenaRef<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<'a, T: ?Sized> std::ops::DerefMut for ArenaRef<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl<'a, T: ?Sized + std::fmt::Debug> std::fmt::Debug for ArenaRef<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&*self.0, f)
    }
}

impl<'a, T: ?Sized + std::fmt::Display> std::fmt::Display for ArenaRef<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&*self.0, f)
    }
}
