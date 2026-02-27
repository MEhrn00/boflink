use std::{
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit},
    ptr::NonNull,
};

use super::Bump;

#[repr(transparent)]
pub struct BumpBox<'a, T: ?Sized> {
    pub(super) ptr: NonNull<T>,
    _marker: PhantomData<&'a T>,
}

impl<'a, T> BumpBox<'a, T> {
    #[inline]
    pub fn new_in(value: T, bump: &'a Bump) -> BumpBox<'a, T> {
        Self {
            ptr: bump.alloc(value).into(),
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn take(this: BumpBox<'a, T>) -> (T, BumpBox<'a, MaybeUninit<T>>) {
        unsafe {
            let ptr = Self::into_non_null(this);
            let val = ptr.read();
            let uninit = BumpBox {
                ptr: ptr.cast(),
                _marker: PhantomData,
            };

            (val, uninit)
        }
    }

    /// Maps `BumpBox<'a, T>` to `BumpBox<'a, U>` reusing the allocated memory.
    #[inline]
    pub fn map<U>(this: BumpBox<'a, T>, f: impl FnOnce(T) -> U) -> BumpBox<'a, U> {
        const {
            assert!(std::mem::size_of::<T>() == std::mem::size_of::<U>());
            assert!(std::mem::align_of::<T>() == std::mem::align_of::<U>());
        }

        let (value, mem) = BumpBox::take(this);
        BumpBox::write(
            unsafe { std::mem::transmute::<BumpBox<MaybeUninit<T>>, BumpBox<MaybeUninit<U>>>(mem) },
            f(value),
        )
    }

    #[inline]
    pub fn into_inner(this: BumpBox<'a, T>) -> T {
        unsafe { std::ptr::read(BumpBox::into_raw(this)) }
    }
}

impl<'a, T: ?Sized> BumpBox<'a, T> {
    /// Constructs a new `BumpBox<'a, T>` from the specified pointer.
    ///
    /// # Safety
    /// Memory must have been allocated by a bump allocator matching the returned
    /// lifetime. Pointer must not be NULL.
    #[inline]
    pub unsafe fn from_raw(raw: *mut T) -> Self {
        BumpBox {
            ptr: unsafe { NonNull::new_unchecked(raw) },
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn into_raw(this: BumpBox<'a, T>) -> *mut T {
        let this = ManuallyDrop::new(this);
        this.ptr.as_ptr()
    }

    #[inline]
    pub fn leak(this: BumpBox<'a, T>) -> &'a mut T {
        unsafe { &mut *BumpBox::into_raw(this) }
    }

    #[inline]
    pub fn into_non_null(this: BumpBox<'a, T>) -> NonNull<T> {
        NonNull::from(Self::leak(this))
    }
}

impl<'a, T> BumpBox<'a, MaybeUninit<T>> {
    #[inline]
    unsafe fn assume_init(self) -> BumpBox<'a, T> {
        let raw = BumpBox::into_raw(self);
        unsafe { BumpBox::from_raw(raw as *mut T) }
    }

    #[inline]
    pub fn write(mut boxed: Self, value: T) -> BumpBox<'a, T> {
        unsafe {
            (*boxed).write(value);
            boxed.assume_init()
        }
    }
}

impl<'a, T: ?Sized> Drop for BumpBox<'a, T> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            std::ptr::drop_in_place(self.ptr.as_ptr());
        }
    }
}

#[cfg(test)]
/* TODO: miri tests */
mod tests {}
