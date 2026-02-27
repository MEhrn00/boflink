use super::BumpBox;

impl<'a, T: ?Sized> AsMut<T> for BumpBox<'a, T> {
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        &mut *self
    }
}

impl<'a, T: ?Sized> AsRef<T> for BumpBox<'a, T> {
    #[inline]
    fn as_ref(&self) -> &T {
        self
    }
}

impl<'a, T: ?Sized> std::borrow::Borrow<T> for BumpBox<'a, T> {
    #[inline]
    fn borrow(&self) -> &T {
        self
    }
}

impl<'a, T: ?Sized> std::borrow::BorrowMut<T> for BumpBox<'a, T> {
    #[inline]
    fn borrow_mut(&mut self) -> &mut T {
        &mut *self
    }
}

impl<'a, T: ?Sized> std::ops::Deref for BumpBox<'a, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref() }
    }
}

impl<'a, T: ?Sized> std::ops::DerefMut for BumpBox<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut() }
    }
}

impl<'a, T: ?Sized + std::fmt::Debug> std::fmt::Debug for BumpBox<'a, T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

impl<'a, T: ?Sized + std::fmt::Display> std::fmt::Display for BumpBox<'a, T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&**self, f)
    }
}
