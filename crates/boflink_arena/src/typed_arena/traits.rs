use super::TypedArenaRef;

impl<'a, T: ?Sized> AsMut<T> for TypedArenaRef<'a, T> {
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        &mut *self
    }
}

impl<'a, T: ?Sized> AsRef<T> for TypedArenaRef<'a, T> {
    #[inline]
    fn as_ref(&self) -> &T {
        self
    }
}

impl<'a, T: ?Sized> std::borrow::Borrow<T> for TypedArenaRef<'a, T> {
    #[inline]
    fn borrow(&self) -> &T {
        self
    }
}

impl<'a, T: ?Sized> std::borrow::BorrowMut<T> for TypedArenaRef<'a, T> {
    #[inline]
    fn borrow_mut(&mut self) -> &mut T {
        &mut *self
    }
}

impl<'a, T: ?Sized> std::ops::Deref for TypedArenaRef<'a, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<'a, T: ?Sized> std::ops::DerefMut for TypedArenaRef<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl<'a, T: ?Sized + std::fmt::Debug> std::fmt::Debug for TypedArenaRef<'a, T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&*self.0, f)
    }
}

impl<'a, T: ?Sized + std::fmt::Display> std::fmt::Display for TypedArenaRef<'a, T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&*self.0, f)
    }
}
