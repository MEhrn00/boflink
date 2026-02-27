use super::TypedArena;

#[repr(transparent)]
pub struct TypedArenaRef<'a, T: ?Sized>(pub(super) &'a mut T);

impl<'a, T> TypedArenaRef<'a, T> {
    #[inline]
    pub fn new_in(value: T, arena: &'a TypedArena<T>) -> TypedArenaRef<'a, T> {
        Self(arena.alloc(value))
    }
}

impl<'a, T: ?Sized> TypedArenaRef<'a, T> {
    #[inline]
    pub fn into_inner(this: TypedArenaRef<'a, T>) -> &'a mut T {
        this.0
    }
}
