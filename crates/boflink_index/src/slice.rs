use std::{fmt, marker::PhantomData, slice::SliceIndex};

use crate::{Idx, IndexVec, IntoSliceIdx};

pub type Iter<'a, T> = std::slice::Iter<'a, T>;
pub type IterMut<'a, T> = std::slice::IterMut<'a, T>;

#[derive(PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct IndexSlice<I: Idx, T> {
    _marker: PhantomData<fn(&I)>,
    pub raw: [T],
}

impl<I: Idx, T> IndexSlice<I, T> {
    #[inline]
    pub const fn empty<'a>() -> &'a Self {
        Self::from_raw(&[])
    }

    #[inline]
    pub const fn from_raw(raw: &[T]) -> &Self {
        let ptr = raw as *const [T];
        // SAFETY: Self is `repr(transparent)` over a `[T]`
        unsafe { &*(ptr as *const Self) }
    }

    #[inline]
    pub fn from_raw_mut(raw: &mut [T]) -> &mut Self {
        let ptr = raw as *mut [T];
        // SAFETY: Self is `repr(transparent)` over a `[T]`
        unsafe { &mut *(ptr as *mut Self) }
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.raw.len()
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    #[inline]
    pub fn next_index(&self) -> I {
        I::from_usize(self.len())
    }

    #[inline]
    pub fn iter(&self) -> Iter<'_, T> {
        self.raw.iter()
    }

    #[inline]
    pub fn iter_enumerated(&self) -> impl DoubleEndedIterator<Item = (I, &T)> + ExactSizeIterator {
        // Optimize out bounds checks when calling `I::from_usize` in `.map()`
        let _ = I::from_usize(self.len());
        self.raw
            .iter()
            .enumerate()
            .map(|(i, t)| (I::from_usize(i), t))
    }

    #[inline]
    pub fn indicies(
        &self,
    ) -> impl DoubleEndedIterator<Item = I> + ExactSizeIterator + Clone + 'static {
        // Optimize out bounds checks when calling `I::from_usize` in `.map()`
        let _ = I::from_usize(self.len());
        (0..self.len()).map(I::from_usize)
    }

    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        self.raw.iter_mut()
    }

    #[inline]
    pub fn iter_enumerated_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = (I, &mut T)> + ExactSizeIterator {
        // Optimize out bounds checks when calling `I::from_usize` in `.map()`
        let _ = I::from_usize(self.len());
        self.raw
            .iter_mut()
            .enumerate()
            .map(|(i, t)| (I::from_usize(i), t))
    }

    #[inline]
    pub fn last_index(&self) -> Option<I> {
        self.len().checked_sub(1).map(I::from_usize)
    }

    #[inline]
    pub fn swap(&mut self, a: I, b: I) {
        self.raw.swap(a.index(), b.index());
    }

    #[inline]
    pub fn get<R: IntoSliceIdx<I, [T]>>(
        &self,
        index: R,
    ) -> Option<&<R::Output as SliceIndex<[T]>>::Output> {
        self.raw.get(index.into_slice_idx())
    }

    #[inline]
    pub fn get_mut<R: IntoSliceIdx<I, [T]>>(
        &mut self,
        index: R,
    ) -> Option<&mut <R::Output as SliceIndex<[T]>>::Output> {
        self.raw.get_mut(index.into_slice_idx())
    }

    #[inline]
    pub fn binary_search(&self, value: &T) -> Result<I, I>
    where
        T: Ord,
    {
        match self.raw.binary_search(value) {
            Ok(i) => Ok(Idx::from_usize(i)),
            Err(i) => Err(Idx::from_usize(i)),
        }
    }
}

impl<I: Idx, T: fmt::Debug> fmt::Debug for IndexSlice<I, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.raw, f)
    }
}

impl<I: Idx, T, R: IntoSliceIdx<I, [T]>> std::ops::Index<R> for IndexSlice<I, T> {
    type Output = <R::Output as SliceIndex<[T]>>::Output;

    #[inline]
    fn index(&self, index: R) -> &Self::Output {
        &self.raw[index.into_slice_idx()]
    }
}

impl<I: Idx, T, R: IntoSliceIdx<I, [T]>> std::ops::IndexMut<R> for IndexSlice<I, T> {
    #[inline]
    fn index_mut(&mut self, index: R) -> &mut Self::Output {
        &mut self.raw[index.into_slice_idx()]
    }
}

impl<'a, I: Idx, T> IntoIterator for &'a IndexSlice<I, T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.raw.iter()
    }
}

impl<'a, I: Idx, T> IntoIterator for &'a mut IndexSlice<I, T> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.raw.iter_mut()
    }
}

impl<I: Idx, T: Clone> ToOwned for IndexSlice<I, T> {
    type Owned = IndexVec<I, T>;
    fn to_owned(&self) -> Self::Owned {
        IndexVec::from_raw(self.raw.to_owned())
    }

    fn clone_into(&self, target: &mut Self::Owned) {
        self.raw.clone_into(&mut target.raw);
    }
}

impl<I: Idx, T> Default for &IndexSlice<I, T> {
    #[inline]
    fn default() -> Self {
        IndexSlice::from_raw(Default::default())
    }
}

impl<I: Idx, T> Default for &mut IndexSlice<I, T> {
    #[inline]
    fn default() -> Self {
        IndexSlice::from_raw_mut(Default::default())
    }
}

unsafe impl<I: Idx, T> Send for IndexSlice<I, T> where T: Send {}
