use std::{
    borrow::{Borrow, BorrowMut},
    fmt::Debug,
    marker::PhantomData,
    ops::RangeBounds,
};

use crate::{Idx, IndexSlice, slice};

pub type IntoIter<T> = std::vec::IntoIter<T>;

#[derive(Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct IndexVec<I: Idx, T> {
    pub raw: Vec<T>,
    _marker: PhantomData<fn(&I)>,
}

impl<I: Idx, T> IndexVec<I, T> {
    #[inline]
    pub const fn new() -> Self {
        Self::from_raw(Vec::new())
    }

    #[inline]
    pub const fn from_raw(raw: Vec<T>) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::from_raw(Vec::with_capacity(capacity))
    }

    #[inline]
    pub fn from_elem<S>(elem: T, universe: &IndexSlice<I, S>) -> Self
    where
        T: Clone,
    {
        Self::from_raw(vec![elem; universe.len()])
    }

    #[inline]
    pub fn from_elem_n(elem: T, n: usize) -> Self
    where
        T: Clone,
    {
        Self::from_raw(vec![elem; n])
    }

    #[inline]
    pub fn from_fn_n(f: impl FnMut(I) -> T, n: usize) -> Self {
        let _ = I::from_usize(n);
        Self::from_raw((0..n).map(I::from_usize).map(f).collect())
    }

    #[inline]
    pub fn as_slice(&self) -> &IndexSlice<I, T> {
        IndexSlice::from_raw(&self.raw)
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut IndexSlice<I, T> {
        IndexSlice::from_raw_mut(&mut self.raw)
    }

    #[inline]
    pub fn push(&mut self, val: T) -> I {
        let idx = self.next_index();
        self.raw.push(val);
        idx
    }

    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        self.raw.pop()
    }

    #[inline]
    pub fn into_iter_enumerated(
        self,
    ) -> impl DoubleEndedIterator<Item = (I, T)> + ExactSizeIterator {
        let _ = I::from_usize(self.len());
        self.raw
            .into_iter()
            .enumerate()
            .map(|(i, t)| (I::from_usize(i), t))
    }

    #[inline]
    pub fn drain<R: RangeBounds<usize>>(&mut self, range: R) -> impl Iterator<Item = T> {
        self.raw.drain(range)
    }

    #[inline]
    pub fn drain_enumerated<R: RangeBounds<usize>>(
        &mut self,
        range: R,
    ) -> impl Iterator<Item = (I, T)> {
        let begin = match range.start_bound() {
            std::ops::Bound::Included(i) => *i,
            std::ops::Bound::Excluded(i) => i.checked_add(1).unwrap(),
            std::ops::Bound::Unbounded => 0,
        };
        self.raw
            .drain(range)
            .enumerate()
            .map(move |(i, t)| (I::from_usize(begin + i), t))
    }

    #[inline]
    pub fn shrink_to_fit(&mut self) {
        self.raw.shrink_to_fit();
    }

    #[inline]
    pub fn truncate(&mut self, len: usize) {
        self.raw.truncate(len);
    }

    #[inline]
    pub fn ensure_contains_elem(&mut self, elem: I, fill_with: impl FnMut() -> T) -> &mut T {
        let min_new_len = elem.index() + 1;
        if self.len() < min_new_len {
            self.raw.resize_with(min_new_len, fill_with);
        }
        &mut self[elem]
    }

    #[inline]
    pub fn resize(&mut self, new_len: usize, value: T)
    where
        T: Clone,
    {
        self.raw.resize(new_len, value)
    }

    #[inline]
    pub fn resize_to_elem(&mut self, elem: I, fill_with: impl FnMut() -> T) {
        let min_new_len = elem.index() + 1;
        self.raw.resize_with(min_new_len, fill_with);
    }

    #[inline]
    pub fn append(&mut self, other: &mut Self) {
        self.raw.append(&mut other.raw);
    }
}

impl<I: Idx, T> IndexVec<I, Option<T>> {
    #[inline]
    pub fn insert(&mut self, index: I, value: T) -> Option<T> {
        self.ensure_contains_elem(index, || None).replace(value)
    }

    #[inline]
    pub fn get_or_insert_with(&mut self, index: I, value: impl FnOnce() -> T) -> &mut T {
        self.ensure_contains_elem(index, || None)
            .get_or_insert_with(value)
    }

    #[inline]
    pub fn get_or_insert_default(&mut self, index: I) -> &mut T
    where
        T: std::default::Default,
    {
        self.get_or_insert_with(index, T::default)
    }

    #[inline]
    pub fn remove(&mut self, index: I) -> Option<T> {
        self.get_mut(index)?.take()
    }

    #[inline]
    pub fn contains(&self, index: I) -> bool {
        self.get(index).and_then(Option::as_ref).is_some()
    }
}

impl<I: Idx, T> std::ops::Deref for IndexVec<I, T> {
    type Target = IndexSlice<I, T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<I: Idx, T> std::ops::DerefMut for IndexVec<I, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<I: Idx, T> Borrow<IndexSlice<I, T>> for IndexVec<I, T> {
    fn borrow(&self) -> &IndexSlice<I, T> {
        self
    }
}

impl<I: Idx, T> BorrowMut<IndexSlice<I, T>> for IndexVec<I, T> {
    fn borrow_mut(&mut self) -> &mut IndexSlice<I, T> {
        self
    }
}

impl<I: Idx, T> Extend<T> for IndexVec<I, T> {
    #[inline]
    fn extend<II: IntoIterator<Item = T>>(&mut self, iter: II) {
        self.raw.extend(iter);
    }
}

impl<I: Idx, T> FromIterator<T> for IndexVec<I, T> {
    #[inline]
    fn from_iter<II: IntoIterator<Item = T>>(iter: II) -> Self {
        IndexVec::from_raw(Vec::from_iter(iter))
    }
}

impl<I: Idx, T> IntoIterator for IndexVec<I, T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.raw.into_iter()
    }
}

impl<'a, I: Idx, T> IntoIterator for &'a IndexVec<I, T> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, I: Idx, T> IntoIterator for &'a mut IndexVec<I, T> {
    type Item = &'a mut T;
    type IntoIter = slice::IterMut<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<I: Idx, T> Default for IndexVec<I, T> {
    #[inline]
    fn default() -> Self {
        IndexVec::new()
    }
}

impl<I: Idx, T: Debug> Debug for IndexVec<I, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexVec")
            .field("raw", &self.raw)
            .field("_marker", &self._marker)
            .finish()
    }
}

impl<I: Idx, T, const N: usize> From<[T; N]> for IndexVec<I, T> {
    #[inline]
    fn from(value: [T; N]) -> Self {
        IndexVec::from_raw(value.into())
    }
}

unsafe impl<I: Idx, T> Send for IndexVec<I, T> where T: Send {}
