use rayon::{
    iter::{
        FromParallelIterator, IndexedParallelIterator, IntoParallelIterator,
        IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
    },
    slice::{ParallelSlice, ParallelSliceMut},
};

use crate::{Idx, IndexSlice, IndexVec};

impl<I: Idx, T: Sync> ParallelSlice<T> for &IndexSlice<I, T> {
    fn as_parallel_slice(&self) -> &[T] {
        &self.raw
    }
}

impl<I: Idx, T: Send> ParallelSliceMut<T> for &mut IndexSlice<I, T> {
    fn as_parallel_slice_mut(&mut self) -> &mut [T] {
        &mut self.raw
    }
}

impl<I: Idx, T> IndexSlice<I, T>
where
    I: Send,
    T: Send,
{
    #[inline]
    pub fn par_indicies(&self) -> impl ParallelIterator<Item = I> {
        let _ = I::from_usize(self.len());
        (0..self.len()).into_par_iter().map(I::from_usize)
    }
}

impl<I: Idx, T> IndexSlice<I, T>
where
    I: Send,
    T: Send + Sync,
{
    #[inline]
    pub fn par_iter_enumerated(&self) -> impl IndexedParallelIterator<Item = (I, &T)> {
        let _ = I::from_usize(self.len());
        self.raw
            .par_iter()
            .enumerate()
            .map(|(i, t)| (I::from_usize(i), t))
    }

    #[inline]
    pub fn par_iter_enumerated_mut(&mut self) -> impl IndexedParallelIterator<Item = (I, &mut T)> {
        let _ = I::from_usize(self.len());
        self.raw
            .par_iter_mut()
            .enumerate()
            .map(|(i, t)| (I::from_usize(i), t))
    }
}

impl<I: Idx, T> IndexVec<I, T>
where
    I: Send,
    T: Send,
{
    #[inline]
    pub fn into_par_iter_enumerated(self) -> impl IndexedParallelIterator<Item = (I, T)> {
        let _ = I::from_usize(self.len());
        self.raw
            .into_par_iter()
            .enumerate()
            .map(|(i, t)| (I::from_usize(i), t))
    }
}

impl<'data, I: Idx, T> IntoParallelIterator for &'data IndexVec<I, T>
where
    T: Sync + 'data,
{
    type Iter = rayon::slice::Iter<'data, T>;
    type Item = &'data T;

    #[inline]
    fn into_par_iter(self) -> Self::Iter {
        <&[T]>::into_par_iter(&self.raw)
    }
}

impl<'data, I: Idx, T> IntoParallelIterator for &'data mut IndexVec<I, T>
where
    T: Send + 'data,
{
    type Iter = rayon::slice::IterMut<'data, T>;
    type Item = &'data mut T;

    #[inline]
    fn into_par_iter(self) -> Self::Iter {
        <&mut [T]>::into_par_iter(&mut self.raw)
    }
}

impl<I: Idx, T> IntoParallelIterator for IndexVec<I, T>
where
    T: Send,
{
    type Item = T;
    type Iter = rayon::vec::IntoIter<T>;

    #[inline]
    fn into_par_iter(self) -> Self::Iter {
        self.raw.into_par_iter()
    }
}

impl<I: Idx, T> FromParallelIterator<T> for IndexVec<I, T>
where
    T: Send,
{
    #[inline]
    fn from_par_iter<It>(par_iter: It) -> Self
    where
        It: IntoParallelIterator<Item = T>,
    {
        Self::from_raw(Vec::from_par_iter(par_iter))
    }
}
