use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelIterator,
    },
    slice::{ParallelSlice, ParallelSliceMut},
};

use crate::{Idx, IndexSlice};

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
    pub fn par_iter_enumerated(&self) -> impl ParallelIterator<Item = (I, &T)> {
        let _ = I::from_usize(self.len());
        self.raw
            .par_iter()
            .enumerate()
            .map(|(i, t)| (I::from_usize(i), t))
    }

    #[inline]
    pub fn par_iter_enumerated_mut(&mut self) -> impl ParallelIterator<Item = (I, &mut T)> {
        let _ = I::from_usize(self.len());
        self.raw
            .par_iter_mut()
            .enumerate()
            .map(|(i, t)| (I::from_usize(i), t))
    }
}
