use std::{fmt::Debug, hash::Hash, ops, slice::SliceIndex};

pub trait Idx: Copy + Eq + PartialEq + Debug + Hash + 'static {
    fn from_usize(idx: usize) -> Self;
    fn index(self) -> usize;
}

impl Idx for usize {
    #[inline]
    fn from_usize(idx: usize) -> Self {
        idx
    }

    #[inline]
    fn index(self) -> usize {
        self
    }
}

impl Idx for u32 {
    #[inline]
    fn from_usize(idx: usize) -> Self {
        assert!(idx <= u32::MAX as usize);
        idx as u32
    }

    #[inline]
    fn index(self) -> usize {
        self as usize
    }
}

pub trait IntoSliceIdx<I, T: ?Sized> {
    type Output: SliceIndex<T>;
    fn into_slice_idx(self) -> Self::Output;
}

impl<I: Idx, T> IntoSliceIdx<I, [T]> for I {
    type Output = usize;
    #[inline]
    fn into_slice_idx(self) -> Self::Output {
        self.index()
    }
}

impl<I, T> IntoSliceIdx<I, [T]> for ops::RangeFull {
    type Output = ops::RangeFull;
    #[inline]
    fn into_slice_idx(self) -> Self::Output {
        self
    }
}

impl<I: Idx, T> IntoSliceIdx<I, [T]> for ops::Range<I> {
    type Output = ops::Range<usize>;
    #[inline]
    fn into_slice_idx(self) -> Self::Output {
        ops::Range {
            start: self.start.index(),
            end: self.end.index(),
        }
    }
}

impl<I: Idx, T> IntoSliceIdx<I, [T]> for ops::RangeFrom<I> {
    type Output = ops::RangeFrom<usize>;
    #[inline]
    fn into_slice_idx(self) -> Self::Output {
        ops::RangeFrom {
            start: self.start.index(),
        }
    }
}

impl<I: Idx, T> IntoSliceIdx<I, [T]> for ops::RangeTo<I> {
    type Output = ops::RangeTo<usize>;
    #[inline]
    fn into_slice_idx(self) -> Self::Output {
        ..self.end.index()
    }
}

impl<I: Idx, T> IntoSliceIdx<I, [T]> for ops::RangeInclusive<I> {
    type Output = ops::RangeInclusive<usize>;
    #[inline]
    fn into_slice_idx(self) -> Self::Output {
        ops::RangeInclusive::new(self.start().index(), self.end().index())
    }
}

impl<I: Idx, T> IntoSliceIdx<I, [T]> for ops::RangeToInclusive<I> {
    type Output = ops::RangeToInclusive<usize>;
    #[inline]
    fn into_slice_idx(self) -> Self::Output {
        ..=self.end.index()
    }
}
