pub mod bit_set;
mod idx;
pub mod slice;
pub mod vec;

#[cfg(feature = "rayon")]
mod rayon;

pub use idx::{Idx, IntoSliceIdx};
pub use slice::IndexSlice;
pub use vec::IndexVec;

#[macro_export]
macro_rules! indexvec {
    ($expr:expr; $n:expr) => {
        IndexVec::from_raw(vec![$expr; $n])
    };
    ($($expr:expr),* $(,)?) => {
        IndexVec::from_raw(vec![$($expr),*])
    };
}
