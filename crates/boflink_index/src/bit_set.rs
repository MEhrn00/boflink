use std::{
    marker::PhantomData,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::Idx;

/// Bit set represented as dense `u64` values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DenseBitSet<T> {
    domain: usize,
    entries: Vec<u64>,
    _marker: PhantomData<T>,
}

impl<T> DenseBitSet<T> {
    #[inline]
    pub fn domain_size(&self) -> usize {
        self.domain
    }
}

impl<T: Idx> DenseBitSet<T> {
    /// Creates a new [`DenseBitSet`] with the specified domain size.
    ///
    /// This is the number of bits that the bitset can hold.
    #[inline]
    pub fn new_empty(domain: usize) -> Self {
        Self::from_parts(domain, vec![0u64; num_entries(domain)])
    }

    #[inline]
    pub fn new_filled(domain: usize) -> Self {
        let mut this = Self::from_parts(domain, vec![!0; num_entries(domain)]);
        this.clear_excess_bits();
        this
    }

    #[inline]
    pub fn clear(&mut self) {
        self.entries.fill(0);
    }

    /// Returns the number of set bits.
    #[inline]
    pub fn count(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| entry.count_ones() as usize)
            .sum()
    }

    /// Returns `true` if the bitset contains `item`
    ///
    /// # Panics
    /// This panics if [`Idx::index()`] is exceeds the bitset domain.
    #[inline]
    #[must_use]
    pub fn contains(&self, item: T) -> bool {
        assert!(item.index() < self.domain);
        let (i, mask) = entry_location(item);
        (self.entries[i] & mask) != 0
    }

    /// Sets the bit at the specified index and returns `true` if the bit was
    /// newly set.
    ///
    /// # Panics
    /// Panics if the index of the bit exceeds the bitset domain.
    #[inline]
    pub fn insert(&mut self, item: T) -> bool {
        assert!(item.index() < self.domain);
        let (i, mask) = entry_location(item);
        let entry = &mut self.entries[i];
        let value = *entry;
        let new_value = value | mask;
        *entry = new_value;
        new_value != value
    }

    fn clear_excess_bits(&mut self) {
        let rem = self.domain % u64::BITS as usize;
        if rem > 0 {
            let mask = (1u64 << rem) - 1;
            let entries = self.entries.as_mut_slice();
            entries[entries.len() - 1] &= mask;
        }
    }

    fn from_parts(domain: usize, entries: Vec<u64>) -> Self {
        Self {
            domain,
            entries,
            _marker: PhantomData,
        }
    }
}

impl<T> From<AtomicDenseBitSet<T>> for DenseBitSet<T> {
    #[inline]
    fn from(value: AtomicDenseBitSet<T>) -> Self {
        Self {
            domain: value.domain,
            entries: value
                .entries
                .into_iter()
                .map(|entry| entry.into_inner())
                .collect(),
            _marker: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct AtomicDenseBitSet<T> {
    domain: usize,
    entries: Vec<AtomicU64>,
    _marker: PhantomData<T>,
}

impl<T> AtomicDenseBitSet<T> {
    #[inline]
    pub fn domain_size(&self) -> usize {
        self.domain
    }
}

impl<T: Idx> AtomicDenseBitSet<T> {
    #[inline]
    pub fn new_empty(domain: usize) -> Self {
        DenseBitSet::new_empty(domain).into()
    }

    #[inline]
    pub fn new_filled(domain: usize) -> Self {
        DenseBitSet::new_filled(domain).into()
    }

    #[inline]
    pub fn insert(&self, item: T, order: Ordering) -> bool {
        assert!(item.index() < self.domain);
        let (i, mask) = entry_location(item);
        let entry = &self.entries[i];
        entry.fetch_or(mask, order) & mask == 0
    }

    #[inline]
    #[must_use]
    pub fn contains(&self, item: T, order: Ordering) -> bool {
        assert!(item.index() < self.domain);
        let (i, mask) = entry_location(item);
        self.entries[i].load(order) & mask != 0
    }
}

impl<T> From<DenseBitSet<T>> for AtomicDenseBitSet<T> {
    #[inline]
    fn from(value: DenseBitSet<T>) -> Self {
        Self {
            domain: value.domain,
            entries: value.entries.into_iter().map(AtomicU64::new).collect(),
            _marker: PhantomData,
        }
    }
}

#[inline]
fn entry_location<T: Idx>(item: T) -> (usize, u64) {
    let index = item.index();
    let entry = index / u64::BITS as usize;
    let mask = 1u64 << (index % u64::BITS as usize);
    (entry, mask)
}

#[inline]
const fn num_entries(domain: usize) -> usize {
    domain.div_ceil(u64::BITS as usize)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::AtomicDenseBitSet;

    #[test]
    fn atomic_insert_contains() {
        let id = 0;

        let bset = AtomicDenseBitSet::<u32>::new_empty(1);
        bset.insert(id, Ordering::Relaxed);
        let ret = bset.contains(id, Ordering::Relaxed);
        assert!(ret);
    }

    #[test]
    fn atomic_new_insert() {
        let id = 0;

        let bset = AtomicDenseBitSet::<u32>::new_empty(1);
        let ret = bset.insert(id, Ordering::Relaxed);
        assert!(ret);
    }

    #[test]
    fn atomic_double_insert() {
        let id = 0;

        let bset = AtomicDenseBitSet::<u32>::new_empty(1);
        let ret = bset.insert(id, Ordering::Relaxed);
        assert!(ret);
        let ret = bset.insert(id, Ordering::Relaxed);
        assert!(!ret);
    }

    #[test]
    fn atomic_adjacent_insert() {
        let id1 = 0;
        let id2 = 4;

        let bset = AtomicDenseBitSet::<u32>::new_empty(5);
        bset.insert(id1, Ordering::Relaxed);
        assert!(bset.contains(id1, Ordering::Relaxed));
        assert!(!bset.contains(id2, Ordering::Relaxed));
    }

    #[test]
    fn atomic_adjacent_new_insert() {
        let id1 = 0;
        let id2 = 4;

        let bset = AtomicDenseBitSet::<u32>::new_empty(5);
        let ret = bset.insert(id1, Ordering::Relaxed);
        assert!(ret);
        let ret = bset.insert(id2, Ordering::Relaxed);
        assert!(ret);
    }

    #[test]
    fn atomic_adjacent_double_insert() {
        let id1 = 0;
        let id2 = 4;

        let bset = AtomicDenseBitSet::<u32>::new_empty(5);
        let ret = bset.insert(id1, Ordering::Relaxed);
        assert!(ret);
        let ret = bset.insert(id2, Ordering::Relaxed);
        assert!(ret);

        let ret = bset.insert(id1, Ordering::Relaxed);
        assert!(!ret);

        let ret = bset.insert(id2, Ordering::Relaxed);
        assert!(!ret);
    }
}
