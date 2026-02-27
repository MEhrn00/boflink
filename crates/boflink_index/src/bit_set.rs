use std::marker::PhantomData;

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

#[inline]
fn entry_location<T: Idx>(item: T) -> (usize, u64) {
    let index = item.index();
    let entry = index / u64::BITS as usize;
    let mask = 1u64 << (entry % u64::BITS as usize);
    (entry, mask)
}

#[inline]
const fn num_entries(domain: usize) -> usize {
    domain.div_ceil(u64::BITS as usize)
}
