/// Bitset which has a fixed domain size specified on creation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FixedBitSet {
    domain: usize,
    entries: Vec<u64>,
}

impl FixedBitSet {
    /// Creates a new [`FixedBitSet`] with the specified domain size.
    ///
    /// This is the number of bits that the bitset can hold.
    pub fn new_empty(domain: usize) -> Self {
        Self {
            domain,
            entries: vec![0u64; domain.div_ceil(u64::BITS as usize)],
        }
    }

    /// Sets the bit at the specified index and returns `true` if the bit was
    /// newly set.
    ///
    /// # Panics
    /// Panics if the index of the bit exceeds the bitset domain.
    pub fn insert(&mut self, bit: usize) -> bool {
        assert!(bit < self.domain);
        let (i, mask) = location(bit);
        let entry = &mut self.entries[i];
        let value = *entry;
        let new_value = value | mask;
        *entry = new_value;
        new_value != value
    }
}

fn location(bit: usize) -> (usize, u64) {
    let entry = bit / u64::BITS as usize;
    let mask = 1u64 << (entry % u64::BITS as usize);
    (entry, mask)
}
