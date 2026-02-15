#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FixedDenseBitSet {
    domain: usize,
    entries: Vec<u64>,
}

impl FixedDenseBitSet {
    pub fn new_empty(domain: usize) -> Self {
        Self {
            domain,
            entries: vec![0u64; domain.div_ceil(u64::BITS as usize)],
        }
    }

    pub fn contains(&self, bit: usize) -> bool {
        assert!(bit < self.domain);
        let (i, mask) = location(bit);
        self.entries[i] & mask != 0
    }

    pub fn insert(&mut self, bit: usize) -> bool {
        assert!(bit < self.domain);
        let (i, mask) = location(bit);
        let entry = &mut self.entries[i];
        let value = *entry;
        let new_value = value | mask;
        *entry = new_value;
        new_value != value
    }

    pub fn set(&mut self, bit: usize, enabled: bool) {
        assert!(bit < self.domain);
        let (i, mask) = location(bit);
        let entry = &mut self.entries[i];
        let mut value = *entry;
        if enabled {
            value |= mask;
        } else {
            value &= !mask;
        }
        *entry = value;
    }

    pub fn toggle(&mut self, bit: usize) {
        assert!(bit < self.domain);
        let (i, mask) = location(bit);
        let entry = &mut self.entries[i];
        let mut value = *entry;
        value ^= mask;
        *entry = value;
    }
}

fn location(bit: usize) -> (usize, u64) {
    let entry = bit / u64::BITS as usize;
    let mask = 1u64 << (entry % u64::BITS as usize);
    (entry, mask)
}
