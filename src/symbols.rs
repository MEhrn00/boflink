//! Symbol types and global symbol handling.
//!
//! The global symbol map is internally represented as a concurrent [`IndexMap`].
//! The symbol map requires concurrent read/write access and can contain well over
//! 12000 entries in a typical scenario.
//!
//! Since the symbol name strings can potentially be very long with C++/Rust name
//! mangling, the goal here is to use [String interning](https://en.wikipedia.org/wiki/String_interning).
//! A symbol name should only be added into the symbol map once at the beginning
//! of the program and a unique [`ExternalId`] value returned is used for later
//! referencing it. The advantage here is that this id value can be used as a
//! more efficient reference to a symbol inside the map compared to using a
//! hash table with symbol names. Doing a lookup by name in a hash table may
//! cause hash collisions which requires a potentially expensive string comparison.
//! Using an id value to get a symbol does not require handling collisions and
//! is essentially the same has doing a constant-time array index.
//!
//! ## Concurrency
//! The symbol map is internally represented as a collection of slots with each
//! slot containing an [`IndexMap`] wrapped behind a [`RwLock`]. Inserting a
//! string for the first time will get hashed to determine what slot it should
//! be placed in. This should hopefully mean that the number of entries in each
//! indexmap is relatively evenly distributed when the full symbol map is built.
//!
//! This should help reduce lock contention when accessing entries since the
//! RwLock being acquired is "random" when two threads access two separate
//! entries.
//!
//! ## Id tagging
//! The [`ExternalId`] value is a tagged index that internally uses a `u32`.
//! The most-significant 8 bits (1 byte) is used to denote the slot index with
//! the indexmap that contains the entry and the least-significant 24 bits (3 bytes)
//! is the index into the indexmap where the entry lies. An id value of [`u32::MAX`]
//! represents an invalid index or an index for a non-existent entry.
//!
//! The limitation here is that there can only be a maximum of 255 slots in
//! use and each slot can only contain a maximum of 2^24 - 1 entries (16777215)
//! minus 1 for the invalid index [`u32::MAX`].
//! This should be acceptable because in worst case with only 1 slot in use,
//! the symbol map still has enough capacity to hold 16777214 unique symbol
//! names.

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::RwLock,
};

use crossbeam_utils::CachePadded;
use indexmap::{IndexMap, map::Entry};
use object::SymbolIndex;
use rayon::iter::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};

use crate::{
    coff::{ComdatSelection, SectionNumber, StorageClass},
    fatal,
    inputs::ObjectFileId,
};

const SLOT_BITS: u32 = 8;
const SLOT_SHIFT: u32 = u32::BITS - SLOT_BITS;
const MAX_SLOTS: usize = 2usize.pow(SLOT_BITS as u32) - 1;
const MAX_INDEX: usize = !((MAX_SLOTS << SLOT_SHIFT) as u32) as usize;
const INDEX_MASK: u32 = MAX_INDEX as u32;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ExternalId(u32);

impl std::fmt::Debug for ExternalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalId")
            .field("slot", &self.slot())
            .field("index", &self.index())
            .finish()
    }
}

impl std::default::Default for ExternalId {
    fn default() -> Self {
        Self::invalid()
    }
}

impl ExternalId {
    pub const fn invalid() -> Self {
        Self(u32::MAX)
    }

    pub const fn is_invalid(&self) -> bool {
        self.0 == ExternalId::invalid().0
    }

    fn new(slot: usize, idx: usize) -> Self {
        // Debug assert here because an invalid slot index indicates there is
        // a bug in the code since this should never occur from external factors.
        debug_assert!(slot < MAX_SLOTS, "ExternalId slot index >= MAX_SLOTS");

        // Although highly improbable, there is a chance that over 16.7 million
        // unique symbol names were inserted into a single slot which is a fatal
        // error.
        if idx > MAX_INDEX {
            fatal!("symbol map insertion for slot {slot} overflowed max");
        }
        Self(((slot as u32) << SLOT_SHIFT) | idx as u32)
    }

    const fn slot(self) -> usize {
        (self.0 >> SLOT_SHIFT) as usize
    }

    const fn index(self) -> usize {
        (self.0 & INDEX_MASK) as usize
    }
}

#[derive(Debug)]
pub struct Symbol<'a> {
    pub name: &'a [u8],
    pub value: u32,
    pub section: SectionNumber,
    pub storage_class: StorageClass,
    pub typ: u16,
    pub owner: ObjectFileId,
    pub table_index: SymbolIndex,
    pub selection: Option<ComdatSelection>,
}

impl<'a> std::default::Default for Symbol<'a> {
    fn default() -> Self {
        Self {
            name: &[],
            value: 0,
            section: SectionNumber::Undefined,
            typ: 0,
            storage_class: StorageClass::Null,
            owner: ObjectFileId::invalid(),
            table_index: object::SymbolIndex(0),
            selection: None,
        }
    }
}

impl<'a> Symbol<'a> {
    pub fn is_undefined(&self) -> bool {
        self.storage_class == StorageClass::External
            && self.section == SectionNumber::Undefined
            && self.value == 0
    }

    pub fn is_defined(&self) -> bool {
        self.section > SectionNumber::Undefined && self.section < SectionNumber::Debug
    }

    pub fn is_common(&self) -> bool {
        self.storage_class == StorageClass::External
            && self.section == SectionNumber::Undefined
            && self.value != 0
    }

    pub fn is_weak(&self) -> bool {
        self.storage_class == StorageClass::WeakExternal
    }

    pub fn is_comdat_leader(&self) -> bool {
        self.selection.is_some()
    }

    pub fn priority(&self) -> u64 {
        0
    }
}

type MapSlot<'a> = IndexMap<&'a [u8], RwLock<Symbol<'a>>>;

#[derive(Debug)]
pub struct SymbolMap<'a> {
    slots: Box<[CachePadded<RwLock<MapSlot<'a>>>]>,
}

impl<'a> SymbolMap<'a> {
    pub fn with_slot_count(count: usize) -> Self {
        Self {
            slots: (0..count.clamp(1, MAX_SLOTS))
                .map(|_| CachePadded::new(RwLock::new(IndexMap::new())))
                .collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.slots.iter().fold(0, |acc, slot| {
            acc + slot.read().expect("SymbolMap poisoned").len()
        })
    }

    pub fn get_or_default(&self, name: &'a [u8]) -> ExternalId {
        let slot_idx = self.compute_slot(name);
        let slot_entry = &self.slots[slot_idx];
        let index = {
            let mut slot = slot_entry.write().expect("SymbolMap poisoned");
            let entry = slot.entry(name);
            let index = entry.index();
            entry.or_insert_with(|| RwLock::new(Symbol::default()));
            index
        };

        ExternalId::new(slot_idx, index)
    }

    pub fn get_exclusive_or_default_new(&mut self, name: &'a [u8]) -> Option<ExternalId> {
        let slot_idx = self.compute_slot(name);
        let slot = self.slots[slot_idx].get_mut().expect("SymbolMap poisoned");
        let index = match slot.entry(name) {
            Entry::Occupied(_) => return None,
            Entry::Vacant(entry) => {
                let entry = entry.insert_entry(RwLock::new(Symbol::default()));
                entry.index()
            }
        };

        Some(ExternalId::new(slot_idx, index))
    }

    pub fn get_exclusive(&mut self, symbol: ExternalId) -> Option<&mut Symbol<'a>> {
        if symbol.is_invalid() {
            return None;
        }

        let slot = self.slots[symbol.slot()]
            .get_mut()
            .expect("SymbolMap poisoned");
        let entry = slot.get_index_mut(symbol.index())?.1;
        Some(entry.get_mut().expect("SymbolMap entry poisoned"))
    }

    pub fn inspect(&self, symbol: ExternalId, f: impl FnOnce(&RwLock<Symbol<'a>>)) {
        if symbol.is_invalid() {
            return;
        }

        let slot = self.slots[symbol.slot()]
            .read()
            .expect("SymbolMap poisoned");
        if let Some(entry) = slot.get_index(symbol.index()).map(|entry| entry.1) {
            f(entry);
        }
    }

    pub fn par_for_each(&self, f: impl Fn(&RwLock<Symbol<'a>>) + Send + Sync) {
        self.slots.par_iter().for_each(|slot| {
            let slot = slot.read().expect("SymbolMap poisoned");
            slot.par_values().for_each(|symbol| f(symbol));
        });
    }

    pub fn par_for_each_exclusive(&mut self, f: impl Fn(&mut Symbol<'a>) + Send + Sync) {
        self.slots.par_iter_mut().for_each(|slot| {
            let slot = slot.get_mut().expect("SymbolMap poisoned");
            slot.par_values_mut()
                .for_each(|symbol| f(symbol.get_mut().expect("SymbolMap entry poisoned")));
        });
    }

    fn compute_slot(&self, name: &[u8]) -> usize {
        let mut h = DefaultHasher::default();
        h.write(name);
        (h.finish() as usize % self.slots.len()) as usize
    }
}
