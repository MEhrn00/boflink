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
    inputs::ObjectFileId,
    syncpool::{BumpBox, BumpRef},
};

const SLOT_BITS: u32 = 8;
const SLOT_SHIFT: u32 = 32 - SLOT_BITS;
const MAX_SLOTS: usize = 2usize.pow(SLOT_BITS as u32) - 1;

const MAX_INDEX: usize = !((MAX_SLOTS << SLOT_SHIFT) as u32) as usize;
const INDEX_MASK: u32 = MAX_INDEX as u32;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SymbolId(u32);

impl std::fmt::Debug for SymbolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolId")
            .field("slot", &self.slot())
            .field("index", &self.index())
            .finish()
    }
}

impl std::default::Default for SymbolId {
    fn default() -> Self {
        Self::invalid()
    }
}

impl SymbolId {
    pub const fn invalid() -> Self {
        Self(u32::MAX)
    }

    pub const fn is_invalid(&self) -> bool {
        self.0 == SymbolId::invalid().0
    }

    fn new(slot: usize, idx: usize) -> Self {
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
}

type MapEntry<'a> = BumpBox<'a, Symbol<'a>>;
type MapSlot<'a> = IndexMap<&'a [u8], RwLock<MapEntry<'a>>>;

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
        self.slots
            .iter()
            .fold(0, |acc, slot| acc + slot.read().unwrap().len())
    }

    pub fn get_or_default(&self, arena: &BumpRef<'a>, name: &'a [u8]) -> SymbolId {
        let mut h = DefaultHasher::default();
        h.write(name);
        let slot_idx = (h.finish() as usize % self.slots.len()) as usize;
        let slot_entry = &self.slots[slot_idx];
        let index = {
            let mut slot = slot_entry.write().expect("SymbolMap poisoned");
            let entry = slot.entry(name);
            let index = entry.index();
            entry.or_insert_with(|| RwLock::new(arena.alloc_boxed(Symbol::default())));
            index
        };

        assert!(index <= MAX_INDEX, "SymbolMap overflowed");
        SymbolId::new(slot_idx, index)
    }

    pub fn get_exclusive_or_default_new(
        &mut self,
        arena: &BumpRef<'a>,
        name: &'a [u8],
    ) -> Option<SymbolId> {
        let mut h = DefaultHasher::default();
        h.write(name);
        let slot_idx = (h.finish() as usize % self.slots.len()) as usize;

        let slot = self.slots[slot_idx].get_mut().unwrap();
        let index = match slot.entry(name) {
            Entry::Occupied(_) => return None,
            Entry::Vacant(entry) => {
                let entry = entry.insert_entry(RwLock::new(arena.alloc_boxed(Symbol::default())));
                entry.index()
            }
        };

        assert!(index <= MAX_INDEX, "SymbolMap overflowed");
        Some(SymbolId::new(slot_idx, index))
    }

    pub fn get_exclusive(&mut self, symbol: SymbolId) -> Option<&mut BumpBox<'a, Symbol<'a>>> {
        if symbol.is_invalid() {
            return None;
        }

        let slot = self.slots[symbol.slot()].get_mut().unwrap();
        let entry = slot.get_index_mut(symbol.index())?.1;
        Some(entry.get_mut().unwrap())
    }

    pub fn inspect(&self, symbol: SymbolId, f: impl FnOnce(&RwLock<BumpBox<'a, Symbol<'a>>>)) {
        if symbol.is_invalid() {
            return;
        }

        let slot = self.slots[symbol.slot()].read().unwrap();
        if let Some(entry) = slot.get_index(symbol.index()).map(|entry| entry.1) {
            f(entry);
        }
    }

    pub fn par_for_each(&self, f: impl Fn(&RwLock<BumpBox<'a, Symbol<'a>>>) + Send + Sync) {
        self.slots.par_iter().for_each(|slot| {
            let slot = slot.read().unwrap();
            slot.par_values().for_each(|symbol| f(symbol));
        });
    }

    pub fn par_for_each_mut(&mut self, f: impl Fn(&mut Symbol<'a>) + Send + Sync) {
        self.slots.par_iter_mut().for_each(|slot| {
            let slot = slot.get_mut().unwrap();
            slot.par_values_mut()
                .for_each(|symbol| f(symbol.get_mut().unwrap()));
        });
    }
}
