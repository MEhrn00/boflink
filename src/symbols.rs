//! Symbol types and global symbol handling.
//!
//! The global symbol map is internally represented as a concurrent [`IndexMap`].
//! The symbol map requires concurrent read/write access and can contain well over
//! 12000 entries in a typical scenario.
//!
//! Since the symbol name strings can potentially be very long with C++/Rust name
//! mangling, the goal here is to use [String interning](https://en.wikipedia.org/wiki/String_interning).
//! A symbol name should only be added into the symbol map once at the beginning
//! of the program and a unique [`SymbolId`] value returned is used for later
//! referencing it. The advantage here is that this id value can be used as a
//! more efficient reference to a symbol inside the map compared to using a
//! hash table with symbol names. Doing a lookup by name in a hash table may
//! cause hash collisions which requires a potentially expensive string comparison.
//! Using an id value to get a symbol does not require handling collisions and
//! is essentially the same has doing a constant-time array index.
//!
//! # Concurrency
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
//! # ID Tagging
//! The [`SymbolId`] value is a tagged index that internally uses a `u32`.
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
//!
//! # Symbol Types
//! The handling of symbol types in the MS COFF/PE spec is a little peculiar.
//!
//! Firstly, most tools only use the `IMAGE_SYM_TYPE_NULL` and `IMAGE_SYM_DTYPE_FUNCTION`
//! values. This largely leaves the rest of the type values unused.
//!
//! Secondly, the type representation states that the complex and base types are
//! the "most significant byte" and "least significant byte" values in the field.
//! The reality is that these do not refer to the most significant and least
//! significant "bytes" but instead 4 bit nibbles. The complex type is really
//! just the upper 4 bits of the base type. This means that only 6 bits of the
//! entire 2 byte field are actually being used.
//!
//! The Microsoft docs also include a clause stating:
//! "However, other tools can use this field to communicate more information."
//!
//! ...so we're going to exploit this and do exactly that.
//!
//! The most significant byte (upper 8 bits) of the symbol type are used to store
//! additional flags during global symbol resolution. These flags will get reset
//! to the original value in the final COFF. This is done instead of adding an
//! extra field to help keep the size of the symbol structure small.

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::RwLock,
};

use bitflags::bitflags;
use crossbeam_utils::CachePadded;
use indexmap::{IndexMap, map::Entry};
use object::{SymbolIndex, pe::IMAGE_SYM_DTYPE_SHIFT};
use rayon::iter::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};

use crate::{
    arena::ArenaRef,
    coff::{ComdatSelection, SectionNumber, StorageClass},
    fatal,
    inputs::{ObjectFile, ObjectFileId},
};

const SLOT_BITS: u32 = 8;
const SLOT_SHIFT: u32 = u32::BITS - SLOT_BITS;
const MAX_SLOTS: usize = 2usize.pow(SLOT_BITS as u32) - 1;
const MAX_INDEX: usize = !((MAX_SLOTS << SLOT_SHIFT) as u32) as usize;
const INDEX_MASK: u32 = MAX_INDEX as u32;

const GLOBAL_SYMBOL_FLAGS_SHIFT: usize = 8;
const GLOBAL_SYMBOL_FLAGS_MASK: u16 = 0xff00;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SymbolId(u32);

impl std::fmt::Debug for SymbolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalId")
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

    pub const fn is_valid(&self) -> bool {
        !self.is_invalid()
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
    /// Returns `true` if this is a globally scoped symbol.
    pub fn is_global(&self) -> bool {
        self.storage_class == StorageClass::External
            || self.storage_class == StorageClass::WeakExternal
    }

    /// Returns `true` if this is a local symbol.
    pub fn is_local(&self) -> bool {
        !self.is_global()
    }

    /// Returns `true` if this is an undefined global symbol.
    pub fn is_undefined(&self) -> bool {
        self.storage_class == StorageClass::External
            && self.section == SectionNumber::Undefined
            && self.value == 0
    }

    /// Returns `true` if this symbol is defined
    pub fn is_defined(&self) -> bool {
        self.section > SectionNumber::Undefined && self.section < SectionNumber::Debug
    }

    /// Returns `true` if this is a COMMON symbol
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

    /// Returns `true` if this symbol is imported from a DLL
    pub fn is_imported(&self) -> bool {
        self.global_flags().contains(GlobalSymbolFlags::Imported)
    }

    pub fn set_imported(&mut self, value: bool) {
        self.set_global_flag(GlobalSymbolFlags::Imported, value);
    }

    pub fn base_type(&self) -> u16 {
        self.typ & 0xff
    }

    pub fn derived_type(&self) -> u16 {
        // Unset the global symbol flags
        (self.typ & !GLOBAL_SYMBOL_FLAGS_MASK) >> IMAGE_SYM_DTYPE_SHIFT
    }

    fn priority(&self, lazy: bool) -> u64 {
        let mut prio = 7u64;
        if self.is_defined() && !lazy {
            prio = 1;
        } else if self.is_weak() && !lazy {
            prio = 2;
        } else if self.is_defined() {
            prio = 3;
        } else if self.is_weak() {
            prio = 4;
        } else if self.is_common() {
            prio = 5;
            if lazy {
                prio = 6;
            }
        }
        (prio << 31) | self.owner.index() as u64
    }

    /// Returns `true` if `self` should claim `other`.
    pub fn should_claim(
        &self,
        other: &Symbol,
        live: bool,
        objs: &[ArenaRef<'a, ObjectFile<'a>>],
    ) -> bool {
        if other.owner.is_invalid() {
            if self.owner.is_invalid() {
                return false;
            }

            return true;
        }

        self.priority(!live) < other.priority(!objs[self.owner.index()].lazy)
    }

    /// Copies `self` into `other`
    pub fn claim(&self, other: &mut Symbol) {
        other.value = self.value;
        other.section = self.section;
        other.storage_class = self.storage_class;
        other.typ = self.typ;
        other.owner = self.owner;
        other.table_index = self.table_index;
        other.selection = self.selection;
    }

    const fn global_flags(&self) -> GlobalSymbolFlags {
        GlobalSymbolFlags::from_bits_retain(
            ((self.typ & GLOBAL_SYMBOL_FLAGS_MASK) >> GLOBAL_SYMBOL_FLAGS_SHIFT) as u8,
        )
    }

    fn set_global_flag(&mut self, flag: GlobalSymbolFlags, state: bool) {
        let mut flags = self.global_flags();
        flags.set(flag, state);
        self.typ |= (flag.bits() as u16) << GLOBAL_SYMBOL_FLAGS_SHIFT
    }
}

/// Flags used for global symbols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct GlobalSymbolFlags(u8);

bitflags! {
    impl GlobalSymbolFlags: u8 {
        /// Symbol is imported from an import file
        const Imported = 1;
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

    pub fn get_or_default(&self, name: &'a [u8]) -> SymbolId {
        let slot_idx = self.compute_slot(name);
        let slot_entry = &self.slots[slot_idx];
        let index = {
            let mut slot = slot_entry.write().expect("SymbolMap poisoned");
            let entry = slot.entry(name);
            let index = entry.index();
            entry.or_insert_with(|| RwLock::new(Symbol::default()));
            index
        };

        SymbolId::new(slot_idx, index)
    }

    pub fn get_exclusive_or_default_new(&mut self, name: &'a [u8]) -> Option<SymbolId> {
        let slot_idx = self.compute_slot(name);
        let slot = self.slots[slot_idx].get_mut().expect("SymbolMap poisoned");
        let index = match slot.entry(name) {
            Entry::Occupied(_) => return None,
            Entry::Vacant(entry) => {
                let entry = entry.insert_entry(RwLock::new(Symbol::default()));
                entry.index()
            }
        };

        Some(SymbolId::new(slot_idx, index))
    }

    pub fn get_exclusive(&mut self, symbol: SymbolId) -> Option<&mut Symbol<'a>> {
        if symbol.is_invalid() {
            return None;
        }

        let slot = self.slots[symbol.slot()]
            .get_mut()
            .expect("SymbolMap poisoned");
        let entry = slot.get_index_mut(symbol.index())?.1;
        Some(entry.get_mut().expect("SymbolMap entry poisoned"))
    }

    pub fn inspect(&self, symbol: SymbolId, f: impl FnOnce(&RwLock<Symbol<'a>>)) {
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
