//! Symbol types and global symbol handling.
//!
//! The global symbol map is internally represented as a concurrent [`IndexMap`].
//! The symbol map requires concurrent read/write access and can contain well over
//! 12000 entries in a typical scenario.
//!
//! Since the symbol name strings can potentially be very long with C++/Rust name
//! mangling, the goal here is to use
//! [String interning](https://en.wikipedia.org/wiki/String_interning).
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

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::{RwLock, atomic::Ordering},
};

use crossbeam_utils::CachePadded;
use indexmap::IndexMap;
use object::SymbolIndex;
use rayon::iter::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};

use crate::{
    arena::ArenaRef,
    coff::{ImageFileMachine, SectionNumber, StorageClass},
    context::LinkContext,
    fatal,
    inputs::{ObjectFile, ObjectFileId},
};

const SLOT_BITS: u32 = 8;
const SLOT_SHIFT: u32 = u32::BITS - SLOT_BITS;
const MAX_SLOTS: usize = 2usize.pow(SLOT_BITS as u32) - 1;
const MAX_INDEX: usize = !((MAX_SLOTS << SLOT_SHIFT) as u32) as usize;
const INDEX_MASK: u32 = MAX_INDEX as u32;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SymbolId(u32);

impl std::fmt::Debug for SymbolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SymbolId").field(&self.location()).finish()
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

    /// Returns the (slot, index) pair if this symbol id is valid
    const fn location(&self) -> Option<(usize, usize)> {
        if self.is_valid() {
            let slot = (self.0 >> SLOT_SHIFT) as usize;
            let index = (self.0 & INDEX_MASK) as usize;
            Some((slot, index))
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct GlobalSymbol<'a> {
    pub name: &'a [u8],
    pub value: u32,
    pub section_number: SectionNumber,
    pub storage_class: StorageClass,
    pub index: SymbolIndex,
    pub owner: ObjectFileId,
    pub traced: bool,
}

impl<'a> std::default::Default for GlobalSymbol<'a> {
    fn default() -> Self {
        Self {
            name: &[],
            value: 0,
            section_number: SectionNumber::Undefined,
            storage_class: StorageClass::Null,
            owner: ObjectFileId::invalid(),
            index: object::SymbolIndex(0),
            traced: false,
        }
    }
}

impl<'a> GlobalSymbol<'a> {
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
            && self.section_number == SectionNumber::Undefined
            && self.value == 0
    }

    /// Returns `true` if this symbol is defined.
    ///
    /// This only returns `true` for symbols with external or static storage
    /// class
    pub fn is_defined(&self) -> bool {
        self.section_number > SectionNumber::Undefined
            && (self.is_global() || self.storage_class == StorageClass::Static)
    }

    /// Returns `true` if this is a COMMON symbol
    pub fn is_common(&self) -> bool {
        self.storage_class == StorageClass::External
            && self.section_number == SectionNumber::Undefined
            && self.value != 0
    }

    /// Returns `true` if this is a weak external symbol
    pub fn is_weak_external(&self) -> bool {
        self.storage_class == StorageClass::WeakExternal
    }

    pub fn kind(&self) -> SymbolKind {
        if self.is_defined() {
            SymbolKind::Defined
        } else if self.is_weak_external() {
            SymbolKind::Weak
        } else if self.is_common() {
            SymbolKind::Common
        } else {
            SymbolKind::Unknown
        }
    }

    pub fn priority(&self, objs: &[ArenaRef<'a, ObjectFile<'a>>]) -> SymbolPriority {
        if let Some(index) = self.owner.index() {
            SymbolPriority {
                obj: self.owner,
                kind: self.kind(),
                live: objs[index].live.load(Ordering::Relaxed),
            }
        } else {
            SymbolPriority {
                obj: self.owner,
                kind: SymbolKind::Unknown,
                live: false,
            }
        }
    }

    pub fn demangle(
        &self,
        ctx: &LinkContext<'a>,
        architecture: ImageFileMachine,
    ) -> SymbolDemangler<'a> {
        demangle_symbol(ctx, self, architecture)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SymbolKind {
    Defined,
    Weak,
    Common,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SymbolPriority {
    obj: ObjectFileId,
    kind: SymbolKind,
    live: bool,
}

impl SymbolPriority {
    pub fn new(obj: ObjectFileId, kind: SymbolKind, live: bool) -> Self {
        Self { obj, kind, live }
    }
}

impl PartialOrd for SymbolPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let scalar_priority = |symbol: &SymbolPriority| {
            if symbol.obj.is_invalid() {
                return 7;
            }

            match symbol.kind {
                SymbolKind::Common if symbol.live => 5,
                SymbolKind::Common => 6,
                SymbolKind::Defined if symbol.live => 1,
                SymbolKind::Defined => 3,
                SymbolKind::Weak if symbol.live => 2,
                SymbolKind::Weak => 4,
                SymbolKind::Unknown => 7,
            }
        };

        match scalar_priority(self).cmp(&scalar_priority(other)) {
            std::cmp::Ordering::Equal => self.obj.partial_cmp(&other.obj),
            o => Some(o),
        }
    }
}

type MapSlot<'a> = IndexMap<&'a [u8], RwLock<GlobalSymbol<'a>>>;

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

    /// Gets the symbol id for `name` or inserts a new default symbol if not
    /// already present.
    pub fn get_or_create_default(&self, name: &'a [u8]) -> SymbolId {
        let slot_idx = self.compute_slot(name);
        let slot_entry = &self.slots[slot_idx];
        let index = {
            let mut slot = slot_entry.write().expect("SymbolMap poisoned");
            let entry = slot.entry(name);
            let index = entry.index();
            entry.or_insert_with(|| {
                let mut symbol = GlobalSymbol::default();
                symbol.name = name;
                RwLock::new(symbol)
            });
            index
        };

        SymbolId::new(slot_idx, index)
    }

    pub fn get_exclusive_symbol(&mut self, symbol: SymbolId) -> Option<&mut GlobalSymbol<'a>> {
        let (slot_index, index) = symbol.location()?;

        let slot = self.slots[slot_index]
            .get_mut()
            .expect("SymbolMap poisoned");
        let entry = slot.get_index_mut(index)?.1;
        Some(entry.get_mut().expect("SymbolMap entry poisoned"))
    }

    pub fn get_exclusive_entry(&mut self, name: &'a [u8]) -> ExclusiveEntry<'_, 'a> {
        let slot_idx = self.compute_slot(name);
        let slot = self.slots[slot_idx].get_mut().expect("SymbolMap poisoned");
        match slot.entry(name) {
            indexmap::map::Entry::Occupied(entry) => ExclusiveEntry::Occupied(OccupiedEntry {
                slot: slot_idx,
                entry,
            }),
            indexmap::map::Entry::Vacant(entry) => ExclusiveEntry::Vacant(VacantEntry {
                slot: slot_idx,
                entry,
            }),
        }
    }

    pub fn inspect(&self, symbol: SymbolId, f: impl FnOnce(&RwLock<GlobalSymbol<'a>>)) {
        let Some((slot_index, index)) = symbol.location() else {
            return;
        };

        let slot = self.slots[slot_index].read().expect("SymbolMap poisoned");
        if let Some((_, entry)) = slot.get_index(index) {
            f(entry);
        }
    }

    pub fn par_for_each(&self, f: impl Fn(&RwLock<GlobalSymbol<'a>>) + Send + Sync) {
        self.slots.par_iter().for_each(|slot| {
            let slot = slot.read().expect("SymbolMap poisoned");
            slot.par_values().for_each(|symbol| f(symbol));
        });
    }

    pub fn par_for_each_exclusive(&mut self, f: impl Fn(&mut GlobalSymbol<'a>) + Send + Sync) {
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

pub enum ExclusiveEntry<'b, 'a> {
    Occupied(OccupiedEntry<'b, 'a>),
    Vacant(VacantEntry<'b, 'a>),
}

impl<'b, 'a> ExclusiveEntry<'b, 'a> {
    pub fn id(&self) -> SymbolId {
        match self {
            Self::Occupied(entry) => entry.id(),
            Self::Vacant(entry) => entry.id(),
        }
    }

    pub fn or_default(self) -> &'b mut GlobalSymbol<'a> {
        match self {
            Self::Occupied(entry) => entry.into_mut_symbol(),
            Self::Vacant(entry) => entry.insert_default().into_mut_symbol(),
        }
    }
}

pub struct OccupiedEntry<'b, 'a> {
    slot: usize,
    entry: indexmap::map::OccupiedEntry<'b, &'a [u8], RwLock<GlobalSymbol<'a>>>,
}

impl<'b, 'a> OccupiedEntry<'b, 'a> {
    pub fn id(&self) -> SymbolId {
        SymbolId::new(self.slot, self.entry.index())
    }

    pub fn into_mut_symbol(self) -> &'b mut GlobalSymbol<'a> {
        self.entry.into_mut().get_mut().unwrap()
    }
}

pub struct VacantEntry<'b, 'a> {
    slot: usize,
    entry: indexmap::map::VacantEntry<'b, &'a [u8], RwLock<GlobalSymbol<'a>>>,
}

impl<'b, 'a> VacantEntry<'b, 'a> {
    pub fn id(&self) -> SymbolId {
        SymbolId::new(self.slot, self.entry.index())
    }

    pub fn insert_default(self) -> OccupiedEntry<'b, 'a> {
        let mut symbol = GlobalSymbol::default();
        symbol.name = *self.entry.key();
        let entry = self.entry.insert_entry(RwLock::new(symbol));
        OccupiedEntry {
            slot: self.slot,
            entry,
        }
    }
}

pub fn demangle_symbol<'a>(
    ctx: &LinkContext<'a>,
    symbol: &GlobalSymbol<'a>,
    architecture: ImageFileMachine,
) -> SymbolDemangler<'a> {
    SymbolDemangler {
        name: symbol.name,
        i386: architecture == ImageFileMachine::I386,
        demangle: ctx.options.demangle,
    }
}

#[derive(Debug, Clone)]
pub struct SymbolDemangler<'a> {
    name: &'a [u8],
    i386: bool,
    demangle: bool,
}

impl std::fmt::Display for SymbolDemangler<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name_string = String::from_utf8_lossy(self.name);
        if !self.demangle {
            f.write_str(&name_string)?;
            return Ok(());
        }

        let mut name = name_string.as_ref();
        if let Some(trimmed) = name.strip_prefix("__imp_") {
            name = trimmed;
            write!(f, "__declspec(dllimport) ")?;
        }

        let try_demangle = |f: &mut std::fmt::Formatter<'_>| -> Option<()> {
            demangle_msvc(f, name, self.i386)
                .or_else(|| demangle_cpp(f, name, self.i386))
                .or_else(|| demangle_rustc(f, name, self.i386))
        };

        if try_demangle(f).is_none() {
            f.write_str(name)?;
        }

        Ok(())
    }
}

fn demangle_cpp(f: &mut std::fmt::Formatter<'_>, symbol: &str, i386: bool) -> Option<()> {
    let is_cpp_mangled =
        |symbol: &str| (i386 && symbol.starts_with("__Z")) || symbol.starts_with("_Z");

    if is_cpp_mangled(symbol) {
        let demangler = cpp_demangle::Symbol::new(symbol).ok()?;
        demangler.structured_demangle(f, &Default::default()).ok()
    } else {
        None
    }
}

fn demangle_rustc(f: &mut std::fmt::Formatter<'_>, mut symbol: &str, i386: bool) -> Option<()> {
    if i386 {
        symbol = symbol.trim_start_matches('_');
    }

    let demangler = rustc_demangle::try_demangle(symbol).ok()?;
    write!(f, "{demangler}").ok()
}

#[cfg(not(windows))]
fn demangle_msvc(_f: &mut std::fmt::Formatter<'_>, _symbol: &str, _i386: bool) -> Option<()> {
    None
}

#[cfg(windows)]
fn demangle_msvc(f: &mut std::fmt::Formatter<'_>, symbol: &str, i386: bool) -> Option<()> {
    use crate::undname::{UndnameFlags, undname_demangle};

    let mut flags = UndnameFlags::NoPtr64Expansion;
    if i386 {
        flags |= UndnameFlags::ThirtyTwoBitDecode;
    }

    let demangler = undname_demangle(symbol, flags).ok()?;
    write!(f, "{demangler}").ok()
}
