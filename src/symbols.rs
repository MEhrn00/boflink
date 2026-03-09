//! Symbol types and global symbol handling.
//!
//! The global [`SymbolMap`] holds a [`GlobalSymbol`] entry which represents
//! every globally scoped symbol from each input object file keyed by the symbol
//! name. The symbol map requires low-overhead concurrent access for inserting
//! and manipulating entries. In a typical scenario using GCC for linking, the
//! symbol map will contain well over 12,000 entries.
//!
//! Since the names of symbols can potentially be very large due to Rust/C++
//! name mangling, the symbol map will use [String interning](https://en.wikipedia.org/wiki/String_interning).
//! The idea for this is that each object file will go through its list of globally
//! visible symbols and do a regular map insertion using through the symbol
//! name. The map insertion will return a [`SymbolId`] which is then used for
//! referencing the symbol instead of using the symbol name. This symbol id is
//! a unique 64 bit integer that is tied to the symbol name used for insertion.
//! The advantage here is that accessing the symbol after it has been interned
//! is a lot quicker on average since it used as an index into two vectors where
//! as a general hash map lookup requires recomputing the hash value of the string
//! and potentially doing string comparisons to resolve hash collisions.

use std::{
    hash::{DefaultHasher, Hasher},
    num::NonZeroU32,
    sync::atomic::AtomicBool,
};

use bitflags::bitflags;
use boflink_index::{Idx, IndexVec};
use bstr::{BStr, ByteSlice};

use crossbeam_utils::CachePadded;
use indexmap::IndexMap;
use object::pe;
use parking_lot::RwLock;
use rayon::iter::ParallelIterator;

use crate::{
    coff::{ImageFileMachine, SectionIndex, SymbolIndex},
    object::ObjectFileId,
};

pub trait Symbol {
    fn value(&self) -> u32;
    fn storage_class(&self) -> u8;
    fn section_number(&self) -> i32;
    fn is_function(&self) -> bool;

    #[inline]
    fn is_undefined(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL
            && self.section_number() == pe::IMAGE_SYM_UNDEFINED
            && self.value() == 0
    }

    #[inline]
    fn is_definition(&self) -> bool {
        self.section_number() > 0
    }

    #[inline]
    fn is_common(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL
            && self.section_number() == pe::IMAGE_SYM_UNDEFINED
            && self.value() > 0
    }

    #[inline]
    fn is_weak(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
    }

    #[inline]
    fn is_global(&self) -> bool {
        let sc = self.storage_class();
        sc == pe::IMAGE_SYM_CLASS_EXTERNAL || sc == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
    }

    #[inline]
    fn is_local(&self) -> bool {
        !self.is_global()
    }

    #[inline]
    fn is_absolute(&self) -> bool {
        self.section_number() == pe::IMAGE_SYM_ABSOLUTE
    }

    #[inline]
    fn is_debug(&self) -> bool {
        self.section_number() == pe::IMAGE_SYM_DEBUG
    }

    #[inline]
    fn section_index(&self) -> Option<SectionIndex> {
        let n = self.section_number();
        (n > 0).then(|| SectionIndex(n.cast_unsigned()))
    }

    #[inline]
    fn section(&self) -> SymbolSection {
        match self.section_number() {
            pe::IMAGE_SYM_UNDEFINED => {
                if self.value() > 0 {
                    SymbolSection::Common
                } else {
                    SymbolSection::Undefined
                }
            }
            pe::IMAGE_SYM_ABSOLUTE => SymbolSection::Absolute,
            pe::IMAGE_SYM_DEBUG => SymbolSection::Debug,
            o if o > 0 => SymbolSection::Section(SectionIndex(o.cast_unsigned())),
            _ => SymbolSection::Undefined,
        }
    }

    #[inline]
    fn priority(&self) -> SymbolPriority {
        if self.is_common() {
            SymbolPriority::Common
        } else if self.is_weak() {
            SymbolPriority::Weak
        } else if self.is_definition() {
            SymbolPriority::Defined
        } else {
            SymbolPriority::Unknown
        }
    }
}

/// The section for a symbol
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolSection {
    /// Symbol is not defined
    #[default]
    Undefined,

    /// Symbol is absolute
    Absolute,

    /// Symbol is common
    Common,

    /// Symbol is a debug symbol
    Debug,

    /// Section the symbol is defined in
    Section(SectionIndex),
}

impl SymbolSection {
    #[inline]
    pub fn index(&self) -> Option<SectionIndex> {
        if let Self::Section(v) = self {
            Some(*v)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct GlobalSymbol<'a> {
    pub name: &'a BStr,
    pub value: u32,
    pub owner: ObjectFileId,
    pub index: SymbolIndex,
    pub flags: GlobalSymbolFlags,
    pub import_needed: AtomicBool,
    pub section_number: i32,
}

impl<'a> GlobalSymbol<'a> {
    #[inline]
    pub fn new(name: &'a BStr) -> Self {
        Self {
            name,
            value: 0,
            owner: ObjectFileId::from(u32::MAX),
            index: SymbolIndex(0),
            flags: GlobalSymbolFlags::empty(),
            import_needed: AtomicBool::new(false),
            section_number: 0,
        }
    }

    #[inline]
    pub fn replace_with(&mut self, owner: ObjectFileId, index: SymbolIndex, symbol: &impl Symbol) {
        self.owner = owner;
        self.index = index;
        self.value = symbol.value();
        self.flags
            .set(GlobalSymbolFlags::Function, symbol.is_function());
        self.section_number = symbol.section_number();
    }

    #[inline]
    pub fn is_traced(&self) -> bool {
        self.flags.contains(GlobalSymbolFlags::Traced)
    }

    #[inline]
    pub fn allowed_undefined(&self) -> bool {
        self.flags.contains(GlobalSymbolFlags::AllowUndefined)
    }

    #[inline]
    pub fn is_imported(&self) -> bool {
        self.flags.contains(GlobalSymbolFlags::Imported)
    }

    #[inline]
    pub fn is_import_thunk(&self) -> bool {
        self.flags.is_import_thunk()
    }
}

/// Flags for global symbols
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GlobalSymbolFlags(u8);

bitflags! {
    impl GlobalSymbolFlags: u8 {
        /// Symbol is weak
        const Weak = 1;

        /// Symbol is for a function or defined in a code section
        const Function = 1 << 1;

        /// Symbol is imported
        const Imported = 1 << 2;

        /// This symbol is traced using `--trace-symbol`
        const Traced = 1 << 3;

        /// Symbol is allowed to be undefined
        const AllowUndefined = 1 << 4;
    }
}

impl GlobalSymbolFlags {
    #[inline]
    pub fn is_import_thunk(&self) -> bool {
        self.contains(GlobalSymbolFlags::Function | GlobalSymbolFlags::Imported)
    }
}

impl Symbol for GlobalSymbol<'_> {
    #[inline]
    fn value(&self) -> u32 {
        self.value
    }

    #[inline]
    fn is_function(&self) -> bool {
        self.flags.contains(GlobalSymbolFlags::Function)
    }

    #[inline]
    fn section_number(&self) -> i32 {
        self.section_number
    }

    #[inline]
    fn storage_class(&self) -> u8 {
        if self.flags.contains(GlobalSymbolFlags::Weak) {
            pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
        } else {
            pe::IMAGE_SYM_CLASS_EXTERNAL
        }
    }
}

/// Symbol priorities.
///
/// These are ordered and can be compared to see if one kind has a higher resolution
/// strength over the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymbolPriority {
    Unknown,
    Common,
    Weak,
    Defined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct MapId(NonZeroU32);

impl boflink_index::Idx for MapId {
    #[inline]
    fn from_usize(idx: usize) -> Self {
        Self(NonZeroU32::new((idx + 1) as u32).unwrap())
    }

    #[inline]
    fn index(self) -> usize {
        (self.0.get() - 1) as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct SlotId(u32);

impl boflink_index::Idx for SlotId {
    #[inline]
    fn from_usize(idx: usize) -> Self {
        assert!(idx <= u32::MAX as usize);
        Self(idx as u32)
    }

    #[inline]
    fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SymbolId {
    map: MapId,
    slot: SlotId,
}

type SyncMap<'a> = CachePadded<RwLock<IndexMap<&'a BStr, RwLock<GlobalSymbol<'a>>>>>;

#[derive(Debug)]
pub struct SyncSymbolMap<'a> {
    maps: IndexVec<MapId, SyncMap<'a>>,
}

impl<'a> SyncSymbolMap<'a> {
    #[inline]
    pub fn with_map_count(count: usize) -> Self {
        let count = count.clamp(1, u32::MAX as usize);
        Self {
            maps: (0..count)
                .map(|_| CachePadded::new(RwLock::new(IndexMap::new())))
                .collect(),
        }
    }

    pub fn get_or_create_default(&self, name: &'a BStr) -> SymbolId {
        let map_index = compute_map_index(name.as_ref(), self.maps.len());
        let map = &self.maps[map_index];
        let mut guard = map.write();
        let entry = guard.entry(name);
        let slot = SlotId::from_usize(entry.index());
        entry.or_insert_with(|| RwLock::new(GlobalSymbol::new(name)));

        SymbolId {
            map: map_index,
            slot,
        }
    }

    #[inline]
    pub fn into_unsync(self) -> SymbolMap<'a> {
        SymbolMap {
            maps: self
                .maps
                .into_iter()
                .map(|map| CachePadded::new(map.into_inner().into_inner()))
                .collect(),
        }
    }
}

#[derive(Debug, Default)]
pub struct SymbolMap<'a> {
    maps: IndexVec<MapId, CachePadded<IndexMap<&'a BStr, RwLock<GlobalSymbol<'a>>>>>,
}

impl<'a> SymbolMap<'a> {
    #[inline]
    pub fn with_map_count(count: usize) -> Self {
        let count = count.clamp(1, u32::MAX as usize);
        Self {
            maps: (0..count)
                .map(|_| CachePadded::new(IndexMap::new()))
                .collect(),
        }
    }

    pub fn get_or_create_default(&mut self, name: &'a BStr) -> SymbolId {
        let map_index = compute_map_index(name.as_ref(), self.maps.len());
        let map = &mut self.maps[map_index];
        let entry = map.entry(name);
        let slot = SlotId::from_usize(entry.index());
        entry.or_insert_with(|| RwLock::new(GlobalSymbol::new(name)));

        SymbolId {
            map: map_index,
            slot,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.maps.iter().fold(0, |acc, map| acc + map.len())
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn get_exclusive_symbol(&mut self, symbol: SymbolId) -> Option<&mut GlobalSymbol<'a>> {
        let map = &mut self.maps[symbol.map];
        map.get_index_mut(symbol.slot.index())
            .map(|(_, v)| v.get_mut())
    }

    #[inline]
    pub fn get_map_entry(&mut self, name: &'a BStr) -> MapEntry<'_, 'a> {
        let map_id = compute_map_index(name.as_ref(), self.maps.len());
        let map = &mut self.maps[map_id];
        match map.entry(name) {
            indexmap::map::Entry::Occupied(entry) => {
                MapEntry::Occupied(OccupiedMapEntry { map_id, entry })
            }
            indexmap::map::Entry::Vacant(entry) => {
                MapEntry::Vacant(VacantMapEntry { map_id, entry })
            }
        }
    }

    #[inline]
    pub fn get(&self, symbol: SymbolId) -> Option<&RwLock<GlobalSymbol<'a>>> {
        let map = &self.maps[symbol.map];
        map.get_index(symbol.slot.index()).map(|(_, v)| v)
    }

    #[inline]
    pub fn par_for_each_symbol(&mut self, f: impl Fn(&mut GlobalSymbol<'a>) + Send + Sync) {
        self.maps.par_iter_enumerated_mut().for_each(|(_, map)| {
            map.par_values_mut().for_each(|symbol| f(symbol.get_mut()));
        });
    }
}

fn compute_map_index(name: &[u8], count: usize) -> MapId {
    let mut h = DefaultHasher::new();
    h.write(name);
    let index = h.finish() as usize % count;
    MapId::from_usize(index)
}

pub enum MapEntry<'b, 'a> {
    Occupied(OccupiedMapEntry<'b, 'a>),
    Vacant(VacantMapEntry<'b, 'a>),
}

impl<'b, 'a> MapEntry<'b, 'a> {
    #[inline]
    pub fn id(&self) -> SymbolId {
        match self {
            Self::Occupied(entry) => entry.id(),
            Self::Vacant(entry) => entry.id(),
        }
    }

    #[inline]
    pub fn or_default(self) -> &'b mut GlobalSymbol<'a> {
        match self {
            Self::Occupied(entry) => entry.into_mut_symbol(),
            Self::Vacant(entry) => entry.insert_default().into_mut_symbol(),
        }
    }
}

pub struct OccupiedMapEntry<'b, 'a> {
    map_id: MapId,
    entry: indexmap::map::OccupiedEntry<'b, &'a BStr, RwLock<GlobalSymbol<'a>>>,
}

impl<'b, 'a> OccupiedMapEntry<'b, 'a> {
    #[inline]
    pub fn id(&self) -> SymbolId {
        SymbolId {
            map: self.map_id,
            slot: SlotId::from_usize(self.entry.index()),
        }
    }

    #[inline]
    pub fn into_mut_symbol(self) -> &'b mut GlobalSymbol<'a> {
        self.entry.into_mut().get_mut()
    }
}

pub struct VacantMapEntry<'b, 'a> {
    map_id: MapId,
    entry: indexmap::map::VacantEntry<'b, &'a BStr, RwLock<GlobalSymbol<'a>>>,
}

impl<'b, 'a> VacantMapEntry<'b, 'a> {
    pub fn id(&self) -> SymbolId {
        SymbolId {
            map: self.map_id,
            slot: SlotId::from_usize(self.entry.index()),
        }
    }

    pub fn insert_default(self) -> OccupiedMapEntry<'b, 'a> {
        let name = *self.entry.key();
        OccupiedMapEntry {
            map_id: self.map_id,
            entry: self
                .entry
                .insert_entry(RwLock::new(GlobalSymbol::new(name))),
        }
    }
}

/// Architecture specified mangling scheme for global symbol names.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManglingScheme {
    #[default]
    None,

    I386,
}

impl ManglingScheme {
    /// Returns the mangling scheme matching the specified machine value
    #[inline]
    pub fn machine(machine: ImageFileMachine) -> Self {
        if machine == ImageFileMachine::I386 {
            Self::I386
        } else {
            Self::None
        }
    }

    /// Returns the global prefix as a char for the mangling scheme.
    #[inline]
    pub fn global_prefix_char(self) -> Option<char> {
        if self == Self::I386 { Some('_') } else { None }
    }

    /// Returns the global prefix for the mangling scheme.
    #[inline]
    pub fn global_prefix(self) -> Option<u8> {
        self.global_prefix_char().map(|ch| ch as u8)
    }

    /// Returns the prefix used for DLL imports for the mangling scheme.
    ///
    /// This will add the leading global prefix if I386
    #[inline]
    pub fn dllimport_prefix(self) -> &'static BStr {
        if self == Self::I386 {
            BStr::new(b"__imp__")
        } else {
            BStr::new(b"__imp_")
        }
    }

    /// Returns the global prefix for the mangling scheme as a byte slice.
    ///
    /// The byte slice will be empty if there is no prefix.
    #[inline]
    pub fn global_prefix_bytes(self) -> &'static BStr {
        if self == Self::I386 {
            BStr::new(b"_")
        } else {
            BStr::new(b"")
        }
    }
}

/// Demangler for a symbol name that is possibly itanium, Rust or MSVC mangled.
#[derive(Debug, Clone)]
pub struct SymbolDemangler<'a> {
    name: &'a BStr,
    scheme: ManglingScheme,
}

impl<'a> SymbolDemangler<'a> {
    #[inline]
    pub fn new(name: &'a BStr, scheme: ManglingScheme) -> Self {
        Self { name, scheme }
    }
}

impl std::fmt::Display for SymbolDemangler<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut name = self.name;
        if let Some(trimmed) = name.strip_prefix(b"__imp_") {
            name = BStr::new(trimmed);
            write!(f, "__declspec(dllimport) ")?;
        }

        let try_demangle = |f: &mut std::fmt::Formatter<'_>| -> Option<()> {
            demangle_msvc(f, name, self.scheme == ManglingScheme::I386)
                .or_else(|| demangle_cpp(f, name, self.scheme))
                .or_else(|| demangle_rustc(f, name, self.scheme))
        };

        if try_demangle(f).is_none() {
            name.fmt(f)?;
        }

        Ok(())
    }
}

fn demangle_cpp(
    f: &mut std::fmt::Formatter<'_>,
    mut symbol: &[u8],
    mangling: ManglingScheme,
) -> Option<()> {
    if mangling
        .global_prefix()
        .is_some_and(|prefix| symbol.first() == Some(&prefix))
    {
        symbol = &symbol[1..];
    }

    if symbol.starts_with(b"_Z") {
        let demangler = cpp_demangle::Symbol::new(symbol).ok()?;
        demangler.structured_demangle(f, &Default::default()).ok()
    } else {
        None
    }
}

fn demangle_rustc(
    f: &mut std::fmt::Formatter<'_>,
    mut symbol: &[u8],
    mangling: ManglingScheme,
) -> Option<()> {
    if mangling
        .global_prefix()
        .is_some_and(|prefix| symbol.first() == Some(&prefix))
    {
        symbol = &symbol[1..];
    }

    let symbol = symbol.to_str_lossy();
    let demangler = rustc_demangle::try_demangle(&symbol).ok()?;
    write!(f, "{demangler}").ok()
}

#[cfg(not(windows))]
fn demangle_msvc(_f: &mut std::fmt::Formatter<'_>, _symbol: &[u8], _i386: bool) -> Option<()> {
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
