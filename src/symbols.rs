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

use bitflags::bitflags;
use bstr::{BStr, ByteSlice};

use object::{SymbolIndex, pe};
use parking_lot::RwLock;

use crate::{
    coff::{ImageFileMachine, Symbol},
    concurrent_indexmap::{self, ConcurrentIndexMap, Index},
    object::ObjectFileId,
};

/// A globally unique symbol in the symbol map.
///
/// This represents symbols defined and referenced by object files which are
/// externally scoped. Each object file will contain a [`SymbolId`] that is
/// used to reference the global version. The ID is an interned version of the
/// symbol name used to create this symbol.
/// Since symbol names may be rewritten in the output file, the `name` field
/// should be used as the real symbol name for the output file.
///
/// The size of this structure should be kept small. There can be well over
/// 12,000 symbols inside the symbol table at once in a normal linking scenario
/// with GCC. Minimizing the size of this structure reduces the overhead needed
/// when creating the initial symbol map.
#[derive(Debug)]
pub struct GlobalSymbol<'a> {
    pub name: &'a BStr,
    pub index: SymbolIndex,
    pub value: u32,
    pub section_number: i32,
    pub owner: ObjectFileId,
    pub storage_class: u8,
    pub flags: GlobalSymbolFlags,
}

impl<'a> std::default::Default for GlobalSymbol<'a> {
    fn default() -> Self {
        Self {
            name: BStr::new(b""),
            value: 0,
            section_number: 0,
            storage_class: pe::IMAGE_SYM_CLASS_EXTERNAL,
            index: object::SymbolIndex(0),
            owner: ObjectFileId::new(0),
            flags: GlobalSymbolFlags::empty(),
        }
    }
}

impl<'a> GlobalSymbol<'a> {
    pub fn is_traced(&self) -> bool {
        self.flags.contains(GlobalSymbolFlags::Traced)
    }

    pub fn set_traced(&mut self, value: bool) {
        self.flags.set(GlobalSymbolFlags::Traced, value);
    }

    pub fn is_imported(&self) -> bool {
        self.flags.contains(GlobalSymbolFlags::Imported)
    }
}

bitflags! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct GlobalSymbolFlags: u8 {
        /// This symbol is traced using `--trace-symbol`
        const Traced = 1;

        /// This symbol is imported from a DLL
        const Imported = 1 << 1;
    }

}

impl<'a> GlobalSymbol<'a> {
    pub fn priority(&self, live: bool) -> SymbolPriority {
        SymbolPriority::new(self, live)
    }
}

impl<'a> Symbol for GlobalSymbol<'a> {
    fn value(&self) -> u32 {
        self.value
    }

    fn section_number(&self) -> i32 {
        self.section_number
    }

    fn typ(&self) -> u16 {
        // Symbol type is mostly useless for globals
        0
    }

    fn storage_class(&self) -> u8 {
        self.storage_class
    }
}

impl<'a> Symbol for &GlobalSymbol<'a> {
    fn value(&self) -> u32 {
        self.value
    }

    fn section_number(&self) -> i32 {
        self.section_number
    }

    fn typ(&self) -> u16 {
        0
    }

    fn storage_class(&self) -> u8 {
        self.storage_class
    }
}

impl<'a> Symbol for &mut GlobalSymbol<'a> {
    fn value(&self) -> u32 {
        self.value
    }

    fn section_number(&self) -> i32 {
        self.section_number
    }

    fn typ(&self) -> u16 {
        0
    }

    fn storage_class(&self) -> u8 {
        self.storage_class
    }
}

/// Symbol priorities.
///
/// These are ordered and can be compared to see if one kind has a higher resolution
/// strength over the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymbolPriority {
    Unknown,
    LazyCommon,
    Common,
    LazyWeak,
    LazyDefined,
    Weak,
    Defined,
}

impl SymbolPriority {
    pub fn new<S: Symbol>(symbol: S, live: bool) -> SymbolPriority {
        if symbol.is_common() {
            if live {
                SymbolPriority::Common
            } else {
                SymbolPriority::LazyCommon
            }
        } else if symbol.is_weak() {
            if live {
                SymbolPriority::Weak
            } else {
                SymbolPriority::LazyWeak
            }
        } else if !symbol.is_undefined() {
            if live {
                SymbolPriority::Defined
            } else {
                SymbolPriority::LazyDefined
            }
        } else {
            SymbolPriority::Unknown
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SymbolId(Index);

pub type ExternalRef<'s, 'a> = concurrent_indexmap::Ref<'s, &'a BStr, RwLock<GlobalSymbol<'a>>>;

#[derive(Debug)]
pub struct SymbolMap<'a> {
    map: ConcurrentIndexMap<&'a BStr, RwLock<GlobalSymbol<'a>>>,
}

impl<'a> SymbolMap<'a> {
    pub fn with_slot_count(count: usize) -> Self {
        Self {
            map: ConcurrentIndexMap::with_slot_count(count),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Gets the symbol id for `name` or inserts a new default symbol if not
    /// already present.
    pub fn get_or_create_default(&self, name: &'a BStr) -> SymbolId {
        let entry = self.map.entry(name);
        let index = entry.index();
        entry.or_insert_with(|| {
            RwLock::new(GlobalSymbol {
                name,
                ..Default::default()
            })
        });
        SymbolId(index)
    }

    pub fn get_exclusive_symbol(&mut self, symbol: SymbolId) -> Option<&mut GlobalSymbol<'a>> {
        self.map
            .get_exclusive_value(symbol.0)
            .map(|symbol| symbol.get_mut())
    }

    pub fn get_map_entry(&mut self, name: &'a BStr) -> MapEntry<'_, 'a> {
        match self.map.exclusive_entry(name) {
            concurrent_indexmap::ExclusiveEntry::Vacant(entry) => {
                MapEntry::Vacant(VacantMapEntry { entry })
            }
            concurrent_indexmap::ExclusiveEntry::Occupied(entry) => {
                MapEntry::Occupied(OccupiedMapEntry { entry })
            }
        }
    }

    pub fn get(&self, symbol: SymbolId) -> Option<ExternalRef<'_, 'a>> {
        self.map.get(symbol.0)
    }

    pub fn par_for_each_symbol(&mut self, f: impl Fn(&mut GlobalSymbol<'a>) + Send + Sync) {
        self.map.par_for_each_value_mut(|symbol| {
            let symbol = symbol.get_mut();
            f(symbol);
        });
    }
}

pub enum MapEntry<'b, 'a> {
    Occupied(OccupiedMapEntry<'b, 'a>),
    Vacant(VacantMapEntry<'b, 'a>),
}

impl<'b, 'a> MapEntry<'b, 'a> {
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

pub struct OccupiedMapEntry<'b, 'a> {
    entry: concurrent_indexmap::ExclusiveOccupiedEntry<'b, &'a BStr, RwLock<GlobalSymbol<'a>>>,
}

impl<'b, 'a> OccupiedMapEntry<'b, 'a> {
    pub fn id(&self) -> SymbolId {
        SymbolId(self.entry.index())
    }

    pub fn into_mut_symbol(self) -> &'b mut GlobalSymbol<'a> {
        self.entry.into_mut().get_mut()
    }
}

pub struct VacantMapEntry<'b, 'a> {
    entry: concurrent_indexmap::ExclusiveVacantEntry<'b, &'a BStr, RwLock<GlobalSymbol<'a>>>,
}

impl<'b, 'a> VacantMapEntry<'b, 'a> {
    pub fn id(&self) -> SymbolId {
        SymbolId(self.entry.index())
    }

    pub fn insert_default(self) -> OccupiedMapEntry<'b, 'a> {
        let name = *self.entry.key();
        OccupiedMapEntry {
            entry: self.entry.insert_entry(RwLock::new(GlobalSymbol {
                name,
                ..Default::default()
            })),
        }
    }
}

pub fn is_possible_user_identifier(name: impl AsRef<[u8]>) -> bool {
    let name = name.as_ref();
    if name.is_empty() {
        return false;
    }

    if !(name[0] == b'_' || name[0] == b'?' || name[0].is_ascii_alphabetic()) {
        return false;
    }

    true
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
    pub fn machine(machine: ImageFileMachine) -> Self {
        if machine == ImageFileMachine::I386 {
            Self::I386
        } else {
            Self::None
        }
    }

    /// Returns the global prefix as a char for the mangling scheme.
    pub fn global_prefix_char(self) -> Option<char> {
        if self == Self::I386 { Some('_') } else { None }
    }

    /// Returns the global prefix for the mangling scheme.
    pub fn global_prefix(self) -> Option<u8> {
        self.global_prefix_char().map(|ch| ch as u8)
    }

    /// Returns the prefix used for DLL imports for the mangling scheme.
    ///
    /// This will add the leading global prefix if I386
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
