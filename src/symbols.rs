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

use bstr::{BStr, ByteSlice};

use object::{SectionIndex, SymbolIndex, pe};
use parking_lot::RwLock;

use crate::{
    coff::ImageFileMachine,
    concurrent_indexmap::{self, ConcurrentIndexMap, Index},
    object::ObjectFileId,
};

/// This trait is used to abstract various routines when dealing with COFF symbols.
///
/// COFF symbols include 4 main metadata fields.
/// - Value
/// - SectionNumber
/// - Type
/// - StorageClass
///
/// Some of these fields are insignificant on their own without being paired with
/// values from other fields.
/// This trait requires implementors to add accessors for these metadata fields.
///
/// The rest of the trait methods allow querying for different attributes of
/// symbols through the associated fields.
pub trait Symbol {
    /// Returns the raw `Value` from the symbol
    fn value(&self) -> u32;

    /// Returns the raw `SectionNumber` from the symbol
    fn section_number(&self) -> i32;

    /// Returns the raw `Type` from the symbol
    fn typ(&self) -> u16;

    /// Returns the raw `StorageClass` from the symbol
    fn storage_class(&self) -> u8;

    /// Returns the base type of the symbol
    fn base_type(&self) -> u16 {
        self.typ() & pe::N_BTMASK
    }

    /// Returns the complex type of the symbol
    fn complex_type(&self) -> u16 {
        (self.typ() & pe::N_TMASK) >> pe::N_BTSHFT
    }

    /// Returns the index of the section this symbol is defined in
    fn section(&self) -> Option<SectionIndex> {
        let section_number = self.section_number();
        if section_number > pe::IMAGE_SYM_UNDEFINED {
            Some(SectionIndex(section_number as usize))
        } else {
            None
        }
    }

    /// Returns `true` if this is a symbol for a debug item
    fn is_debug(&self) -> bool {
        self.section_number() == pe::IMAGE_SYM_DEBUG
    }

    /// Returns `true` if this is an absolute symbol.
    ///
    /// The value is interpreted as the symbol value.
    fn is_absolute(&self) -> bool {
        self.section_number() == pe::IMAGE_SYM_ABSOLUTE
    }

    /// Returns `true` if this is a relocatable symbol.
    ///
    /// A relocatable symbol means that the value field refers to an RVA inside
    /// the section referred to by the section number.
    fn is_relocatable(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL
            || self.storage_class() == pe::IMAGE_SYM_CLASS_STATIC
            || self.storage_class() == pe::IMAGE_SYM_CLASS_LABEL
    }

    /// Returns `true` if this is a globally visible symbol.
    ///
    /// Globally visible symbols are symbols with `IMAGE_SYM_CLASS_EXTERNAL` or
    /// `IMAGE_SYM_CLASS_WEAK_EXTERNAL` storage class
    fn is_global(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL
            || self.storage_class() == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
    }

    /// Returns `true` if this symbol is locally scoped.
    ///
    /// Local symbols are all other symbols that do not fall under the category of
    /// [`Symbol::is_global()`]
    fn is_local(&self) -> bool {
        !self.is_global()
    }

    /// Returns `true` if this symbol is an undefined external symbol.
    ///
    /// An undefined external symbol is a symbol with `IMAGE_SYM_CLASS_EXTERNAL`
    /// storage class, a section number of 0 (`IMAGE_SYM_UNDEFINED`) and a value
    /// of 0.
    ///
    /// # Note
    /// Common symbols [`Symbol::is_common()`] and weak externals [`Symbol::is_weak()`]
    /// do not fall under this category
    fn is_undefined(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL
            && self.section_number() == pe::IMAGE_SYM_UNDEFINED
            && self.value() == 0
    }

    /// Returns `true` if this is a common symbol.
    ///
    /// A common symbol has `IMAGE_SYM_CLASS_EXTERNAL` storage class, a section
    /// number of 0 (`IMAGE_SYM_UNDEFINED`) and a value that is non-zero. The
    /// value field is interpreted as the symbol size/alignment
    fn is_common(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL
            && self.section_number() == pe::IMAGE_SYM_UNDEFINED
            && self.value() > 0
    }

    /// Returns `true` if this is a weak external symbol
    fn is_weak(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
    }
}

#[derive(Debug)]
pub struct GlobalSymbol<'a> {
    pub name: &'a BStr,
    pub value: u32,
    pub section_number: i32,
    pub storage_class: u8,
    pub owner: ObjectFileId,
    pub index: SymbolIndex,
    pub traced: bool,
    pub imported: bool,
    pub dfr: bool,
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
            imported: false,
            traced: false,
            dfr: false,
        }
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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SymbolId(Index);

impl std::fmt::Debug for SymbolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SymbolId").field(&self.0).finish()
    }
}

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
