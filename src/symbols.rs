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

use std::hash::Hash;

use object::{SectionIndex, SymbolIndex, pe};
use parking_lot::RwLock;

use crate::{
    coff::ImageFileMachine,
    concurrent_indexmap::{self, ConcurrentIndexMap, Index, Ref},
    context::LinkContext,
    object::ObjectFileId,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SymbolId(Index);

impl std::fmt::Debug for SymbolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SymbolId").field(&self.0).finish()
    }
}

pub trait Symbol {
    fn value(&self) -> u32;
    fn section_number(&self) -> u16;
    fn typ(&self) -> u16;
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
        if section_number > pe::IMAGE_SYM_UNDEFINED as u16
            && section_number < (pe::IMAGE_SYM_DEBUG as i16).cast_unsigned()
        {
            Some(SectionIndex(section_number as usize))
        } else {
            None
        }
    }

    /// Returns `true` if this is a symbol for debug info
    fn is_debug(&self) -> bool {
        self.section_number() == (pe::IMAGE_SYM_DEBUG as i16).cast_unsigned()
    }

    /// Returns `true` if this is an absolute symbol
    fn is_absolute(&self) -> bool {
        self.section_number() == (pe::IMAGE_SYM_ABSOLUTE as i16).cast_unsigned()
    }

    /// Returns `true` if this is a globally visible symbol
    fn is_global(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL
            || self.storage_class() == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
    }

    /// Returns `true` if this symbol is locally scoped
    fn is_local(&self) -> bool {
        !self.is_global()
    }

    /// Returns `true` if this symbol is a globally visible undefined external
    fn is_undefined(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL
            && self.section_number() == pe::IMAGE_SYM_UNDEFINED as u16
            && self.value() == 0
    }

    /// Returns `true` if this is a common symbol
    fn is_common(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL
            && self.section_number() == pe::IMAGE_SYM_UNDEFINED as u16
            && self.value() > 0
    }

    /// Returns `true` if this is a weak external symbol
    fn is_weak(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
    }
}

#[derive(Debug)]
pub struct GlobalSymbol<'a> {
    pub name: &'a [u8],
    pub value: u32,
    pub section_number: u16,
    pub typ: u16,
    pub storage_class: u8,
    pub owner: ObjectFileId,
    pub index: SymbolIndex,
    pub imported: bool,
    pub needs_thunk: bool,
    pub traced: bool,
}

impl<'a> std::default::Default for GlobalSymbol<'a> {
    fn default() -> Self {
        Self {
            name: &[],
            value: 0,
            section_number: 0,
            typ: 0,
            storage_class: 0,
            index: object::SymbolIndex(0),
            owner: ObjectFileId::new(0),
            imported: false,
            needs_thunk: false,
            traced: false,
        }
    }
}

impl<'a> GlobalSymbol<'a> {
    pub fn demangle(
        &self,
        ctx: &LinkContext,
        architecture: ImageFileMachine,
    ) -> SymbolDemangler<'a> {
        demangle(ctx, self.name, architecture)
    }

    pub fn priority(&self, live: bool) -> SymbolPriority {
        SymbolPriority::new(self, live)
    }
}

impl<'a> Symbol for GlobalSymbol<'a> {
    fn value(&self) -> u32 {
        self.value
    }

    fn section_number(&self) -> u16 {
        self.section_number
    }

    fn typ(&self) -> u16 {
        self.typ
    }

    fn storage_class(&self) -> u8 {
        self.storage_class
    }
}

impl<'a> Symbol for &GlobalSymbol<'a> {
    fn value(&self) -> u32 {
        self.value
    }

    fn section_number(&self) -> u16 {
        self.section_number
    }

    fn typ(&self) -> u16 {
        self.typ
    }

    fn storage_class(&self) -> u8 {
        self.storage_class
    }
}

impl<'a> Symbol for &mut GlobalSymbol<'a> {
    fn value(&self) -> u32 {
        self.value
    }

    fn section_number(&self) -> u16 {
        self.section_number
    }

    fn typ(&self) -> u16 {
        self.typ
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

pub type ExternalRef<'s, 'a> = concurrent_indexmap::Ref<'s, &'a [u8], RwLock<GlobalSymbol<'a>>>;

#[derive(Debug)]
pub struct SymbolMap<'a> {
    map: ConcurrentIndexMap<&'a [u8], RwLock<GlobalSymbol<'a>>>,
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
    pub fn get_or_create_default(&self, name: &'a [u8]) -> SymbolId {
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

    pub fn get_map_entry(&mut self, name: &'a [u8]) -> MapEntry<'_, 'a> {
        match self.map.exclusive_entry(name) {
            concurrent_indexmap::ExclusiveEntry::Vacant(entry) => {
                MapEntry::Vacant(VacantMapEntry { entry })
            }
            concurrent_indexmap::ExclusiveEntry::Occupied(entry) => {
                MapEntry::Occupied(OccupiedMapEntry { entry })
            }
        }
    }

    pub fn get(&self, symbol: SymbolId) -> Option<Ref<'_, &'a [u8], RwLock<GlobalSymbol<'a>>>> {
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
    entry: concurrent_indexmap::ExclusiveOccupiedEntry<'b, &'a [u8], RwLock<GlobalSymbol<'a>>>,
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
    entry: concurrent_indexmap::ExclusiveVacantEntry<'b, &'a [u8], RwLock<GlobalSymbol<'a>>>,
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

pub fn demangle<'a>(
    ctx: &LinkContext,
    name: &'a [u8],
    architecture: ImageFileMachine,
) -> SymbolDemangler<'a> {
    SymbolDemangler {
        name,
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
