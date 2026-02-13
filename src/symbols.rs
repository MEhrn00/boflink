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

use std::{hash::Hash, sync::RwLock};

use object::SymbolIndex;

use crate::{
    coff::{ImageFileMachine, SectionNumber},
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

#[derive(Debug)]
pub struct GlobalSymbol<'a> {
    pub name: &'a [u8],
    pub value: u32,
    pub section_number: SectionNumber,
    pub index: SymbolIndex,
    pub imported: bool,
    pub owner: Option<ObjectFileId>,
    pub traced: bool,
}

impl<'a> std::default::Default for GlobalSymbol<'a> {
    fn default() -> Self {
        Self {
            name: &[],
            value: 0,
            section_number: SectionNumber::Undefined,
            owner: None,
            index: object::SymbolIndex(0),
            imported: false,
            traced: false,
        }
    }
}

impl<'a> GlobalSymbol<'a> {
    /// Returns `true` if this is a COMMON symbol
    pub fn is_common(&self) -> bool {
        self.section_number == SectionNumber::Undefined && self.value != 0
    }

    pub fn demangle(
        &self,
        ctx: &LinkContext<'a>,
        architecture: ImageFileMachine,
    ) -> SymbolDemangler<'a> {
        demangle_symbol(ctx, self, architecture)
    }
}

#[derive(Debug)]
pub struct SymbolMap<'a> {
    map: ConcurrentIndexMap<&'a [u8], RwLock<GlobalSymbol<'a>>>,
}

impl<'a> SymbolMap<'a> {
    pub fn with_slot_count(count: usize) -> Self {
        Self {
            map: ConcurrentIndexMap::with_slot_count(count.next_power_of_two()),
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
            .map(|symbol| symbol.get_mut().unwrap())
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
            let symbol = symbol.get_mut().unwrap();
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
        self.entry.into_mut().get_mut().unwrap()
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
