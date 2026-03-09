use bitflags::bitflags;
use object::{StringTable, pe, read::coff};

use crate::symbols::Symbol;

/// A COFF symbol table.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SymbolIndex(pub u32);

impl boflink_index::Idx for SymbolIndex {
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

impl std::fmt::Display for SymbolIndex {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct SymbolTable<'a, H: coff::CoffHeader = pe::ImageFileHeader>(
    coff::SymbolTable<'a, &'a [u8], H>,
);

impl<'a, H: coff::CoffHeader> Default for SymbolTable<'a, H> {
    fn default() -> Self {
        Self(coff::SymbolTable::default())
    }
}

impl<'a, H: coff::CoffHeader> SymbolTable<'a, H> {
    #[inline]
    pub fn parse(header: &H, data: &'a [u8]) -> crate::Result<Self> {
        Ok(Self(coff::SymbolTable::parse(header, data)?))
    }

    #[inline]
    pub fn strings(&self) -> StringTable<'a> {
        self.0.strings()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (SymbolIndex, &'a <H as coff::CoffHeader>::ImageSymbol)> {
        self.0
            .iter()
            .map(|(i, symbol)| (SymbolIndex(i.0 as u32), symbol))
    }

    #[inline]
    pub fn symbol(&self, index: SymbolIndex) -> crate::Result<&'a H::ImageSymbol> {
        Ok(self.0.symbol(object::SymbolIndex(index.0 as usize))?)
    }

    #[inline]
    pub fn aux_section(&self, index: SymbolIndex) -> crate::Result<&'a pe::ImageAuxSymbolSection> {
        Ok(self.0.aux_section(object::SymbolIndex(index.0 as usize))?)
    }

    #[inline]
    pub fn aux_weak_external(
        &self,
        index: SymbolIndex,
    ) -> crate::Result<&'a pe::ImageAuxSymbolWeak> {
        Ok(self
            .0
            .aux_weak_external(object::SymbolIndex(index.0 as usize))?)
    }
}

impl<T: coff::ImageSymbol> Symbol for T {
    #[inline]
    fn value(&self) -> u32 {
        coff::ImageSymbol::value(self)
    }

    #[inline]
    fn storage_class(&self) -> u8 {
        coff::ImageSymbol::storage_class(self)
    }

    #[inline]
    fn section_number(&self) -> i32 {
        coff::ImageSymbol::section_number(self)
    }

    #[inline]
    fn is_function(&self) -> bool {
        self.derived_type() == pe::IMAGE_SYM_DTYPE_FUNCTION
    }
}

/// @feat.00 symbol flags.
///
/// Flags are from
/// <https://github.com/llvm/llvm-project/blob/544c300f4396119bf5a2ea4239d32774908a882d/llvm/include/llvm/BinaryFormat/COFF.h#L845>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Feat00Flags(u32);

bitflags! {
    impl Feat00Flags: u32 {
        /// Object is compatible with /safeseh.
        const SafeSEH = 1;

        /// Object was compiled with /GS.
        const GuardStack = 0x100;

        /// Object was compiled with /sdl.
        const SDL = 0x200;

        /// Object was compiled with /guard:cf.
        const GuardCF = 0x800;

        /// Object was compiled with /guard:ehcont.
        const GuardEHCont = 0x4000;

        /// Object was compiled with /kernel.
        const Kernel = 0x40000000;

        // Allow externally set flags
        const _ = !0;
    }
}
