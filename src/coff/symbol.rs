use bitflags::bitflags;
use bstr::BStr;
use object::{LittleEndian, StringTable, U32Bytes, pe, read::coff};

use crate::{make_error, symbols::Symbol};

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
    pub fn aux_weak_external(&self, index: SymbolIndex) -> crate::Result<&'a ImageAuxSymbolWeak> {
        Ok(self
            .0
            .get::<ImageAuxSymbolWeak>(object::SymbolIndex(index.0 as usize), 1)?)
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

pub trait ImageSymbol: Symbol {
    /// The raw symbol name
    fn raw_name(&self) -> &[u8; 8];

    /// Returns the raw symbol type value
    fn typ(&self) -> u16;

    /// Returns the number of auxiliary symbol table records
    fn number_of_aux_symbols(&self) -> u8;

    #[inline]
    fn name_bytes<'data>(&'data self, strings: StringTable<'data>) -> crate::Result<&'data [u8]> {
        let raw_name = self.raw_name();
        if raw_name[0] == 0 {
            let offset = u32::from_le_bytes(raw_name[4..8].try_into().unwrap());
            strings
                .get(offset)
                .map_err(|_| make_error!("invalid COFF symbol name offset"))
        } else {
            Ok(match memchr::memchr(b'\0', raw_name) {
                Some(pos) => &raw_name[..pos],
                None => &raw_name[..],
            })
        }
    }

    #[inline]
    fn name_bstr<'data>(&'data self, strings: StringTable<'data>) -> crate::Result<&'data BStr> {
        self.name_bytes(strings).map(BStr::new)
    }

    #[inline]
    fn has_aux_section(&self) -> bool {
        self.number_of_aux_symbols() > 0
            && self.storage_class() == pe::IMAGE_SYM_CLASS_STATIC
            && self.typ() == 0
    }

    #[inline]
    fn has_aux_weak_external(&self) -> bool {
        self.number_of_aux_symbols() > 0
            && self.storage_class() == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
            && self.section_number() == pe::IMAGE_SYM_UNDEFINED
            && self.value() == 0
    }

    #[inline]
    fn base_type(&self) -> u16 {
        self.typ() & pe::N_BTMASK
    }

    #[inline]
    fn complex_type(&self) -> u16 {
        (self.typ() & pe::N_TMASK) >> pe::N_BTSHFT
    }
}

impl<T: coff::ImageSymbol> ImageSymbol for T {
    #[inline]
    fn raw_name(&self) -> &[u8; 8] {
        coff::ImageSymbol::raw_name(self)
    }

    #[inline]
    fn typ(&self) -> u16 {
        coff::ImageSymbol::typ(self)
    }

    #[inline]
    fn number_of_aux_symbols(&self) -> u8 {
        coff::ImageSymbol::number_of_aux_symbols(self)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ImageAuxSymbolWeak {
    pub tag_index: U32Bytes<LittleEndian>,
    pub characteristics: U32Bytes<LittleEndian>,
    pub unused: [u8; 10],
}

impl ImageAuxSymbolWeak {
    #[inline]
    pub fn default_symbol(&self) -> SymbolIndex {
        SymbolIndex(self.tag_index.get(LittleEndian))
    }
}

unsafe impl object::Pod for ImageAuxSymbolWeak {}

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
