use bitflags::bitflags;
use object::{SectionIndex, pe};

/// A COFF symbol table.
pub type SymbolTable<'a> = object::coff::SymbolTable<'a>;

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
            Some(object::SectionIndex(section_number as usize))
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

    /// Returns `true` if this symbol is for a code label
    fn is_label(&self) -> bool {
        self.storage_class() == pe::IMAGE_SYM_CLASS_LABEL
    }
}

impl Symbol for &pe::ImageSymbol {
    fn value(&self) -> u32 {
        self.value.get(object::LittleEndian)
    }

    fn section_number(&self) -> i32 {
        let number = self.section_number.get(object::LittleEndian);
        if number >= pe::IMAGE_SYM_SECTION_MAX {
            (number.cast_signed()) as i32
        } else {
            number as i32
        }
    }

    fn typ(&self) -> u16 {
        self.typ.get(object::LittleEndian)
    }

    fn storage_class(&self) -> u8 {
        self.storage_class
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
