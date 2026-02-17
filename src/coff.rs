//! Low-level COFF handling module.
//!
//! This acts as a supplement to the [object](https://github.com/gimli-rs/object)
//! crate.
//!
//! Most of the items here are [newtypes](https://doc.rust-lang.org/rust-by-example/generics/new_types.html)
//! and strongly typed bit flags for handling PE characteristics.
//!
//! This module contains a lot of boilerplate stuff due to the nature of new
//! types and bit flags. Some crates exist to help reduce the boilerplate stuff.
//! Namely num_enum and thiserror.
//!
//! num_enum's derive crate pulls in 8 additional transitive dependencies one
//! of which is a pretty heavy toml parser for parsing the Cargo.toml file.
//! This is so that the proc macro works in cases where the num_enum dependency
//! was renamed. It would not be renamed if used here and there is no way to
//! exclude that dependency with a feature flag.
//!
//! Both the thiserror and num_enum crates pull in syn with all of the feature
//! flags enabled. Syn takes about 3s to build. That is not a lot of time in
//! reality but the source code in this project only takes about 1.5s to build.
//! These crates also do not include any feature flags to help reduce their
//! build times so the added overhead did not seem worth it compared to the
//! boilerplate needed here.

use bitflags::bitflags;
use object::{SectionIndex, SymbolIndex, coff::ImageSymbol as _, pe, read::coff};

pub type ComdatKind = object::ComdatKind;

use crate::symbols::Symbol;

#[derive(Debug)]
pub struct TryFromImageFileMachineError(u16);

impl std::fmt::Display for TryFromImageFileMachineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown 'IMAGE_FILE_MACHINE_*' value '{}'", self.0)
    }
}

impl std::error::Error for TryFromImageFileMachineError {}

/// PE `IMAGE_FILE_MACHINE_*` constants.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ImageFileMachine {
    #[default]
    Unknown = pe::IMAGE_FILE_MACHINE_UNKNOWN,
    Alpha = pe::IMAGE_FILE_MACHINE_ALPHA,
    Alpha64 = pe::IMAGE_FILE_MACHINE_ALPHA64,
    Am33 = pe::IMAGE_FILE_MACHINE_AM33,
    Amd64 = pe::IMAGE_FILE_MACHINE_AMD64,
    Arm = pe::IMAGE_FILE_MACHINE_ARM,
    Arm64 = pe::IMAGE_FILE_MACHINE_ARM64,
    Arm64Ec = pe::IMAGE_FILE_MACHINE_ARM64EC,
    Arm64X = pe::IMAGE_FILE_MACHINE_ARM64X,
    ArmNt = pe::IMAGE_FILE_MACHINE_ARMNT,
    Ebc = pe::IMAGE_FILE_MACHINE_EBC,
    I386 = pe::IMAGE_FILE_MACHINE_I386,
    Ia64 = pe::IMAGE_FILE_MACHINE_IA64,
    M32R = pe::IMAGE_FILE_MACHINE_M32R,
    Mips16 = pe::IMAGE_FILE_MACHINE_MIPS16,
    MipsFpu = pe::IMAGE_FILE_MACHINE_MIPSFPU,
    MipsFpu16 = pe::IMAGE_FILE_MACHINE_MIPSFPU16,
    PowerPc = pe::IMAGE_FILE_MACHINE_POWERPC,
    PowerPcFp = pe::IMAGE_FILE_MACHINE_POWERPCFP,
    R3000 = pe::IMAGE_FILE_MACHINE_R3000,
    R4000 = pe::IMAGE_FILE_MACHINE_R4000,
    R10000 = pe::IMAGE_FILE_MACHINE_R10000,
    RiscV32 = pe::IMAGE_FILE_MACHINE_RISCV32,
    RiscV64 = pe::IMAGE_FILE_MACHINE_RISCV64,
    RiscV128 = pe::IMAGE_FILE_MACHINE_RISCV128,
    Sh3 = pe::IMAGE_FILE_MACHINE_SH3,
    Sh3Dsp = pe::IMAGE_FILE_MACHINE_SH3DSP,
    Sh4 = pe::IMAGE_FILE_MACHINE_SH4,
    Sh5 = pe::IMAGE_FILE_MACHINE_SH5,
    Thumb = pe::IMAGE_FILE_MACHINE_THUMB,
    WceMipsV2 = pe::IMAGE_FILE_MACHINE_WCEMIPSV2,
}

impl std::fmt::Display for ImageFileMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(s) = MachineDisplay(*self as u16).as_str() {
            f.write_str(s)
        } else {
            panic!("unhandled MachineDisplay variant {}", *self as u16);
        }
    }
}

impl TryFrom<u16> for ImageFileMachine {
    type Error = TryFromImageFileMachineError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            pe::IMAGE_FILE_MACHINE_UNKNOWN => Self::Unknown,
            pe::IMAGE_FILE_MACHINE_ALPHA => Self::Alpha,
            pe::IMAGE_FILE_MACHINE_ALPHA64 => Self::Alpha64,
            pe::IMAGE_FILE_MACHINE_AM33 => Self::Am33,
            pe::IMAGE_FILE_MACHINE_AMD64 => Self::Amd64,
            pe::IMAGE_FILE_MACHINE_ARM => Self::Arm,
            pe::IMAGE_FILE_MACHINE_ARM64 => Self::Arm64,
            pe::IMAGE_FILE_MACHINE_ARM64EC => Self::Arm64Ec,
            pe::IMAGE_FILE_MACHINE_ARM64X => Self::Arm64X,
            pe::IMAGE_FILE_MACHINE_ARMNT => Self::ArmNt,
            pe::IMAGE_FILE_MACHINE_EBC => Self::Ebc,
            pe::IMAGE_FILE_MACHINE_I386 => Self::I386,
            pe::IMAGE_FILE_MACHINE_IA64 => Self::Ia64,
            pe::IMAGE_FILE_MACHINE_M32R => Self::M32R,
            pe::IMAGE_FILE_MACHINE_MIPS16 => Self::Mips16,
            pe::IMAGE_FILE_MACHINE_MIPSFPU => Self::MipsFpu,
            pe::IMAGE_FILE_MACHINE_MIPSFPU16 => Self::Mips16,
            pe::IMAGE_FILE_MACHINE_POWERPC => Self::PowerPc,
            pe::IMAGE_FILE_MACHINE_POWERPCFP => Self::PowerPcFp,
            pe::IMAGE_FILE_MACHINE_R3000 => Self::R3000,
            pe::IMAGE_FILE_MACHINE_R4000 => Self::R4000,
            pe::IMAGE_FILE_MACHINE_R10000 => Self::R10000,
            pe::IMAGE_FILE_MACHINE_RISCV32 => Self::RiscV32,
            pe::IMAGE_FILE_MACHINE_RISCV64 => Self::RiscV64,
            pe::IMAGE_FILE_MACHINE_RISCV128 => Self::RiscV128,
            pe::IMAGE_FILE_MACHINE_SH3 => Self::Sh3,
            pe::IMAGE_FILE_MACHINE_SH3DSP => Self::Sh3Dsp,
            pe::IMAGE_FILE_MACHINE_SH4 => Self::Sh4,
            pe::IMAGE_FILE_MACHINE_SH5 => Self::Sh5,
            pe::IMAGE_FILE_MACHINE_THUMB => Self::Thumb,
            pe::IMAGE_FILE_MACHINE_WCEMIPSV2 => Self::WceMipsV2,
            o => return Err(TryFromImageFileMachineError(o)),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct MachineDisplay(u16);

impl MachineDisplay {
    const fn as_str(&self) -> Option<&'static str> {
        Some(match self.0 {
            pe::IMAGE_FILE_MACHINE_UNKNOWN => stringify!(IMAGE_FILE_MACHINE_UNKNOWN),
            pe::IMAGE_FILE_MACHINE_ALPHA => stringify!(IMAGE_FILE_MACHINE_ALPHA),
            pe::IMAGE_FILE_MACHINE_ALPHA64 => stringify!(IMAGE_FILE_MACHINE_ALPHA64),
            pe::IMAGE_FILE_MACHINE_AM33 => stringify!(IMAGE_FILE_MACHINE_AM33),
            pe::IMAGE_FILE_MACHINE_AMD64 => stringify!(IMAGE_FILE_MACHINE_AMD64),
            pe::IMAGE_FILE_MACHINE_ARM => stringify!(IMAGE_FILE_MACHINE_ARM),
            pe::IMAGE_FILE_MACHINE_ARM64 => stringify!(IMAGE_FILE_MACHINE_ARM64),
            pe::IMAGE_FILE_MACHINE_ARM64EC => stringify!(IMAGE_FILE_MACHINE_ARM64EC),
            pe::IMAGE_FILE_MACHINE_ARM64X => stringify!(IMAGE_FILE_MACHINE_ARM64X),
            pe::IMAGE_FILE_MACHINE_ARMNT => stringify!(IMAGE_FILE_MACHINE_ARMNT),
            pe::IMAGE_FILE_MACHINE_EBC => stringify!(IMAGE_FILE_MACHINE_EBC),
            pe::IMAGE_FILE_MACHINE_I386 => stringify!(IMAGE_FILE_MACHINE_I386),
            pe::IMAGE_FILE_MACHINE_IA64 => stringify!(IMAGE_FILE_MACHINE_IA64),
            pe::IMAGE_FILE_MACHINE_M32R => stringify!(IMAGE_FILE_MACHINE_M32R),
            pe::IMAGE_FILE_MACHINE_MIPS16 => stringify!(IMAGE_FILE_MACHINE_MIPS16),
            pe::IMAGE_FILE_MACHINE_MIPSFPU => stringify!(IMAGE_FILE_MACHINE_MIPSFPU),
            pe::IMAGE_FILE_MACHINE_MIPSFPU16 => stringify!(IMAGE_FILE_MACHINE_MIPSFPU16),
            pe::IMAGE_FILE_MACHINE_POWERPC => stringify!(IMAGE_FILE_MACHINE_POWERPC),
            pe::IMAGE_FILE_MACHINE_POWERPCFP => stringify!(IMAGE_FILE_MACHINE_POWERPCFP),
            pe::IMAGE_FILE_MACHINE_R3000 => stringify!(IMAGE_FILE_MACHINE_R3000),
            pe::IMAGE_FILE_MACHINE_R4000 => stringify!(IMAGE_FILE_MACHINE_R4000),
            pe::IMAGE_FILE_MACHINE_R10000 => stringify!(IMAGE_FILE_MACHINE_R10000),
            pe::IMAGE_FILE_MACHINE_RISCV32 => stringify!(IMAGE_FILE_MACHINE_RISCV32),
            pe::IMAGE_FILE_MACHINE_RISCV64 => stringify!(IMAGE_FILE_MACHINE_RISCV64),
            pe::IMAGE_FILE_MACHINE_RISCV128 => stringify!(IMAGE_FILE_MACHINE_RISCV128),
            pe::IMAGE_FILE_MACHINE_SH3 => stringify!(IMAGE_FILE_MACHINE_SH3),
            pe::IMAGE_FILE_MACHINE_SH3DSP => stringify!(IMAGE_FILE_MACHINE_SH3DSP),
            pe::IMAGE_FILE_MACHINE_SH4 => stringify!(IMAGE_FILE_MACHINE_SH4),
            pe::IMAGE_FILE_MACHINE_SH5 => stringify!(IMAGE_FILE_MACHINE_SH5),
            pe::IMAGE_FILE_MACHINE_THUMB => stringify!(IMAGE_FILE_MACHINE_THUMB),
            pe::IMAGE_FILE_MACHINE_WCEMIPSV2 => stringify!(IMAGE_FILE_MACHINE_WCEMIPSV2),
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CoffFlags(u16);

bitflags! {
    impl CoffFlags: u16 {
        const RelocsStripped = pe::IMAGE_FILE_RELOCS_STRIPPED;
        const ExecutableImage = pe::IMAGE_FILE_EXECUTABLE_IMAGE;
        const LineNumsStripped = pe::IMAGE_FILE_LINE_NUMS_STRIPPED;
        const LocalSymsStripped = pe::IMAGE_FILE_LOCAL_SYMS_STRIPPED;
        const LargeAddressAware = pe::IMAGE_FILE_LARGE_ADDRESS_AWARE;
        const BytesReversedLo = pe::IMAGE_FILE_BYTES_REVERSED_LO;
        const ThirtyTwoBitMachine = pe::IMAGE_FILE_32BIT_MACHINE;
        const DebugStripped = pe::IMAGE_FILE_DEBUG_STRIPPED;
        const RemovableRunFromSwap = pe::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP;
        const NetRunFromSwap = pe::IMAGE_FILE_NET_RUN_FROM_SWAP;
        const System = pe::IMAGE_FILE_SYSTEM;
        const Dll = pe::IMAGE_FILE_DLL;
        const UpSystemOnly = pe::IMAGE_FILE_UP_SYSTEM_ONLY;
        const BytesReversedHi = pe::IMAGE_FILE_BYTES_REVERSED_HI;

        // Allow externally set flags
        const _ = !0;
    }
}

/// Characteristics from COFF section headers.
///
/// The characteristic field is a hybrid of bit flags and numeric values.
/// The bit flags portion is also categorized. Each category can be queried
/// separately through various methods on this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SectionFlags(u32);

bitflags! {
    impl SectionFlags: u32 {
        const TypeNoPad = pe::IMAGE_SCN_TYPE_NO_PAD;
        const CntCode = pe::IMAGE_SCN_CNT_CODE;
        const CntInitializedData = pe::IMAGE_SCN_CNT_INITIALIZED_DATA;
        const CntUninitializedData = pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA;
        const LnkOther = pe::IMAGE_SCN_LNK_OTHER;
        const LnkInfo = pe::IMAGE_SCN_LNK_INFO;
        const LnkRemove = pe::IMAGE_SCN_LNK_REMOVE;
        const LnkComdat = pe::IMAGE_SCN_LNK_COMDAT;
        const GpRel = pe::IMAGE_SCN_GPREL;
        // Alignment is numeric not flags
        const LnkNRelocOvfl = pe::IMAGE_SCN_LNK_NRELOC_OVFL;
        const MemDiscardable = pe::IMAGE_SCN_MEM_DISCARDABLE;
        const MemNotCached = pe::IMAGE_SCN_MEM_NOT_CACHED;
        const MemNotPaged = pe::IMAGE_SCN_MEM_NOT_PAGED;
        const MemShared = pe::IMAGE_SCN_MEM_SHARED;
        const MemExecute = pe::IMAGE_SCN_MEM_EXECUTE;
        const MemRead = pe::IMAGE_SCN_MEM_READ;
        const MemWrite = pe::IMAGE_SCN_MEM_WRITE;

        // Allow externally set flags
        const _ = !0;
    }
}

const SECTION_FLAGS_ALIGN_SHIFT: usize = 0x14;
const SECTION_FLAGS_ALIGN_MASK: u32 = 0xf;

impl SectionFlags {
    /// Returns the alignment from the section alignment flags or 0 if unset
    pub const fn alignment(&self) -> usize {
        let align = (self.bits() >> SECTION_FLAGS_ALIGN_SHIFT) & SECTION_FLAGS_ALIGN_MASK;
        if align != 0 {
            2usize.pow(align - 1)
        } else {
            align as usize
        }
    }

    /// Sets the alignment flag to match `align`.
    ///
    /// Valid alignment values are 0, 1 or any power of two <= 8192.
    /// Setting the align value to 0 will clear all alignment flags.
    ///
    /// # Panics
    /// Function will panic if an invalid alignment value is passed in.
    pub const fn set_alignment(&mut self, align: usize) {
        // Clear previous flags
        self.0 &= !(SECTION_FLAGS_ALIGN_MASK << SECTION_FLAGS_ALIGN_SHIFT);

        if align == 0 {
            return;
        }

        assert!(
            align.is_power_of_two(),
            "align value for SectionFlags::set_alignment() must be a power of two"
        );
        assert!(
            align <= 8192,
            "align value for SectionFlags::set_alignment() must be within range 0 <= align <= 8192"
        );
        self.0 |= (align.ilog2() + 1) << SECTION_FLAGS_ALIGN_SHIFT;
    }

    /// Returns a new set of flags with only the `IMAGE_SCN_MEM_*` flags set
    pub const fn memory_flags(self) -> Self {
        SectionFlags(self.0 & (0xe << 24))
    }

    /// Returns a new set of flags with only the `IMAGE_SCN_CNT_*` flags set.
    pub const fn contents_flags(self) -> Self {
        SectionFlags(self.0 & (0xe << 4))
    }

    /// Returns the union of `self.memory_flags() | self.contents_flags()`.
    ///
    /// This is used for determining output section flags from an input section.
    pub const fn kind_flags(self) -> Self {
        Self(self.memory_flags().0 | self.contents_flags().0)
    }
}

#[derive(Debug, Default)]
#[repr(transparent)]
pub struct SymbolTable<'a>(coff::SymbolTable<'a>);

impl<'a> SymbolTable<'a> {
    pub fn parse(header: &pe::ImageFileHeader, data: &'a [u8]) -> object::Result<Self> {
        match coff::SymbolTable::parse(header, data) {
            Ok(table) => Ok(Self(table)),
            Err(e) => Err(e),
        }
    }

    pub fn strings(&self) -> object::read::StringTable<'a> {
        self.0.strings()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter<'table>(&'table self) -> impl Iterator<Item = (SymbolIndex, CoffSymbolRef<'a>)> {
        self.0
            .iter()
            .map(|(index, symbol)| (index, CoffSymbolRef(symbol)))
    }

    pub fn symbol(&self, index: SymbolIndex) -> object::Result<CoffSymbolRef<'a>> {
        match self.0.symbol(index) {
            Ok(symbol) => Ok(CoffSymbolRef(symbol)),
            Err(e) => Err(e),
        }
    }

    pub fn aux_section(&self, index: SymbolIndex) -> object::Result<&'a pe::ImageAuxSymbolSection> {
        self.0.aux_section(index)
    }

    pub fn aux_weak_external(
        &self,
        index: SymbolIndex,
    ) -> object::Result<&'a pe::ImageAuxSymbolWeak> {
        self.0.aux_weak_external(index)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct CoffSymbolRef<'a>(&'a pe::ImageSymbol);

impl<'a> CoffSymbolRef<'a> {
    pub fn new(inner: &'a object::pe::ImageSymbol) -> Self {
        Self(inner)
    }

    pub fn image_symbol(&self) -> &'a object::pe::ImageSymbol {
        self.0
    }

    /// Returns the number of auxiliary symbols following this symbol
    pub fn number_of_aux_symbols(&self) -> u8 {
        self.0.number_of_aux_symbols
    }

    /// Gets the name of the symbol using the specified string table.
    pub fn name_bytes<'data>(
        &self,
        strings: object::read::StringTable<'data>,
    ) -> object::Result<&'data [u8]>
    where
        'a: 'data,
    {
        self.0.name(strings)
    }

    pub fn has_aux_file_name(&self) -> bool {
        self.number_of_aux_symbols() > 0 && self.storage_class() == pe::IMAGE_SYM_CLASS_FILE
    }

    pub fn has_aux_function(&self) -> bool {
        self.number_of_aux_symbols() > 0
            && self.complex_type() == pe::IMAGE_SYM_DTYPE_FUNCTION
            && (self.storage_class() == pe::IMAGE_SYM_CLASS_EXTERNAL
                || self.storage_class() == pe::IMAGE_SYM_CLASS_STATIC)
    }

    pub fn has_aux_section(&self) -> bool {
        self.number_of_aux_symbols() > 0
            && self.storage_class() == pe::IMAGE_SYM_CLASS_STATIC
            && self.typ() == 0
    }

    pub fn has_aux_weak_external(&self) -> bool {
        self.number_of_aux_symbols() > 0
            && self.is_weak()
            && self.section_number() == pe::IMAGE_SYM_UNDEFINED as u16
            && self.value() == 0
    }
}

impl Symbol for CoffSymbolRef<'_> {
    fn value(&self) -> u32 {
        self.0.value.get(object::LittleEndian)
    }

    fn section_number(&self) -> u16 {
        self.0.section_number.get(object::LittleEndian)
    }

    fn typ(&self) -> u16 {
        self.0.typ.get(object::LittleEndian)
    }

    fn storage_class(&self) -> u8 {
        self.0.storage_class
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

#[cfg(test)]
mod tests {
    use super::ImageFileMachine;

    #[test]
    fn machine_formatting() {
        // Test only the constants and formatting that is actually used in the
        // program
        let tests = [
            (ImageFileMachine::Amd64, "IMAGE_FILE_MACHINE_AMD64"),
            (ImageFileMachine::I386, "IMAGE_FILE_MACHINE_I386"),
        ];

        for (machine, expected) in tests {
            let formatted = format!("{machine}");
            assert_eq!(formatted, expected);
        }
    }
}
