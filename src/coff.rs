use bitflags::{Flag, Flags};
use object::pe::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM, IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARM64EC, IMAGE_FILE_MACHINE_ARM64X, IMAGE_FILE_MACHINE_ARMNT,
    IMAGE_FILE_MACHINE_EBC, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64,
    IMAGE_FILE_MACHINE_RISCV32, IMAGE_FILE_MACHINE_RISCV64, IMAGE_FILE_MACHINE_RISCV128,
    IMAGE_FILE_MACHINE_THUMB, IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_SCN_ALIGN_1BYTES,
    IMAGE_SCN_ALIGN_2BYTES, IMAGE_SCN_ALIGN_4BYTES, IMAGE_SCN_ALIGN_8BYTES, IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_LNK_COMDAT,
    IMAGE_SCN_LNK_NRELOC_OVFL, IMAGE_SCN_LNK_OTHER, IMAGE_SCN_LNK_REMOVE,
    IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    IMAGE_SCN_TYPE_NO_PAD, IMAGE_SYM_CLASS_CLR_TOKEN, IMAGE_SYM_CLASS_END_OF_FUNCTION,
    IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_EXTERNAL_DEF, IMAGE_SYM_CLASS_FILE,
    IMAGE_SYM_CLASS_LABEL, IMAGE_SYM_CLASS_NULL, IMAGE_SYM_CLASS_SECTION, IMAGE_SYM_CLASS_STATIC,
    IMAGE_SYM_CLASS_WEAK_EXTERNAL,
};

/// Open enum representation for PE `IMAGE_FILE_MACHINE_*` constants.
///
/// The [`std::fmt::Display`] formatting traits will display the full
/// `IMAGE_FILE_MACHINE_*` string if known or pass through to the `u16`
/// formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ImageFileMachine(pub u16);

#[allow(non_upper_case_globals)]
impl ImageFileMachine {
    pub const Unknown: Self = Self(IMAGE_FILE_MACHINE_UNKNOWN);
    pub const Amd64: Self = Self(IMAGE_FILE_MACHINE_AMD64);
    pub const Arm: Self = Self(IMAGE_FILE_MACHINE_ARM);
    pub const Arm64: Self = Self(IMAGE_FILE_MACHINE_ARM64);
    pub const Arm64Ec: Self = Self(IMAGE_FILE_MACHINE_ARM64EC);
    pub const Arm64X: Self = Self(IMAGE_FILE_MACHINE_ARM64X);
    pub const ArmNt: Self = Self(IMAGE_FILE_MACHINE_ARMNT);
    pub const Ebc: Self = Self(IMAGE_FILE_MACHINE_EBC);
    pub const I386: Self = Self(IMAGE_FILE_MACHINE_I386);
    pub const Ia64: Self = Self(IMAGE_FILE_MACHINE_IA64);
    pub const RiscV32: Self = Self(IMAGE_FILE_MACHINE_RISCV32);
    pub const RiscV64: Self = Self(IMAGE_FILE_MACHINE_RISCV64);
    pub const RiscV128: Self = Self(IMAGE_FILE_MACHINE_RISCV128);
    pub const Thumb: Self = Self(IMAGE_FILE_MACHINE_THUMB);
}

impl ImageFileMachine {
    /// Alternative method for getting the `u16` value instead of `.0`
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    pub const fn fmt_hex(self) -> ImageFileMachineHexFormatter {
        ImageFileMachineHexFormatter(self)
    }
}

impl std::fmt::Display for ImageFileMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(s) = MachineRepr(*self).as_str() {
            f.write_str(s)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// Display representation of [`ImageFileMachine`] which displays the string
/// version of the constant if known or an '0x' prefixed hex number if unknown.
#[derive(Debug)]
#[repr(transparent)]
pub struct ImageFileMachineHexFormatter(ImageFileMachine);

impl std::fmt::Display for ImageFileMachineHexFormatter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(s) = MachineRepr(self.0).as_str() {
            f.write_str(s)
        } else {
            write!(f, "{:#x}", self.0.as_u16())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct MachineRepr(ImageFileMachine);

impl MachineRepr {
    const fn as_str(&self) -> Option<&'static str> {
        Some(match self.0.as_u16() {
            IMAGE_FILE_MACHINE_UNKNOWN => stringify!(IMAGE_FILE_MACHINE_UNKNOWN),
            IMAGE_FILE_MACHINE_AMD64 => stringify!(IMAGE_FILE_MACHINE_AMD64),
            IMAGE_FILE_MACHINE_ARM => stringify!(IMAGE_FILE_MACHINE_ARM),
            IMAGE_FILE_MACHINE_ARM64 => stringify!(IMAGE_FILE_MACHINE_ARM64),
            IMAGE_FILE_MACHINE_ARM64EC => stringify!(IMAGE_FILE_MACHINE_ARM64EC),
            IMAGE_FILE_MACHINE_ARM64X => stringify!(IMAGE_FILE_MACHINE_ARM64X),
            IMAGE_FILE_MACHINE_ARMNT => stringify!(IMAGE_FILE_MACHINE_ARMNT),
            IMAGE_FILE_MACHINE_EBC => stringify!(IMAGE_FILE_MACHINE_EBC),
            IMAGE_FILE_MACHINE_I386 => stringify!(IMAGE_FILE_MACHINE_I386),
            IMAGE_FILE_MACHINE_IA64 => stringify!(IMAGE_FILE_MACHINE_IA64),
            IMAGE_FILE_MACHINE_RISCV32 => stringify!(IMAGE_FILE_MACHINE_RISCV32),
            IMAGE_FILE_MACHINE_RISCV64 => stringify!(IMAGE_FILE_MACHINE_RISCV64),
            IMAGE_FILE_MACHINE_RISCV128 => stringify!(IMAGE_FILE_MACHINE_RISCV128),
            IMAGE_FILE_MACHINE_THUMB => stringify!(IMAGE_FILE_MACHINE_THUMB),
            _ => return None,
        })
    }
}

pub type SectionIndex = object::read::SectionIndex;
pub type SectionTable<'a> = object::read::coff::SectionTable<'a>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SectionFlags(u32);

#[allow(non_upper_case_globals)]
impl SectionFlags {
    pub const TypeNoPad: Self = Self(IMAGE_SCN_TYPE_NO_PAD);
    pub const CntCode: Self = Self(IMAGE_SCN_CNT_CODE);
    pub const CntInitializedData: Self = Self(IMAGE_SCN_CNT_INITIALIZED_DATA);
    pub const CntUninitializedData: Self = Self(IMAGE_SCN_CNT_UNINITIALIZED_DATA);
    pub const LnkOther: Self = Self(IMAGE_SCN_LNK_OTHER);
    pub const LnkRemove: Self = Self(IMAGE_SCN_LNK_REMOVE);
    pub const LnkComdat: Self = Self(IMAGE_SCN_LNK_COMDAT);
    pub const Align1Bytes: Self = Self(IMAGE_SCN_ALIGN_1BYTES);
    pub const Align2Bytes: Self = Self(IMAGE_SCN_ALIGN_2BYTES);
    pub const Align4Bytes: Self = Self(IMAGE_SCN_ALIGN_4BYTES);
    pub const Align8Bytes: Self = Self(IMAGE_SCN_ALIGN_8BYTES);
    pub const LnkNRelocOvfl: Self = Self(IMAGE_SCN_LNK_NRELOC_OVFL);
    pub const MemDiscardable: Self = Self(IMAGE_SCN_MEM_DISCARDABLE);
    pub const MemExecute: Self = Self(IMAGE_SCN_MEM_EXECUTE);
    pub const MemRead: Self = Self(IMAGE_SCN_MEM_READ);
    pub const MemWrite: Self = Self(IMAGE_SCN_MEM_WRITE);
}

impl Flags for SectionFlags {
    const FLAGS: &'static [Flag<Self>] = &[];

    type Bits = u32;

    fn bits(&self) -> Self::Bits {
        self.0
    }

    fn from_bits_retain(bits: Self::Bits) -> Self {
        Self(bits)
    }
}

pub type SymbolIndex = object::read::SymbolIndex;
pub type SymbolTable<'a> = object::read::coff::SymbolTable<'a>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SymbolSectionNumber(u16);

#[allow(non_upper_case_globals)]
impl SymbolSectionNumber {
    pub const Undefined: Self = Self(0);
    pub const Absolute: Self = Self(u16::MAX - 1);
    pub const Debug: Self = Self(u16::MAX - 2);
}

impl SymbolSectionNumber {
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    pub const fn index(self) -> Option<SectionIndex> {
        if self.0 > Self::Undefined.0 && self.0 < Self::Debug.0 {
            Some(object::SectionIndex((self.0 - 1) as usize))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct StorageClass(u8);

#[allow(non_upper_case_globals)]
impl StorageClass {
    pub const EndOfFunction: Self = Self(IMAGE_SYM_CLASS_END_OF_FUNCTION);
    pub const Null: Self = Self(IMAGE_SYM_CLASS_NULL);
    pub const External: Self = Self(IMAGE_SYM_CLASS_EXTERNAL);
    pub const Static: Self = Self(IMAGE_SYM_CLASS_STATIC);
    pub const ExternalDef: Self = Self(IMAGE_SYM_CLASS_EXTERNAL_DEF);
    pub const Label: Self = Self(IMAGE_SYM_CLASS_LABEL);
    pub const File: Self = Self(IMAGE_SYM_CLASS_FILE);
    pub const Section: Self = Self(IMAGE_SYM_CLASS_SECTION);
    pub const WeakExternal: Self = Self(IMAGE_SYM_CLASS_WEAK_EXTERNAL);
    pub const ClrToken: Self = Self(IMAGE_SYM_CLASS_CLR_TOKEN);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ComdatSelection {
    NoDuplicates = 1,
    Any = 2,
    SameSize = 3,
    ExactMatch = 4,
    Largest = 6,
}

/// @feat.00 symbol flags.
///
/// Flags are from
/// https://github.com/llvm/llvm-project/blob/544c300f4396119bf5a2ea4239d32774908a882d/llvm/include/llvm/BinaryFormat/COFF.h#L845.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Feat00Flags(u32);

#[allow(non_upper_case_globals)]
impl Feat00Flags {
    /// Object is compatible with /safeseh.
    pub const SafeSEH: Self = Self(1);

    /// Object was compiled with /GS.
    pub const GuardStack: Self = Self(0x100);

    /// Object was compiled with /sdl.
    pub const SDL: Self = Self(0x200);

    /// Object was compiled with /guard:cf.
    pub const GuardCF: Self = Self(0x800);

    /// Object was compiled with /guard:ehcont.
    pub const GuardEHCont: Self = Self(0x4000);

    /// Object was compiled with /kernel.
    pub const Kernel: Self = Self(0x40000000);
}

impl Flags for Feat00Flags {
    const FLAGS: &'static [bitflags::Flag<Self>] = &[
        Flag::new(stringify!(SafeSEH), Self::SafeSEH),
        Flag::new(stringify!(GuardStack), Self::GuardStack),
        Flag::new(stringify!(SDL), Self::SDL),
        Flag::new(stringify!(GuardCF), Self::GuardCF),
        Flag::new(stringify!(GuardEHCont), Self::GuardEHCont),
        Flag::new(stringify!(Kernel), Self::Kernel),
    ];

    type Bits = u32;

    fn bits(&self) -> Self::Bits {
        self.0
    }

    fn from_bits_retain(bits: Self::Bits) -> Self {
        Self(bits)
    }
}

pub type StringTable<'a> = object::read::StringTable<'a>;
