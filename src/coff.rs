//! Low-level COFF handling module.
//!
//! This acts as a supplement to the [object](https://github.com/gimli-rs/object)
//! crate.
//!
//! Most of the items here are [newtypes](https://doc.rust-lang.org/rust-by-example/generics/new_types.html)
//! and strongly typed bit flags for handling PE characteristics.
//!
//! This module contains a lot of boilerplate stuff due to the nature of new
//! types and bit flags.

use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use object::{
    SectionIndex,
    pe::{
        IMAGE_COMDAT_SELECT_ANY, IMAGE_COMDAT_SELECT_EXACT_MATCH, IMAGE_COMDAT_SELECT_LARGEST,
        IMAGE_COMDAT_SELECT_NODUPLICATES, IMAGE_COMDAT_SELECT_SAME_SIZE, IMAGE_FILE_MACHINE_ALPHA,
        IMAGE_FILE_MACHINE_ALPHA64, IMAGE_FILE_MACHINE_AM33, IMAGE_FILE_MACHINE_AMD64,
        IMAGE_FILE_MACHINE_ARM, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARM64EC,
        IMAGE_FILE_MACHINE_ARM64X, IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_EBC,
        IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64, IMAGE_FILE_MACHINE_M32R,
        IMAGE_FILE_MACHINE_MIPS16, IMAGE_FILE_MACHINE_MIPSFPU, IMAGE_FILE_MACHINE_MIPSFPU16,
        IMAGE_FILE_MACHINE_POWERPC, IMAGE_FILE_MACHINE_POWERPCFP, IMAGE_FILE_MACHINE_R3000,
        IMAGE_FILE_MACHINE_R4000, IMAGE_FILE_MACHINE_R10000, IMAGE_FILE_MACHINE_RISCV32,
        IMAGE_FILE_MACHINE_RISCV64, IMAGE_FILE_MACHINE_RISCV128, IMAGE_FILE_MACHINE_SH3,
        IMAGE_FILE_MACHINE_SH3DSP, IMAGE_FILE_MACHINE_SH4, IMAGE_FILE_MACHINE_SH5,
        IMAGE_FILE_MACHINE_THUMB, IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_WCEMIPSV2,
        IMAGE_SCN_ALIGN_1BYTES, IMAGE_SCN_ALIGN_2BYTES, IMAGE_SCN_ALIGN_4BYTES,
        IMAGE_SCN_ALIGN_8BYTES, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
        IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_LNK_COMDAT, IMAGE_SCN_LNK_NRELOC_OVFL,
        IMAGE_SCN_LNK_OTHER, IMAGE_SCN_LNK_REMOVE, IMAGE_SCN_MEM_DISCARDABLE,
        IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SCN_TYPE_NO_PAD,
        IMAGE_SYM_CLASS_ARGUMENT, IMAGE_SYM_CLASS_AUTOMATIC, IMAGE_SYM_CLASS_BIT_FIELD,
        IMAGE_SYM_CLASS_BLOCK, IMAGE_SYM_CLASS_CLR_TOKEN, IMAGE_SYM_CLASS_END_OF_FUNCTION,
        IMAGE_SYM_CLASS_END_OF_STRUCT, IMAGE_SYM_CLASS_ENUM_TAG, IMAGE_SYM_CLASS_EXTERNAL,
        IMAGE_SYM_CLASS_EXTERNAL_DEF, IMAGE_SYM_CLASS_FILE, IMAGE_SYM_CLASS_FUNCTION,
        IMAGE_SYM_CLASS_LABEL, IMAGE_SYM_CLASS_MEMBER_OF_ENUM, IMAGE_SYM_CLASS_MEMBER_OF_STRUCT,
        IMAGE_SYM_CLASS_MEMBER_OF_UNION, IMAGE_SYM_CLASS_NULL, IMAGE_SYM_CLASS_REGISTER,
        IMAGE_SYM_CLASS_REGISTER_PARAM, IMAGE_SYM_CLASS_SECTION, IMAGE_SYM_CLASS_STATIC,
        IMAGE_SYM_CLASS_STRUCT_TAG, IMAGE_SYM_CLASS_TYPE_DEFINITION,
        IMAGE_SYM_CLASS_UNDEFINED_LABEL, IMAGE_SYM_CLASS_UNDEFINED_STATIC,
        IMAGE_SYM_CLASS_UNION_TAG, IMAGE_SYM_CLASS_WEAK_EXTERNAL,
    },
};

#[derive(Debug, thiserror::Error)]
#[error("unknown 'IMAGE_FILE_MACHINE_*' value '{}'", .0)]
pub struct TryFromImageFileMachineError(u16);

/// PE `IMAGE_FILE_MACHINE_*` constants.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, TryFromPrimitive, IntoPrimitive)]
#[num_enum(error_type(name = TryFromImageFileMachineError, constructor = TryFromImageFileMachineError))]
#[repr(u16)]
pub enum ImageFileMachine {
    #[default]
    Unknown = IMAGE_FILE_MACHINE_UNKNOWN,

    Alpha = IMAGE_FILE_MACHINE_ALPHA,
    Alpha64 = IMAGE_FILE_MACHINE_ALPHA64,
    Am33 = IMAGE_FILE_MACHINE_AM33,
    Amd64 = IMAGE_FILE_MACHINE_AMD64,
    Arm = IMAGE_FILE_MACHINE_ARM,
    Arm64 = IMAGE_FILE_MACHINE_ARM64,
    Arm64Ec = IMAGE_FILE_MACHINE_ARM64EC,
    Arm64X = IMAGE_FILE_MACHINE_ARM64X,
    ArmNt = IMAGE_FILE_MACHINE_ARMNT,
    Ebc = IMAGE_FILE_MACHINE_EBC,
    I386 = IMAGE_FILE_MACHINE_I386,
    Ia64 = IMAGE_FILE_MACHINE_IA64,
    M32R = IMAGE_FILE_MACHINE_M32R,
    Mips16 = IMAGE_FILE_MACHINE_MIPS16,
    MipsFpu = IMAGE_FILE_MACHINE_MIPSFPU,
    MipsFpu16 = IMAGE_FILE_MACHINE_MIPSFPU16,
    PowerPc = IMAGE_FILE_MACHINE_POWERPC,
    PowerPcFp = IMAGE_FILE_MACHINE_POWERPCFP,
    R3000 = IMAGE_FILE_MACHINE_R3000,
    R4000 = IMAGE_FILE_MACHINE_R4000,
    R10000 = IMAGE_FILE_MACHINE_R10000,
    RiscV32 = IMAGE_FILE_MACHINE_RISCV32,
    RiscV64 = IMAGE_FILE_MACHINE_RISCV64,
    RiscV128 = IMAGE_FILE_MACHINE_RISCV128,
    Sh3 = IMAGE_FILE_MACHINE_SH3,
    Sh3Dsp = IMAGE_FILE_MACHINE_SH3DSP,
    Sh4 = IMAGE_FILE_MACHINE_SH4,
    Sh5 = IMAGE_FILE_MACHINE_SH5,
    Thumb = IMAGE_FILE_MACHINE_THUMB,
    WceMipsV2 = IMAGE_FILE_MACHINE_WCEMIPSV2,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct MachineDisplay(u16);

impl MachineDisplay {
    const fn as_str(&self) -> Option<&'static str> {
        Some(match self.0 {
            IMAGE_FILE_MACHINE_UNKNOWN => stringify!(IMAGE_FILE_MACHINE_UNKNOWN),
            IMAGE_FILE_MACHINE_ALPHA => stringify!(IMAGE_FILE_MACHINE_ALPHA),
            IMAGE_FILE_MACHINE_ALPHA64 => stringify!(IMAGE_FILE_MACHINE_ALPHA64),
            IMAGE_FILE_MACHINE_AM33 => stringify!(IMAGE_FILE_MACHINE_AM33),
            IMAGE_FILE_MACHINE_AMD64 => stringify!(IMAGE_FILE_MACHINE_AMD64),
            IMAGE_FILE_MACHINE_ARM => stringify!(IMAGE_FILE_MACHINE_ARM),
            IMAGE_FILE_MACHINE_ARM64 => stringify!(IMAGE_FILE_MACHINE_ARM64),
            IMAGE_FILE_MACHINE_ARM64EC => stringify!(IMAGE_FILE_MACHINE_ARM64EC),
            IMAGE_FILE_MACHINE_ARM64X => stringify!(IMAGE_FILE_MACHINE_ARM64X),
            IMAGE_FILE_MACHINE_ARMNT => stringify!(IMAGE_FILE_MACHINE_ARMNT),
            IMAGE_FILE_MACHINE_EBC => stringify!(IMAGE_FILE_MACHINE_EBC),
            IMAGE_FILE_MACHINE_I386 => stringify!(IMAGE_FILE_MACHINE_I386),
            IMAGE_FILE_MACHINE_IA64 => stringify!(IMAGE_FILE_MACHINE_IA64),
            IMAGE_FILE_MACHINE_M32R => stringify!(IMAGE_FILE_MACHINE_M32R),
            IMAGE_FILE_MACHINE_MIPS16 => stringify!(IMAGE_FILE_MACHINE_MIPS16),
            IMAGE_FILE_MACHINE_MIPSFPU => stringify!(IMAGE_FILE_MACHINE_MIPSFPU),
            IMAGE_FILE_MACHINE_MIPSFPU16 => stringify!(IMAGE_FILE_MACHINE_MIPSFPU16),
            IMAGE_FILE_MACHINE_POWERPC => stringify!(IMAGE_FILE_MACHINE_POWERPC),
            IMAGE_FILE_MACHINE_POWERPCFP => stringify!(IMAGE_FILE_MACHINE_POWERPCFP),
            IMAGE_FILE_MACHINE_R3000 => stringify!(IMAGE_FILE_MACHINE_R3000),
            IMAGE_FILE_MACHINE_R4000 => stringify!(IMAGE_FILE_MACHINE_R4000),
            IMAGE_FILE_MACHINE_R10000 => stringify!(IMAGE_FILE_MACHINE_R10000),
            IMAGE_FILE_MACHINE_RISCV32 => stringify!(IMAGE_FILE_MACHINE_RISCV32),
            IMAGE_FILE_MACHINE_RISCV64 => stringify!(IMAGE_FILE_MACHINE_RISCV64),
            IMAGE_FILE_MACHINE_RISCV128 => stringify!(IMAGE_FILE_MACHINE_RISCV128),
            IMAGE_FILE_MACHINE_SH3 => stringify!(IMAGE_FILE_MACHINE_SH3),
            IMAGE_FILE_MACHINE_SH3DSP => stringify!(IMAGE_FILE_MACHINE_SH3DSP),
            IMAGE_FILE_MACHINE_SH4 => stringify!(IMAGE_FILE_MACHINE_SH4),
            IMAGE_FILE_MACHINE_SH5 => stringify!(IMAGE_FILE_MACHINE_SH5),
            IMAGE_FILE_MACHINE_THUMB => stringify!(IMAGE_FILE_MACHINE_THUMB),
            IMAGE_FILE_MACHINE_WCEMIPSV2 => stringify!(IMAGE_FILE_MACHINE_WCEMIPSV2),
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SectionFlags(u32);

bitflags! {
    impl SectionFlags: u32 {
        const TypeNoPad = IMAGE_SCN_TYPE_NO_PAD;
        const CntCode = IMAGE_SCN_CNT_CODE;
        const CntInitializedData = IMAGE_SCN_CNT_INITIALIZED_DATA;
        const CntUninitializedData = IMAGE_SCN_CNT_UNINITIALIZED_DATA;
        const LnkOther = IMAGE_SCN_LNK_OTHER;
        const LnkRemove = IMAGE_SCN_LNK_REMOVE;
        const LnkComdat = IMAGE_SCN_LNK_COMDAT;
        const Align1Bytes = IMAGE_SCN_ALIGN_1BYTES;
        const Align2Bytes = IMAGE_SCN_ALIGN_2BYTES;
        const Align4Bytes = IMAGE_SCN_ALIGN_4BYTES;
        const Align8Bytes = IMAGE_SCN_ALIGN_8BYTES;
        const LnkNRelocOvfl = IMAGE_SCN_LNK_NRELOC_OVFL;
        const MemDiscardable = IMAGE_SCN_MEM_DISCARDABLE;
        const MemExecute = IMAGE_SCN_MEM_EXECUTE;
        const MemRead = IMAGE_SCN_MEM_READ;
        const MemWrite = IMAGE_SCN_MEM_WRITE;
    }
}

/// A section **number** for a symbol
///
/// The section number is used to denote undefined, absolute, or debug symbols
/// while also containing the section for a symbol definition.
///
/// Section references in the symbol table are 1-based indicies instead of 0-based.
/// This is used to help prevent issues when using these section references to
/// index into the symbol table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SectionNumber(u16);

#[allow(non_upper_case_globals)]
impl SectionNumber {
    pub const Undefined: Self = Self(0);
    pub const Absolute: Self = Self(u16::MAX - 1);
    pub const Debug: Self = Self(u16::MAX - 2);
}

impl From<u16> for SectionNumber {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl SectionNumber {
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    pub const fn index(self) -> Option<SectionIndex> {
        if self.0 > Self::Undefined.0 && self.0 < Self::Debug.0 {
            Some(SectionIndex((self.0 - 1) as usize))
        } else {
            None
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown 'IMAGE_SYM_CLASS_*' value '{}'", .0)]
pub struct TryFromStorageClassError(u8);

/// Symbol storage class values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TryFromPrimitive, IntoPrimitive)]
#[num_enum(error_type(name = TryFromStorageClassError, constructor = TryFromStorageClassError))]
#[repr(u8)]
pub enum StorageClass {
    EndOfFunction = IMAGE_SYM_CLASS_END_OF_FUNCTION,
    Null = IMAGE_SYM_CLASS_NULL,
    Automatic = IMAGE_SYM_CLASS_AUTOMATIC,
    External = IMAGE_SYM_CLASS_EXTERNAL,
    Static = IMAGE_SYM_CLASS_STATIC,
    Register = IMAGE_SYM_CLASS_REGISTER,
    ExternalDef = IMAGE_SYM_CLASS_EXTERNAL_DEF,
    Label = IMAGE_SYM_CLASS_LABEL,
    UndefinedLabel = IMAGE_SYM_CLASS_UNDEFINED_LABEL,
    MemberOfStruct = IMAGE_SYM_CLASS_MEMBER_OF_STRUCT,
    Argument = IMAGE_SYM_CLASS_ARGUMENT,
    StructTag = IMAGE_SYM_CLASS_STRUCT_TAG,
    MemberOfUnion = IMAGE_SYM_CLASS_MEMBER_OF_UNION,
    UnionTag = IMAGE_SYM_CLASS_UNION_TAG,
    TypeDefinition = IMAGE_SYM_CLASS_TYPE_DEFINITION,
    UndefinedStatic = IMAGE_SYM_CLASS_UNDEFINED_STATIC,
    EnumTag = IMAGE_SYM_CLASS_ENUM_TAG,
    MemberOfEnum = IMAGE_SYM_CLASS_MEMBER_OF_ENUM,
    RegisterParam = IMAGE_SYM_CLASS_REGISTER_PARAM,
    BitField = IMAGE_SYM_CLASS_BIT_FIELD,
    Block = IMAGE_SYM_CLASS_BLOCK,
    Function = IMAGE_SYM_CLASS_FUNCTION,
    EndOfStruct = IMAGE_SYM_CLASS_END_OF_STRUCT,
    File = IMAGE_SYM_CLASS_FILE,
    Section = IMAGE_SYM_CLASS_SECTION,
    WeakExternal = IMAGE_SYM_CLASS_WEAK_EXTERNAL,
    ClrToken = IMAGE_SYM_CLASS_CLR_TOKEN,
}

#[derive(Debug, thiserror::Error)]
#[error("unknown 'IMAGE_COMDAT_SELECT_*' value '{}'", .0)]
pub struct TryFromComdatSelectionError(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TryFromPrimitive, IntoPrimitive)]
#[num_enum(error_type(name = TryFromComdatSelectionError, constructor = TryFromComdatSelectionError))]
#[repr(u8)]
pub enum ComdatSelection {
    NoDuplicates = IMAGE_COMDAT_SELECT_NODUPLICATES,
    Any = IMAGE_COMDAT_SELECT_ANY,
    SameSize = IMAGE_COMDAT_SELECT_SAME_SIZE,
    ExactMatch = IMAGE_COMDAT_SELECT_EXACT_MATCH,
    Largest = IMAGE_COMDAT_SELECT_LARGEST,
}

/// @feat.00 symbol flags.
///
/// Flags are from
/// https://github.com/llvm/llvm-project/blob/544c300f4396119bf5a2ea4239d32774908a882d/llvm/include/llvm/BinaryFormat/COFF.h#L845.
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
