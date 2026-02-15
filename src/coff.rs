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
use object::{
    SectionIndex,
    pe::{
        IMAGE_COMDAT_SELECT_ANY, IMAGE_COMDAT_SELECT_ASSOCIATIVE, IMAGE_COMDAT_SELECT_EXACT_MATCH,
        IMAGE_COMDAT_SELECT_LARGEST, IMAGE_COMDAT_SELECT_NODUPLICATES,
        IMAGE_COMDAT_SELECT_SAME_SIZE, IMAGE_FILE_32BIT_MACHINE, IMAGE_FILE_BYTES_REVERSED_HI,
        IMAGE_FILE_BYTES_REVERSED_LO, IMAGE_FILE_DEBUG_STRIPPED, IMAGE_FILE_DLL,
        IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_LARGE_ADDRESS_AWARE, IMAGE_FILE_LINE_NUMS_STRIPPED,
        IMAGE_FILE_LOCAL_SYMS_STRIPPED, IMAGE_FILE_MACHINE_ALPHA, IMAGE_FILE_MACHINE_ALPHA64,
        IMAGE_FILE_MACHINE_AM33, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM,
        IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARM64EC, IMAGE_FILE_MACHINE_ARM64X,
        IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_EBC, IMAGE_FILE_MACHINE_I386,
        IMAGE_FILE_MACHINE_IA64, IMAGE_FILE_MACHINE_M32R, IMAGE_FILE_MACHINE_MIPS16,
        IMAGE_FILE_MACHINE_MIPSFPU, IMAGE_FILE_MACHINE_MIPSFPU16, IMAGE_FILE_MACHINE_POWERPC,
        IMAGE_FILE_MACHINE_POWERPCFP, IMAGE_FILE_MACHINE_R3000, IMAGE_FILE_MACHINE_R4000,
        IMAGE_FILE_MACHINE_R10000, IMAGE_FILE_MACHINE_RISCV32, IMAGE_FILE_MACHINE_RISCV64,
        IMAGE_FILE_MACHINE_RISCV128, IMAGE_FILE_MACHINE_SH3, IMAGE_FILE_MACHINE_SH3DSP,
        IMAGE_FILE_MACHINE_SH4, IMAGE_FILE_MACHINE_SH5, IMAGE_FILE_MACHINE_THUMB,
        IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_WCEMIPSV2, IMAGE_FILE_NET_RUN_FROM_SWAP,
        IMAGE_FILE_RELOCS_STRIPPED, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, IMAGE_FILE_SYSTEM,
        IMAGE_FILE_UP_SYSTEM_ONLY, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
        IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_GPREL, IMAGE_SCN_LNK_COMDAT,
        IMAGE_SCN_LNK_INFO, IMAGE_SCN_LNK_NRELOC_OVFL, IMAGE_SCN_LNK_OTHER, IMAGE_SCN_LNK_REMOVE,
        IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_NOT_CACHED,
        IMAGE_SCN_MEM_NOT_PAGED, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_SHARED, IMAGE_SCN_MEM_WRITE,
        IMAGE_SCN_TYPE_NO_PAD, IMAGE_SYM_CLASS_ARGUMENT, IMAGE_SYM_CLASS_AUTOMATIC,
        IMAGE_SYM_CLASS_BIT_FIELD, IMAGE_SYM_CLASS_BLOCK, IMAGE_SYM_CLASS_CLR_TOKEN,
        IMAGE_SYM_CLASS_END_OF_FUNCTION, IMAGE_SYM_CLASS_END_OF_STRUCT, IMAGE_SYM_CLASS_ENUM_TAG,
        IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_EXTERNAL_DEF, IMAGE_SYM_CLASS_FILE,
        IMAGE_SYM_CLASS_FUNCTION, IMAGE_SYM_CLASS_LABEL, IMAGE_SYM_CLASS_MEMBER_OF_ENUM,
        IMAGE_SYM_CLASS_MEMBER_OF_STRUCT, IMAGE_SYM_CLASS_MEMBER_OF_UNION, IMAGE_SYM_CLASS_NULL,
        IMAGE_SYM_CLASS_REGISTER, IMAGE_SYM_CLASS_REGISTER_PARAM, IMAGE_SYM_CLASS_SECTION,
        IMAGE_SYM_CLASS_STATIC, IMAGE_SYM_CLASS_STRUCT_TAG, IMAGE_SYM_CLASS_TYPE_DEFINITION,
        IMAGE_SYM_CLASS_UNDEFINED_LABEL, IMAGE_SYM_CLASS_UNDEFINED_STATIC,
        IMAGE_SYM_CLASS_UNION_TAG, IMAGE_SYM_CLASS_WEAK_EXTERNAL,
    },
};

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

impl TryFrom<u16> for ImageFileMachine {
    type Error = TryFromImageFileMachineError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            IMAGE_FILE_MACHINE_UNKNOWN => Self::Unknown,
            IMAGE_FILE_MACHINE_ALPHA => Self::Alpha,
            IMAGE_FILE_MACHINE_ALPHA64 => Self::Alpha64,
            IMAGE_FILE_MACHINE_AM33 => Self::Am33,
            IMAGE_FILE_MACHINE_AMD64 => Self::Amd64,
            IMAGE_FILE_MACHINE_ARM => Self::Arm,
            IMAGE_FILE_MACHINE_ARM64 => Self::Arm64,
            IMAGE_FILE_MACHINE_ARM64EC => Self::Arm64Ec,
            IMAGE_FILE_MACHINE_ARM64X => Self::Arm64X,
            IMAGE_FILE_MACHINE_ARMNT => Self::ArmNt,
            IMAGE_FILE_MACHINE_EBC => Self::Ebc,
            IMAGE_FILE_MACHINE_I386 => Self::I386,
            IMAGE_FILE_MACHINE_IA64 => Self::Ia64,
            IMAGE_FILE_MACHINE_M32R => Self::M32R,
            IMAGE_FILE_MACHINE_MIPS16 => Self::Mips16,
            IMAGE_FILE_MACHINE_MIPSFPU => Self::MipsFpu,
            IMAGE_FILE_MACHINE_MIPSFPU16 => Self::Mips16,
            IMAGE_FILE_MACHINE_POWERPC => Self::PowerPc,
            IMAGE_FILE_MACHINE_POWERPCFP => Self::PowerPcFp,
            IMAGE_FILE_MACHINE_R3000 => Self::R3000,
            IMAGE_FILE_MACHINE_R4000 => Self::R4000,
            IMAGE_FILE_MACHINE_R10000 => Self::R10000,
            IMAGE_FILE_MACHINE_RISCV32 => Self::RiscV32,
            IMAGE_FILE_MACHINE_RISCV64 => Self::RiscV64,
            IMAGE_FILE_MACHINE_RISCV128 => Self::RiscV128,
            IMAGE_FILE_MACHINE_SH3 => Self::Sh3,
            IMAGE_FILE_MACHINE_SH3DSP => Self::Sh3Dsp,
            IMAGE_FILE_MACHINE_SH4 => Self::Sh4,
            IMAGE_FILE_MACHINE_SH5 => Self::Sh5,
            IMAGE_FILE_MACHINE_THUMB => Self::Thumb,
            IMAGE_FILE_MACHINE_WCEMIPSV2 => Self::WceMipsV2,
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
pub struct CoffFlags(u16);

bitflags! {
    impl CoffFlags: u16 {
        const RelocsStripped = IMAGE_FILE_RELOCS_STRIPPED;
        const ExecutableImage = IMAGE_FILE_EXECUTABLE_IMAGE;
        const LineNumsStripped = IMAGE_FILE_LINE_NUMS_STRIPPED;
        const LocalSymsStripped = IMAGE_FILE_LOCAL_SYMS_STRIPPED;
        const LargeAddressAware = IMAGE_FILE_LARGE_ADDRESS_AWARE;
        const BytesReversedLo = IMAGE_FILE_BYTES_REVERSED_LO;
        const ThirtyTwoBitMachine = IMAGE_FILE_32BIT_MACHINE;
        const DebugStripped = IMAGE_FILE_DEBUG_STRIPPED;
        const RemovableRunFromSwap = IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP;
        const NetRunFromSwap = IMAGE_FILE_NET_RUN_FROM_SWAP;
        const System = IMAGE_FILE_SYSTEM;
        const Dll = IMAGE_FILE_DLL;
        const UpSystemOnly = IMAGE_FILE_UP_SYSTEM_ONLY;
        const BytesReversedHi = IMAGE_FILE_BYTES_REVERSED_HI;

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
        const TypeNoPad = IMAGE_SCN_TYPE_NO_PAD;
        const CntCode = IMAGE_SCN_CNT_CODE;
        const CntInitializedData = IMAGE_SCN_CNT_INITIALIZED_DATA;
        const CntUninitializedData = IMAGE_SCN_CNT_UNINITIALIZED_DATA;
        const LnkOther = IMAGE_SCN_LNK_OTHER;
        const LnkInfo = IMAGE_SCN_LNK_INFO;
        const LnkRemove = IMAGE_SCN_LNK_REMOVE;
        const LnkComdat = IMAGE_SCN_LNK_COMDAT;
        const GpRel = IMAGE_SCN_GPREL;
        // Alignment is numeric not flags
        const LnkNRelocOvfl = IMAGE_SCN_LNK_NRELOC_OVFL;
        const MemDiscardable = IMAGE_SCN_MEM_DISCARDABLE;
        const MemNotCached = IMAGE_SCN_MEM_NOT_CACHED;
        const MemNotPaged = IMAGE_SCN_MEM_NOT_PAGED;
        const MemShared = IMAGE_SCN_MEM_SHARED;
        const MemExecute = IMAGE_SCN_MEM_EXECUTE;
        const MemRead = IMAGE_SCN_MEM_READ;
        const MemWrite = IMAGE_SCN_MEM_WRITE;

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

/// A section **number** for a symbol.
///
/// The section number is 1-based and stored internally as a `u32`.
/// The associated [`SectionNumber::index()`] method can be used for getting
/// the section index value if the section number refers to a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SectionNumber(u32);

#[allow(non_upper_case_globals)]
impl SectionNumber {
    pub const Undefined: Self = Self(0);
    pub const Absolute: Self = Self(u32::MAX);
    pub const Debug: Self = Self(u32::MAX - 1);
}

impl From<i32> for SectionNumber {
    fn from(value: i32) -> Self {
        Self(value.cast_unsigned())
    }
}

impl From<object::SectionIndex> for SectionNumber {
    fn from(value: object::SectionIndex) -> Self {
        Self(value.0 as u32)
    }
}

impl SectionNumber {
    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    /// Returns the 1-based section index if the section number refers to a section
    pub const fn index(self) -> Option<SectionIndex> {
        if 0 < self.0 && self.0 < SectionNumber::Absolute.0 {
            Some(SectionIndex(self.0 as usize))
        } else {
            None
        }
    }
}

/// Symbol storage class values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

impl TryFrom<u8> for StorageClass {
    type Error = TryFromStorageClassError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            IMAGE_SYM_CLASS_END_OF_FUNCTION => Self::EndOfFunction,
            IMAGE_SYM_CLASS_NULL => Self::Null,
            IMAGE_SYM_CLASS_AUTOMATIC => Self::Automatic,
            IMAGE_SYM_CLASS_EXTERNAL => Self::External,
            IMAGE_SYM_CLASS_STATIC => Self::Static,
            IMAGE_SYM_CLASS_REGISTER => Self::Register,
            IMAGE_SYM_CLASS_EXTERNAL_DEF => Self::ExternalDef,
            IMAGE_SYM_CLASS_LABEL => Self::Label,
            IMAGE_SYM_CLASS_UNDEFINED_LABEL => Self::UndefinedLabel,
            IMAGE_SYM_CLASS_MEMBER_OF_STRUCT => Self::MemberOfStruct,
            IMAGE_SYM_CLASS_ARGUMENT => Self::Argument,
            IMAGE_SYM_CLASS_STRUCT_TAG => Self::StructTag,
            IMAGE_SYM_CLASS_MEMBER_OF_UNION => Self::MemberOfUnion,
            IMAGE_SYM_CLASS_UNION_TAG => Self::UnionTag,
            IMAGE_SYM_CLASS_TYPE_DEFINITION => Self::TypeDefinition,
            IMAGE_SYM_CLASS_UNDEFINED_STATIC => Self::UndefinedStatic,
            IMAGE_SYM_CLASS_ENUM_TAG => Self::EnumTag,
            IMAGE_SYM_CLASS_MEMBER_OF_ENUM => Self::MemberOfEnum,
            IMAGE_SYM_CLASS_REGISTER_PARAM => Self::RegisterParam,
            IMAGE_SYM_CLASS_BIT_FIELD => Self::BitField,
            IMAGE_SYM_CLASS_BLOCK => Self::Block,
            IMAGE_SYM_CLASS_FUNCTION => Self::Function,
            IMAGE_SYM_CLASS_END_OF_STRUCT => Self::EndOfStruct,
            IMAGE_SYM_CLASS_FILE => Self::File,
            IMAGE_SYM_CLASS_SECTION => Self::Section,
            IMAGE_SYM_CLASS_WEAK_EXTERNAL => Self::WeakExternal,
            IMAGE_SYM_CLASS_CLR_TOKEN => Self::ClrToken,
            o => return Err(TryFromStorageClassError(o)),
        })
    }
}

#[derive(Debug)]
pub struct TryFromStorageClassError(u8);

impl std::fmt::Display for TryFromStorageClassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown 'IMAGE_SYM_CLASS_*' value '{}'", self.0)
    }
}

impl std::error::Error for TryFromStorageClassError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ComdatSelection {
    NoDuplicates = IMAGE_COMDAT_SELECT_NODUPLICATES,
    Any = IMAGE_COMDAT_SELECT_ANY,
    SameSize = IMAGE_COMDAT_SELECT_SAME_SIZE,
    ExactMatch = IMAGE_COMDAT_SELECT_EXACT_MATCH,
    Associative = IMAGE_COMDAT_SELECT_ASSOCIATIVE,
    Largest = IMAGE_COMDAT_SELECT_LARGEST,
}

impl From<ComdatSelection> for u8 {
    fn from(value: ComdatSelection) -> Self {
        match value {
            ComdatSelection::NoDuplicates => IMAGE_COMDAT_SELECT_NODUPLICATES,
            ComdatSelection::Any => IMAGE_COMDAT_SELECT_ANY,
            ComdatSelection::SameSize => IMAGE_COMDAT_SELECT_SAME_SIZE,
            ComdatSelection::ExactMatch => IMAGE_COMDAT_SELECT_EXACT_MATCH,
            ComdatSelection::Associative => IMAGE_COMDAT_SELECT_ASSOCIATIVE,
            ComdatSelection::Largest => IMAGE_COMDAT_SELECT_LARGEST,
        }
    }
}

impl TryFrom<u8> for ComdatSelection {
    type Error = TryFromComdatSelectionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            IMAGE_COMDAT_SELECT_NODUPLICATES => Self::NoDuplicates,
            IMAGE_COMDAT_SELECT_ANY => Self::Any,
            IMAGE_COMDAT_SELECT_SAME_SIZE => Self::SameSize,
            IMAGE_COMDAT_SELECT_EXACT_MATCH => Self::ExactMatch,
            IMAGE_COMDAT_SELECT_ASSOCIATIVE => Self::Associative,
            IMAGE_COMDAT_SELECT_LARGEST => Self::Largest,
            o => return Err(TryFromComdatSelectionError(o)),
        })
    }
}

#[derive(Debug)]
pub struct TryFromComdatSelectionError(u8);

impl std::fmt::Display for TryFromComdatSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown 'IMAGE_COMDAT_SELECT_*' value '{}'", self.0)
    }
}

impl std::error::Error for TryFromComdatSelectionError {}

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
