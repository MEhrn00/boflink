use bitflags::bitflags;
use object::pe;

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

#[derive(Debug)]
pub struct TryFromImageFileMachineError(u16);

impl std::fmt::Display for TryFromImageFileMachineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown 'IMAGE_FILE_MACHINE_*' value '{}'", self.0)
    }
}

impl std::error::Error for TryFromImageFileMachineError {}

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

/// Flags from a COFF File Header
/// <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CoffFlags(u16);

bitflags! {
    impl CoffFlags: u16 {
        /// Image only, Windows CE, and Microsoft Windows NT and later.
        /// This indicates that the file does not contain base relocations and
        /// must therefore be loaded at its preferred base address.
        /// If the base address is not available, the loader reports an error.
        /// The default behavior of the linker is to strip base relocations from executable (EXE) files.
        const RelocsStripped = pe::IMAGE_FILE_RELOCS_STRIPPED;

        /// Image only. This indicates that the image file is valid and can be run.
        /// If this flag is not set, it indicates a linker error.
        const ExecutableImage = pe::IMAGE_FILE_EXECUTABLE_IMAGE;

        /// COFF line numbers have been removed. This flag is deprecated and should be zero.
        const LineNumsStripped = pe::IMAGE_FILE_LINE_NUMS_STRIPPED;

        /// COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
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
