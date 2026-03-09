use bitflags::bitflags;
use object::pe;

/// Flags from a COFF File Header
/// <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics>
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
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
