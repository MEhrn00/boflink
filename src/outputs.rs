//! Linker output handling
//!
//! # Section ordering
/// Reserved sections <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#special-sections>
/// get preallocated inside the output file. The specified ordering is meant to
/// follow a hybrid of how GCC and Clang (GNU) order sections in object files.
///
/// Most open source BOFs and BOF loaders use MinGW GCC for compilation or testing.
/// It is best to follow MinGW GCC's behavior as close as possible when building
/// output files to make things predictable and accomodate brittle loaders.
/// MinGW GCC only uses a subset of the reserved sections while Clang uses most of them
/// so places where GCC has a gap, the behavior will try to match Clang. The
/// only deviation from this is that sections that will automatically be discarded
/// in the output file are ordered later.
///
/// Debug sections are never merged if included.
/// Other GNU-specific sections are also included.
///
/// Reserved section ordering:
/// 1. .text (code)
/// 2. .data (data)
/// 3. .bss (uninitialized data)
/// 4. .rdata (read-only data)
/// 5. .xdata (unwind)
/// 6. .pdata (exception)
/// 7. .ctors (global constructors)
/// 8. .dtors (global destructors)
/// 9. .sxdata (registered exception)
/// 10. .debug$S (debug symbols)
/// 11. .debug$T (debug types)
/// 12. .debug$P (precompiled debug types)
/// 13. .debug$F (FPO debug info)
/// 14. .debug_info (DWARF info)
/// 15. .debug_abbrev (DWARF debug)
/// 16. .debug_aranges (DWARF debug)
/// 17. .debug_line (DWARF line info)
/// 18. .debug_str (DWARF strings)
/// 19. .debug_line_str (DWARF line strings)
/// 20. .rdata$zzz (GCC ident)
/// 21. .debug_frame (DWARF frame)
/// 22. .tls (thread-local storage)
/// 23. .tls$ (thread-local storage)
/// 24. .rsrc (resources)
/// 25. .cormeta (CLR metadata, should not be seen)
/// 26. .idata (import information, discarded)
/// 27. .edata (export information, discarded)
///
/// All other sections are ordered after the reserved sections on a "first-seen" basis.
use object::SectionIndex;

use crate::{
    coff::SectionFlags,
    inputs::{InputSection, ObjectFileId},
};

/// ID for an output section.
///
/// Section 0 is treated as the `SHT_NULL` section
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutputSectionId(u32);

#[allow(non_upper_case_globals)]
impl OutputSectionId {
    pub const Null: Self = Self(0);
    pub const Text: Self = Self(1);
    pub const Data: Self = Self(2);
    pub const Bss: Self = Self(3);
    pub const Rdata: Self = Self(4);
    pub const Xdata: Self = Self(5);
    pub const Pdata: Self = Self(6);
    pub const Ctors: Self = Self(7);
    pub const Dtors: Self = Self(8);
    pub const Sxdata: Self = Self(9);
    pub const DebugS: Self = Self(10);
    pub const DebugT: Self = Self(11);
    pub const DebugP: Self = Self(12);
    pub const DebugF: Self = Self(13);
    pub const DebugInfo: Self = Self(14);
    pub const DebugAbbrev: Self = Self(15);
    pub const DebugAranges: Self = Self(16);
    pub const DebugLine: Self = Self(17);
    pub const DebugStr: Self = Self(18);
    pub const DebugLineStr: Self = Self(19);
    pub const GccIdent: Self = Self(20);
    pub const DebugFrame: Self = Self(21);
    pub const Tls: Self = Self(22);
    pub const TlsD: Self = Self(23);
    pub const Rsrc: Self = Self(24);
    pub const Cormeta: Self = Self(25);
    pub const Idata: Self = Self(26);
    pub const Edata: Self = Self(27);
}

#[derive(Debug)]
pub struct OutputSection<'a> {
    pub id: OutputSectionId,
    pub name: &'a [u8],
    pub index: SectionIndex,
    pub characteristics: SectionFlags,
    pub checksum: u32,
    pub length: u32,
    pub discarded: bool,
}

#[derive(Debug)]
pub struct SectionPart<'a> {
    pub output_section: OutputSectionId,
    pub input_object: ObjectFileId,
    pub input_index: SectionIndex,
    pub key: SectionKey<'a>,
    pub address: u32,
}

#[derive(Debug)]
pub struct SectionKey<'a> {
    name: &'a [u8],
    group: &'a [u8],
    flags: SectionFlags,
}

impl<'a> SectionKey<'a> {
    pub fn new(input_section: &InputSection<'a>) -> SectionKey<'a> {
        let split_at = input_section.name.iter().position(|&ch| ch == b'$');
        let (name, group) = if let Some(split_at) = split_at {
            (
                &input_section.name[..split_at],
                &input_section.name[split_at + 1..],
            )
        } else {
            (input_section.name, b"".as_slice())
        };

        SectionKey {
            name,
            group,
            flags: input_section.characteristics.memory_flags()
                | input_section.characteristics.contents_flags(),
        }
    }

    pub fn known_id(&self) -> Option<OutputSectionId> {
        None
    }
}
