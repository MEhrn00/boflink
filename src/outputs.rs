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
/// 17. .debug_rnglists (DWARF)
/// 18. .debug_line (DWARF line info)
/// 19. .debug_str (DWARF strings)
/// 20. .debug_line_str (DWARF line strings)
/// 21. .rdata$zzz (GCC ident)
/// 22. .debug_frame (DWARF frame)
/// 23. .tls (thread-local storage)
/// 24. .tls$ (thread-local storage)
/// 25. .rsrc (resources)
/// 26. .cormeta (CLR metadata, should not be seen)
/// 27. .idata (import information, discarded)
/// 28. .edata (export information, discarded)
///
/// All other sections are ordered after the reserved sections on a "first-seen" basis.
use object::SectionIndex;

use crate::{
    arena::{ArenaHandle, ArenaRef},
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
    pub const DebugRnglists: Self = Self(17);
    pub const DebugLine: Self = Self(18);
    pub const DebugStr: Self = Self(19);
    pub const DebugLineStr: Self = Self(20);
    pub const GccIdent: Self = Self(21);
    pub const DebugFrame: Self = Self(22);
    pub const Tls: Self = Self(23);
    pub const TlsD: Self = Self(24);
    pub const Rsrc: Self = Self(25);
    pub const Cormeta: Self = Self(26);
    pub const Idata: Self = Self(27);
    pub const Edata: Self = Self(28);
}

impl OutputSectionId {
    pub fn new(index: usize) -> Self {
        Self(index as u32)
    }

    pub fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone)]
pub struct OutputSection<'a> {
    pub id: OutputSectionId,
    pub name: &'a [u8],
    pub index: SectionIndex,
    pub characteristics: SectionFlags,
    pub checksum: u32,
    pub length: u32,
    pub discard: bool,
    pub inputs: Vec<(ObjectFileId, SectionIndex)>,
}

impl<'a> std::default::Default for OutputSection<'a> {
    fn default() -> Self {
        Self::new(OutputSectionId(0), b"", SectionFlags::empty(), false)
    }
}

impl<'a> OutputSection<'a> {
    pub fn new(
        id: OutputSectionId,
        name: &'a [u8],
        characteristics: SectionFlags,
        discard: bool,
    ) -> Self {
        Self {
            id,
            name,
            characteristics,
            discard,
            index: SectionIndex(0),
            checksum: 0,
            length: 0,
            inputs: Vec::new(),
        }
    }
}

pub fn create_reserved_sections<'a>(
    arena: &ArenaHandle<'a, OutputSection<'a>>,
) -> Vec<ArenaRef<'a, OutputSection<'a>>> {
    let mut sections = Vec::with_capacity(OutputSectionId::Edata.0 as usize + 1);

    let mut push = |name: &'a str, flags| {
        let id = OutputSectionId(sections.len() as u32);
        sections.push(arena.alloc_ref(OutputSection::new(id, name.as_bytes(), flags, false)));
    };

    let r = SectionFlags::MemRead;
    let w = SectionFlags::MemWrite;
    let x = SectionFlags::MemExecute;
    let discardable = SectionFlags::MemDiscardable;

    let code = SectionFlags::CntCode;
    let data = SectionFlags::CntInitializedData;
    let uninit = SectionFlags::CntUninitializedData;
    let link_info = SectionFlags::LnkInfo;

    push("", SectionFlags::empty()); // Null section
    push(".text", code | r | x);
    push(".data", data | r | w);
    push(".bss", uninit | r | w);
    push(".rdata", data | r);
    push(".xdata", data | r);
    push(".pdata", data | r);
    push(".ctors", data | r | w);
    push(".dtors", data | r | w);
    push(".sxdata", link_info);
    push(".debug$S", r | discardable);
    push(".debug$T", r | discardable);
    push(".debug$P", r | discardable);
    push(".debug$F", r | discardable);
    push(".debug_info", r | discardable);
    push(".debug_abbrev", r | discardable);
    push(".debug_aranges", r | discardable);
    push(".debug_rnglists", r | discardable);
    push(".debug_line", r | discardable);
    push(".debug_str", r | discardable);
    push(".debug_line_str", r | discardable);
    push(".rdata$zzz", data | r);
    push(".debug_frame", r | discardable);
    push(".tls", data | r | w);
    push(".tls$", data | r | w);
    push(".rsrc", data | r);
    push(".cormeta", link_info);
    push(".idata", data | r | w);
    push(".edata", data | r);

    sections
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SectionKey<'a> {
    pub name: &'a [u8],
    pub subname: Option<&'a [u8]>,
    pub flags: SectionFlags,
}

impl<'a> SectionKey<'a> {
    pub fn new(input_section: &InputSection<'a>) -> SectionKey<'a> {
        let mut name = input_section.name;
        let mut subname = None;

        let dollar = input_section.name.iter().position(|&ch| ch == b'$');
        if let Some(dollar) = dollar {
            name = &input_section.name[..dollar];
            subname = Some(&input_section.name[dollar + 1..]);
        }

        SectionKey {
            name,
            subname,
            flags: input_section.characteristics.memory_flags()
                | input_section.characteristics.contents_flags(),
        }
    }

    pub fn known_output(&self) -> Option<OutputSectionId> {
        let r = SectionFlags::MemRead;
        let w = SectionFlags::MemWrite;
        let x = SectionFlags::MemExecute;
        let discardable = SectionFlags::MemDiscardable;

        let code = SectionFlags::CntCode;
        let data = SectionFlags::CntInitializedData;
        let uninit = SectionFlags::CntUninitializedData;
        let link_info = SectionFlags::LnkInfo;

        let flags = |v| self.flags == v;

        let name = self.name;
        let subname = self.subname;

        if name == b".text" && flags(code | r | x) {
            Some(OutputSectionId::Text)
        } else if name == b".data" && flags(data | r | w) {
            Some(OutputSectionId::Data)
        } else if name == b".bss" && flags(uninit | r | w) {
            Some(OutputSectionId::Bss)
        } else if name == b".rdata" && subname == Some(b"zzz") && flags(data | r) {
            Some(OutputSectionId::GccIdent)
        } else if name == b".rdata" && flags(data | r) {
            Some(OutputSectionId::Rdata)
        } else if name == b".xdata" && flags(data | r) {
            Some(OutputSectionId::Xdata)
        } else if name == b".pdata" && flags(data | r) {
            Some(OutputSectionId::Pdata)
        } else if name == b".ctors" && flags(data | r | w) {
            Some(OutputSectionId::Ctors)
        } else if name == b".dtors" && flags(data | r | w) {
            Some(OutputSectionId::Dtors)
        } else if name == b".sxdata" && flags(link_info) {
            Some(OutputSectionId::Sxdata)
        } else if name == b".debug" && subname == Some(b"S") && flags(data | r | discardable) {
            Some(OutputSectionId::DebugS)
        } else if name == b".debug" && subname == Some(b"T") && flags(data | r | discardable) {
            Some(OutputSectionId::DebugT)
        } else if name == b".debug" && subname == Some(b"P") && flags(data | r | discardable) {
            Some(OutputSectionId::DebugP)
        } else if name == b".debug" && subname == Some(b"F") && flags(data | r | discardable) {
            Some(OutputSectionId::DebugF)
        } else if name == b".debug_info" && flags(data | r | discardable) {
            Some(OutputSectionId::DebugInfo)
        } else if name == b".debug_abbrev" && flags(data | r | discardable) {
            Some(OutputSectionId::DebugAbbrev)
        } else if name == b".debug_aranges" && flags(data | r | discardable) {
            Some(OutputSectionId::DebugAranges)
        } else if name == b".debug_rnglists" && flags(data | r | discardable) {
            Some(OutputSectionId::DebugRnglists)
        } else if name == b".debug_line" && flags(data | r | discardable) {
            Some(OutputSectionId::DebugLine)
        } else if name == b".debug_str" && flags(data | r | discardable) {
            Some(OutputSectionId::DebugStr)
        } else if name == b".debug_line_str" && flags(data | r | discardable) {
            Some(OutputSectionId::DebugLineStr)
        } else if name == b".debug_frame" && flags(data | r | discardable) {
            Some(OutputSectionId::DebugFrame)
        } else if name == b".tls" && subname.is_none() && flags(data | r | w) {
            Some(OutputSectionId::Tls)
        } else if name == b".tls" && flags(data | r | w) {
            Some(OutputSectionId::TlsD)
        } else if name == b".rsrc" && flags(data | r) {
            Some(OutputSectionId::Rsrc)
        } else if name == b".cormeta" && flags(link_info) {
            Some(OutputSectionId::Cormeta)
        } else if name == b".idata" && flags(data | r | w) {
            Some(OutputSectionId::Idata)
        } else if name == b".edata" && flags(data | r) {
            Some(OutputSectionId::Edata)
        } else {
            None
        }
    }
}
