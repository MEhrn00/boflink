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
/// 7. .eh_frame (exception)
/// 8. .ctors (global constructors)
/// 9. .dtors (global destructors)
/// 10. .tls (thread-local storage)
/// 11. .rsrc (resources)
/// 12. .idata (import information)
/// 13. .debug$S (debug symbols)
/// 14. .debug$T (debug types)
/// 15. .debug$P (precompiled debug types)
/// 16. .debug$F (FPO debug info)
/// 17. .debug_info (DWARF info)
/// 18. .debug_abbrev (DWARF debug)
/// 19. .debug_aranges (DWARF debug)
/// 20. .debug_rnglists (DWARF)
/// 21. .debug_line (DWARF line info)
/// 22. .debug_str (DWARF strings)
/// 23. .debug_line_str (DWARF line strings)
/// 24. .debug_frame (DWARF frame)
/// 25. .sxdata (registered exception)
///
/// All other sections are ordered after the reserved sections on a "first-seen" basis.
use object::SectionIndex;

use crate::{
    arena::{ArenaHandle, ArenaRef},
    coff::SectionFlags,
    context::LinkContext,
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
    pub const EhFrame: Self = Self(7);
    pub const Ctors: Self = Self(8);
    pub const Dtors: Self = Self(9);
    pub const Tls: Self = Self(10);
    pub const Rsrc: Self = Self(11);
    pub const Idata: Self = Self(12);
    pub const DebugS: Self = Self(13);
    pub const DebugT: Self = Self(14);
    pub const DebugP: Self = Self(15);
    pub const DebugF: Self = Self(16);
    pub const DebugInfo: Self = Self(17);
    pub const DebugAbbrev: Self = Self(18);
    pub const DebugAranges: Self = Self(19);
    pub const DebugRnglists: Self = Self(20);
    pub const DebugLine: Self = Self(21);
    pub const DebugStr: Self = Self(22);
    pub const DebugLineStr: Self = Self(23);
    pub const DebugFrame: Self = Self(24);
    pub const Sxdata: Self = Self(25);
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
            length: 0,
            inputs: Vec::new(),
        }
    }
}

pub fn create_reserved_sections<'a>(
    arena: &ArenaHandle<'a, OutputSection<'a>>,
) -> Vec<ArenaRef<'a, OutputSection<'a>>> {
    let mut sections = Vec::with_capacity(27);

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
    push(".eh_frame", data | r);
    push(".ctors", data | r | w);
    push(".dtors", data | r | w);
    push(".tls", data | r | w);
    push(".rsrc", data | r);
    push(".idata", data | r | w);
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
    push(".debug_frame", r | discardable);
    push(".sxdata", link_info);

    sections
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SectionKey<'a> {
    name: &'a [u8],
    flags: SectionFlags,
}

impl<'a> SectionKey<'a> {
    pub fn new(ctx: &LinkContext, section: &InputSection<'a>) -> SectionKey<'a> {
        let mut name = section.name;
        let flags =
            section.characteristics.memory_flags() | section.characteristics.contents_flags();

        let r = SectionFlags::MemRead;
        let w = SectionFlags::MemWrite;
        let discardable = SectionFlags::MemDiscardable;
        let data = SectionFlags::CntInitializedData;
        let link_info = SectionFlags::LnkInfo;

        let merge_name = |name: &'a [u8]| {
            let dollar = name.iter().position(|&ch| ch == b'$');
            if let Some(dollar) = dollar {
                &name[..dollar]
            } else {
                name
            }
        };

        let has_any = |checks: &[(&str, SectionFlags)], name: &[u8], flags| -> bool {
            checks
                .iter()
                .any(|(s, f)| *f == flags && s.as_bytes() == name)
        };

        let has_any_prefix = |checks: &[(&str, SectionFlags)], name: &[u8], flags| -> bool {
            checks
                .iter()
                .any(|(s, f)| *f == flags && name.starts_with(s.as_bytes()))
        };

        if ctx.options.force_group_allocation {
            // Do not merge these sections
            let ignore_merge = [
                (".debug$S", r | discardable),
                (".debug$T", r | discardable),
                (".debug$P", r | discardable),
                (".debug$F", r | discardable),
                (".sxdata", link_info),
            ];

            let ignore_merge_prefixes = [(".sxdata$", link_info)];

            if !(has_any(&ignore_merge, name, flags)
                || has_any_prefix(&ignore_merge_prefixes, name, flags))
            {
                name = merge_name(name);
            }
        } else {
            // Always merge these sections. This makes looking up import information
            // easier
            let should_merge_prefixes = [(".idata$", data | r | w)];

            if has_any_prefix(&should_merge_prefixes, name, flags) {
                name = merge_name(name);
            }
        }

        SectionKey { name, flags }
    }

    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    pub fn flags(&self) -> SectionFlags {
        self.flags
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

        if name == b".text" && flags(code | r | x) {
            Some(OutputSectionId::Text)
        } else if name == b".data" && flags(data | r | w) {
            Some(OutputSectionId::Data)
        } else if name == b".bss" && flags(uninit | r | w) {
            Some(OutputSectionId::Bss)
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
        } else if name == b".debug$S" && flags(data | r | discardable) {
            Some(OutputSectionId::DebugS)
        } else if name == b".debug$T" && flags(data | r | discardable) {
            Some(OutputSectionId::DebugT)
        } else if name == b".debug$P" && flags(data | r | discardable) {
            Some(OutputSectionId::DebugP)
        } else if name == b".debug$F" && flags(data | r | discardable) {
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
        } else if name == b".tls" && flags(data | r | w) {
            Some(OutputSectionId::Tls)
        } else if name == b".rsrc" && flags(data | r) {
            Some(OutputSectionId::Rsrc)
        } else if name == b".idata" && flags(data | r | w) {
            Some(OutputSectionId::Idata)
        } else {
            None
        }
    }
}
