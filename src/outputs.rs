//! Linker output handling
//!
//! Reserved sections and other linker-synthesized sections get pre-allocated
//! during creation. Some or most of these output sections will get discarded
//! if they happen to contain no inputs or all of the inputs are empty and unused.
//!
//! # Section ordering
//! Most open source BOFs and BOF loaders use MinGW GCC for compilation or testing.
//! It is best to follow MinGW GCC's behavior as close as possible when building
//! output files to make things predictable and accomodate brittle loaders.
//! This ordering tries to follow as close as possible to match a mix of the
//! MinGW GCC and Clang ordering with other linker-synthesizd sections interleaved.
//!
//! Sections that will always be discarded are placed at the end. These are used
//! as containers for referencing various different types of input sections across
//! all input files.
//!
//! Ordering:
//! 0. NULL section (empty section that is unused, discarded)
//! 1. .text (code)
//! 2. .data (data)
//! 3. .bss (uninitialized data)
//! 4. .rdata (read-only data)
//! 5. .xdata (unwind info)
//! 6. .eh_frame (unwind info)
//! 7. .pdata (exception info)
//! 8. .ctors (global constructors)
//! 9. .dtors (global destructors)
//! 10. .tls (thread-local storage)
//! 11. .rsrc (resources)
//! 12. .debug$S (debug symbols)
//! 13. .debug$T (debug types)
//! 14. .debug$P (precompiled debug types)
//! 15. .debug$F (FPO debug info)
//! 16. .debug_info (DWARF)
//! 17. .debug_abbrev (DWARF)
//! 18. .debug_aranges (DWARF)
//! 19. .debug_rnglists (DWARF)
//! 20. .debug_line (DWARF)
//! 21. .debug_str (DWARF)
//! 22. .debug_line_str (DWARF)
//! 23. .debug_frame (DWARF)
//! 24. .idata (import data, discarded)
//! 25. .common (used for temporarily defining common symbols, discarded)
//!
//! All other sections are ordered after the reserved sections on a "first-seen" basis.

use boflink_index::IndexVec;
use bstr::BStr;
use object::{SectionIndex, pe};

use crate::{
    chunks::SectionChunk,
    coff::SectionFlags,
    context::LinkContext,
    object::{InputSection, ObjectFileId},
};

/// ID for an output section.
///
/// Section 0 is treated as the `SHT_NULL` section and is unused
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutputSectionId(u32);

impl boflink_index::Idx for OutputSectionId {
    #[inline]
    fn from_usize(idx: usize) -> Self {
        assert!(idx <= u32::MAX as usize);
        Self(idx as u32)
    }

    #[inline]
    fn index(self) -> usize {
        self.0 as usize
    }
}

#[allow(non_upper_case_globals)]
impl OutputSectionId {
    pub const Null: Self = Self(0);
    pub const Text: Self = Self(1);
    pub const Data: Self = Self(2);
    pub const Bss: Self = Self(3);
    pub const Rdata: Self = Self(4);
    pub const Xdata: Self = Self(5);
    pub const EhFrame: Self = Self(6);
    pub const Pdata: Self = Self(7);
    pub const Ctors: Self = Self(8);
    pub const Dtors: Self = Self(9);
    pub const Tls: Self = Self(10);
    pub const Rsrc: Self = Self(11);
    pub const DebugS: Self = Self(12);
    pub const DebugT: Self = Self(13);
    pub const DebugP: Self = Self(14);
    pub const DebugF: Self = Self(15);
    pub const DebugInfo: Self = Self(16);
    pub const DebugAbbrev: Self = Self(17);
    pub const DebugAranges: Self = Self(18);
    pub const DebugRnglists: Self = Self(19);
    pub const DebugLine: Self = Self(20);
    pub const DebugStr: Self = Self(21);
    pub const DebugLineStr: Self = Self(22);
    pub const DebugFrame: Self = Self(23);
    pub const Idata: Self = Self(24);
    pub const Common: Self = Self(25);
}

impl Default for OutputSectionId {
    fn default() -> Self {
        Self::Null
    }
}

/// The last ID from the reserved output section ids
pub const LAST_RESERVED_SECTION_ID: OutputSectionId = OutputSectionId::Common;

/// Length of the reserved sections list
pub const RESERVED_SECTIONS_LEN: usize = LAST_RESERVED_SECTION_ID.0 as usize + 1;

impl OutputSectionId {
    pub fn new(index: usize) -> Self {
        Self(index as u32)
    }

    pub fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Default)]
pub struct LinkOutputs<'a> {
    pub sections: IndexVec<OutputSectionId, OutputSection<'a>>,
}

/// Section for the output file.
///
/// This contains the section metadata and list of indicies for input sections.
#[derive(Debug, Clone)]
pub struct OutputSection<'a> {
    /// Name that will end up in the section header
    pub name: &'a BStr,

    /// Flags
    pub characteristics: SectionFlags,

    /// The 1-based section index.
    ///
    /// This is different than the id. The id is used for referencing this section
    /// in the output section list. The index is what is actually used for the
    /// section table index in the output file.
    pub index: SectionIndex,

    /// Length of the output section.
    ///
    /// This is the aligned length.
    pub length: u32,

    /// True if this section should be excluded from the output file.
    ///
    /// Output sections will be excluded if they are used as input section containers
    /// or the list of input sections is empty and all of them can be safely
    /// discarded.
    pub exclude: bool,

    /// Input section mapping table
    pub mappings: Vec<MappedSection<'a>>,
}

impl<'a> OutputSection<'a> {
    pub fn new(name: &'a BStr, characteristics: SectionFlags, exclude: bool) -> Self {
        Self {
            name,
            characteristics,
            index: SectionIndex(0),
            length: 0,
            exclude,
            mappings: Vec::new(),
        }
    }
}

/// An input section mapped to an output section.
#[derive(Debug, Clone)]
pub struct MappedSection<'a> {
    /// The object file with the input section.
    pub obj: ObjectFileId,

    /// The index of the input section in the object file.
    pub index: SectionIndex,

    /// The input section relocations that will appear in the output file.
    ///
    /// These are the original relocations read from the input file. The symbol
    /// table indicies need to be updated when the relocations get written to
    /// the output file.
    pub relocs: Vec<&'a pe::ImageRelocation>,
}

/// Creates the list of reserved output sections
pub fn create_reserved_sections<'a>() -> IndexVec<OutputSectionId, OutputSection<'a>> {
    let mut sections = IndexVec::new();

    let mut push = |name: &'a str, flags, exclude: bool| {
        sections.push(OutputSection::new(
            BStr::new(name.as_bytes()),
            flags,
            exclude,
        ));
    };

    let r = SectionFlags::MemRead;
    let w = SectionFlags::MemWrite;
    let x = SectionFlags::MemExecute;
    let discardable = SectionFlags::MemDiscardable;

    let code = SectionFlags::CntCode;
    let data = SectionFlags::CntInitializedData;
    let uninit = SectionFlags::CntUninitializedData;

    push("<null>", SectionFlags::empty(), true); // SHT_NULL section
    push(".text", code | r | x, false);
    push(".data", data | r | w, false);
    push(".bss", uninit | r | w, false);
    push(".rdata", data | r, false);
    push(".xdata", data | r, false);
    push(".eh_frame", data | r, false);
    push(".pdata", data | r, false);
    push(".ctors", data | r | w, false);
    push(".dtors", data | r | w, false);
    push(".tls", data | r | w, false);
    push(".rsrc", data | r, false);
    push(".debug$S", data | r | discardable, false);
    push(".debug$T", data | r | discardable, false);
    push(".debug$P", data | r | discardable, false);
    push(".debug$F", data | r | discardable, false);
    push(".debug_info", data | r | discardable, false);
    push(".debug_abbrev", data | r | discardable, false);
    push(".debug_aranges", data | r | discardable, false);
    push(".debug_rnglists", data | r | discardable, false);
    push(".debug_line", data | r | discardable, false);
    push(".debug_str", data | r | discardable, false);
    push(".debug_line_str", data | r | discardable, false);
    push(".debug_frame", data | r | discardable, false);
    push(".idata", data | r | w, true);
    push(".common", uninit | r | w, true);

    debug_assert!(sections.len() == RESERVED_SECTIONS_LEN);

    sections
}

/// Used for keying input sections to determine what output section they should
/// be placed in
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SectionKey<'a> {
    /// Section name
    name: &'a [u8],

    /// Output section flags
    flags: u32,
}

impl<'a> SectionKey<'a> {
    pub fn new(ctx: &LinkContext, section: &InputSection<'a>) -> SectionKey<'a> {
        let mut key = SectionKey {
            name: section.name,
            flags: section.contents_flags() | section.memory_flags(),
        };

        // Strips `name` up to the first '$' character
        let strip_dollar = |name: &'a [u8]| {
            let dollar = name.iter().position(|&ch| ch == b'$');
            if let Some(dollar) = dollar {
                &name[..dollar]
            } else {
                name
            }
        };

        // MinGW will unreliably set the `IMAGE_SCN_CNT_INITIALIZED_DATA` flag
        // for .idata sections. Ensure it is always set and that the section
        // is marked as writable for conformity.
        if section.is_idata() {
            key.flags |= pe::IMAGE_SCN_CNT_INITIALIZED_DATA | pe::IMAGE_SCN_MEM_WRITE;
        }

        if ctx.options.merge_groups {
            // Codeview sections are not merged since they are special linker
            // sections. They may exist if the user passed `--no-strip-debug`.
            if !section.is_codeview() {
                key.name = strip_dollar(key.name);
            }
        } else if section.is_idata() {
            // Always merge import data sections
            key.name = strip_dollar(key.name);
        }

        key
    }

    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Id for preallocated sections if known
    pub fn known_id(&self) -> Option<OutputSectionId> {
        let r = pe::IMAGE_SCN_MEM_READ;
        let w = pe::IMAGE_SCN_MEM_WRITE;
        let x = pe::IMAGE_SCN_MEM_EXECUTE;
        let discardable = pe::IMAGE_SCN_MEM_DISCARDABLE;

        let code = pe::IMAGE_SCN_CNT_CODE;
        let data = pe::IMAGE_SCN_CNT_INITIALIZED_DATA;
        let uninit = pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA;

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
        } else if name == b".eh_frame" && flags(data | r) {
            Some(OutputSectionId::EhFrame)
        } else if name == b".pdata" && flags(data | r) {
            Some(OutputSectionId::Pdata)
        } else if name == b".ctors" && flags(data | r | w) {
            Some(OutputSectionId::Ctors)
        } else if name == b".dtors" && flags(data | r | w) {
            Some(OutputSectionId::Dtors)
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
