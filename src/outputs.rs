//! Linker output handling
//!
//! # Section ordering
//! Reserved sections <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#special-sections>
//! get preallocated inside the output file. The specified ordering is meant to
//! follow a hybrid of how GCC and Clang (GNU) order sections in object files.
//!
//! Most open source BOFs and BOF loaders use MinGW GCC for compilation or testing.
//! It is best to follow MinGW GCC's behavior as close as possible when building
//! output files to make things predictable and accomodate brittle loaders.
//! MinGW GCC only uses a subset of the reserved sections while Clang uses most of them
//! so places where GCC has a gap, the behavior will try to match Clang. The
//! only deviation from this is that sections that will automatically be discarded
//! in the output file are ordered later.
//!
//! Debug sections are never merged if included.
//! Other GNU-specific sections are also included.
//!
//! Reserved section ordering:
//! 1. .text (code)
//! 2. .data (data)
//! 3. .bss (uninitialized data)
//! 4. .rdata (read-only data)
//! 5. .xdata (unwind)
//! 6. .eh_frame (unwind)
//! 7. .pdata (exception)
//! 8. .ctors (global constructors)
//! 9. .dtors (global destructors)
//! 10. .tls (thread-local storage)
//! 11. .rsrc (resources)
//! 12. .debug$S (debug symbols)
//! 13. .debug$T (debug types)
//! 14. .debug$P (precompiled debug types)
//! 15. .debug$F (FPO debug info)
//! 16. .debug_info (DWARF info)
//! 17. .debug_abbrev (DWARF debug)
//! 18. .debug_aranges (DWARF debug)
//! 19. .debug_rnglists (DWARF)
//! 20. .debug_line (DWARF line info)
//! 21. .debug_str (DWARF strings)
//! 22. .debug_line_str (DWARF line strings)
//! 23. .debug_frame (DWARF frame)
//!
//! All other sections are ordered after the reserved sections on a "first-seen" basis.
use object::SectionIndex;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSliceMut,
};

use crate::{
    arena::{ArenaHandle, ArenaRef},
    coff::SectionFlags,
    context::LinkContext,
    inputs::{InputSection, ObjectFile, ObjectFileId},
    sparse::{FixedSparseMap, SparseKeyBuilder},
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
}

impl OutputSectionId {
    pub fn new(index: usize) -> Self {
        Self(index as u32)
    }

    pub fn index(self) -> usize {
        self.0 as usize
    }
}

pub const RESERVED_OUTPUT_SECTIONS_COUNT: usize = 24;

#[derive(Debug, Clone)]
pub struct OutputSection<'a> {
    pub name: &'a [u8],
    pub characteristics: SectionFlags,
    pub length: u32,
    pub inputs: Vec<(ObjectFileId, SectionIndex)>,
}

impl<'a> std::default::Default for OutputSection<'a> {
    fn default() -> Self {
        Self::new(b"", SectionFlags::empty())
    }
}

impl<'a> OutputSection<'a> {
    pub fn new(name: &'a [u8], characteristics: SectionFlags) -> Self {
        Self {
            name,
            characteristics,
            length: 0,
            inputs: Vec::new(),
        }
    }

    pub fn sort_inputs(&mut self, ctx: &LinkContext, objs: &[ArenaRef<'a, ObjectFile<'a>>]) {
        if ctx.options.merge_groups {
            let name = self.name;
            self.inputs.par_sort_unstable_by_key(|(objid, index)| {
                let index = *index;
                let obj = &objs[objid.index()];
                let input_name = obj.input_section(index).unwrap().name;
                let ordering_name = input_name.strip_prefix(name).unwrap();
                // $<name>, object order, section order
                (ordering_name, objid.index(), index.0)
            });
        } else {
            // Sort based on input file order
            self.inputs
                .par_sort_unstable_by_key(|(objid, index)| (objid.index(), index.0));
        }
    }

    pub fn compute_alignment(&mut self, objs: &[ArenaRef<'a, ObjectFile<'a>>]) {
        let align = self
            .inputs
            .par_iter()
            .map(|(objid, index)| {
                objs[objid.index()]
                    .input_section(*index)
                    .unwrap()
                    .characteristics
                    .alignment()
            })
            .max()
            .unwrap_or_default();
        if align > 0 {
            self.characteristics.set_alignment(align.min(8192));
        }
    }

    /// Computes the length for this output section.
    ///
    /// This is done sequentially
    pub fn compute_length(&mut self, objs: &[ArenaRef<'a, ObjectFile<'a>>]) {
        self.length = self.inputs.iter().fold(0, |length, (objid, index)| {
            let section = objs[objid.index()].input_section(*index).unwrap();
            let align = section.characteristics.alignment().min(1);
            let address = length.next_multiple_of(align as u32);
            address + section.length
        });
    }

    /// Creates a matrix used for joining object file input sections to this
    /// output section.
    pub fn create_join_matrix(&self) -> InputJoinMatrix {
        let mat = self
            .inputs
            .par_iter()
            .by_uniform_blocks(1_000_000)
            .fold(Vec::new, |mut mat, (objid, index)| {
                if mat.len() <= objid.index() {
                    mat.resize(objid.index() + 1, Vec::new());
                }
                mat[objid.index()].push(*index);
                mat
            })
            .reduce(Vec::new, |mut v1, mut v2| {
                v1.append(&mut v2);
                v2
            });

        InputJoinMatrix { mat }
    }
}

pub fn create_reserved_sections<'a>(
    arena: &ArenaHandle<'a, OutputSection<'a>>,
) -> Vec<ArenaRef<'a, OutputSection<'a>>> {
    let mut sections = Vec::new();

    let mut push = |name: &'a str, flags| {
        sections.push(arena.alloc_ref(OutputSection::new(name.as_bytes(), flags)));
    };

    let r = SectionFlags::MemRead;
    let w = SectionFlags::MemWrite;
    let x = SectionFlags::MemExecute;
    let discardable = SectionFlags::MemDiscardable;

    let code = SectionFlags::CntCode;
    let data = SectionFlags::CntInitializedData;
    let uninit = SectionFlags::CntUninitializedData;

    push("<null>", SectionFlags::empty()); // SHT_NULL section
    push(".text", code | r | x);
    push(".data", data | r | w);
    push(".bss", uninit | r | w);
    push(".rdata", data | r);
    push(".xdata", data | r);
    push(".eh_frame", data | r);
    push(".pdata", data | r);
    push(".ctors", data | r | w);
    push(".dtors", data | r | w);
    push(".tls", data | r | w);
    push(".rsrc", data | r);
    push(".debug$S", data | r | discardable);
    push(".debug$T", data | r | discardable);
    push(".debug$P", data | r | discardable);
    push(".debug$F", data | r | discardable);
    push(".debug_info", data | r | discardable);
    push(".debug_abbrev", data | r | discardable);
    push(".debug_aranges", data | r | discardable);
    push(".debug_rnglists", data | r | discardable);
    push(".debug_line", data | r | discardable);
    push(".debug_str", data | r | discardable);
    push(".debug_line_str", data | r | discardable);
    push(".debug_frame", data | r | discardable);

    debug_assert!(sections.len() == RESERVED_OUTPUT_SECTIONS_COUNT);

    sections
}

/// Used for keying input sections to determine what output section they should
/// be placed in
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SectionKey<'a> {
    /// Section name
    name: &'a [u8],

    /// Output section flags
    flags: SectionFlags,
}

impl<'a> SectionKey<'a> {
    pub fn new(ctx: &LinkContext, section: &InputSection<'a>) -> SectionKey<'a> {
        let mut key = SectionKey {
            name: section.name,
            flags: section.characteristics.kind_flags(),
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

        let r = SectionFlags::MemRead;
        let discardable = SectionFlags::MemDiscardable;
        let data = SectionFlags::CntInitializedData;

        if ctx.options.merge_groups {
            // Codeview sections are not merged since they are special linker
            // sections
            let ignore_merge: [(&[u8], SectionFlags); _] = [
                (b".debug$S", data | r | discardable),
                (b".debug$T", data | r | discardable),
                (b".debug$P", data | r | discardable),
                (b".debug$F", data | r | discardable),
            ];

            if !ignore_merge.contains(&(key.name, key.flags)) {
                key.name = strip_dollar(key.name);
            }
        } else {
            key.name = strip_dollar(key.name);
        }

        key
    }

    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    pub fn flags(&self) -> SectionFlags {
        self.flags
    }

    /// Id for preallocated sections if known
    pub fn known_id(&self) -> Option<OutputSectionId> {
        let r = SectionFlags::MemRead;
        let w = SectionFlags::MemWrite;
        let x = SectionFlags::MemExecute;
        let discardable = SectionFlags::MemDiscardable;

        let code = SectionFlags::CntCode;
        let data = SectionFlags::CntInitializedData;
        let uninit = SectionFlags::CntUninitializedData;

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
        } else {
            None
        }
    }
}

pub struct OutputSectionKeyBuilder;

impl SparseKeyBuilder for OutputSectionKeyBuilder {
    type Key = OutputSectionId;

    fn sparse_index(key: Self::Key) -> usize {
        key.index()
    }
}

pub type OutputSectionInputsMap =
    FixedSparseMap<OutputSectionId, Vec<(ObjectFileId, SectionIndex)>, OutputSectionKeyBuilder>;

/// Matrix for joining input sections to output sections
pub struct InputJoinMatrix {
    mat: Vec<Vec<SectionIndex>>,
}

impl InputJoinMatrix {
    /// Gets the list of input sections for the specified object file.
    pub fn get(&self, obj: ObjectFileId) -> Option<&[SectionIndex]> {
        self.mat.get(obj.index()).map(|list| list.as_slice())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RebaseGroup {
    /// Output section for this rebase group
    pub output: OutputSectionId,
    /// Matrix with input object / list of rebased addresses.
    pub rebases: Vec<Vec<RebaseEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RebaseEntry {
    pub index: SectionIndex,
    pub address: u32,
}
