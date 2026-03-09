use bitflags::bitflags;
use boflink_index::Idx;
use object::{ReadRef, pe, read::coff};

use crate::{
    chunks::{P2Align, SectionChunk},
    make_error,
};

/// Shift value for extracting the alignment from section flags
pub const SECTION_FLAGS_ALIGN_SHIFT: usize = 20;

/// 1-based section index
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SectionIndex(pub u32);

impl boflink_index::Idx for SectionIndex {
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

impl std::fmt::Display for SectionIndex {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

#[derive(Default, Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SectionTable<'a>(&'a [pe::ImageSectionHeader]);

impl<'a> SectionTable<'a> {
    #[inline]
    pub fn parse<H: coff::CoffHeader>(
        header: &H,
        data: &'a [u8],
        offset: u64,
    ) -> crate::Result<Self> {
        Ok(Self(
            data.read_slice_at(offset, header.number_of_sections() as usize)
                .map_err(|_| make_error!("invalid COFF/PE section headers"))?,
        ))
    }

    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'a, pe::ImageSectionHeader> {
        self.0.iter()
    }

    #[inline]
    pub fn enumerate(&self) -> impl Iterator<Item = (SectionIndex, &'a pe::ImageSectionHeader)> {
        let _ = SectionIndex::from_usize(self.0.len() + 1);
        self.0
            .iter()
            .enumerate()
            .map(|(i, section)| (SectionIndex::from_usize(i + 1), section))
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn section(&self, index: SectionIndex) -> crate::Result<&'a pe::ImageSectionHeader> {
        self.0
            .get(index.0.wrapping_sub(1) as usize)
            .ok_or_else(|| make_error!("invalid COFF/PE section index"))
    }
}

impl<'a> SectionChunk<'a> for &'a pe::ImageSectionHeader {
    #[inline]
    fn name_bytes(&self) -> &'a [u8] {
        self.raw_name()
    }

    #[inline]
    fn contents_flags(&self) -> u32 {
        self.characteristics.get(object::LittleEndian) & 0xe0
    }

    #[inline]
    fn memory_flags(&self) -> u32 {
        self.characteristics.get(object::LittleEndian) & 0xfe000000
    }

    #[inline]
    fn p2align(&self) -> P2Align {
        P2Align::from_scn_flags(self.characteristics.get(object::LittleEndian))
    }
}

/// COFF section header flags.
///
/// The characteristic field is a hybrid of bit flags and numeric values.
/// The bit flags portion is also categorized. Each category can be queried
/// separately through various methods on this type.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SectionFlags(u32);

bitflags! {
    impl SectionFlags: u32 {
        const TypeNoPad = pe::IMAGE_SCN_TYPE_NO_PAD;
        const CntCode = pe::IMAGE_SCN_CNT_CODE;
        const CntInitializedData = pe::IMAGE_SCN_CNT_INITIALIZED_DATA;
        const CntUninitializedData = pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA;
        const LnkOther = pe::IMAGE_SCN_LNK_OTHER;
        const LnkInfo = pe::IMAGE_SCN_LNK_INFO;
        const LnkRemove = pe::IMAGE_SCN_LNK_REMOVE;
        const LnkComdat = pe::IMAGE_SCN_LNK_COMDAT;
        const GpRel = pe::IMAGE_SCN_GPREL;
        // Alignment is numeric not flags
        const LnkNRelocOvfl = pe::IMAGE_SCN_LNK_NRELOC_OVFL;
        const MemDiscardable = pe::IMAGE_SCN_MEM_DISCARDABLE;
        const MemNotCached = pe::IMAGE_SCN_MEM_NOT_CACHED;
        const MemNotPaged = pe::IMAGE_SCN_MEM_NOT_PAGED;
        const MemShared = pe::IMAGE_SCN_MEM_SHARED;
        const MemExecute = pe::IMAGE_SCN_MEM_EXECUTE;
        const MemRead = pe::IMAGE_SCN_MEM_READ;
        const MemWrite = pe::IMAGE_SCN_MEM_WRITE;

        // Allow externally set flags
        const _ = !0;
    }
}

impl SectionFlags {
    /// Returns the alignment value from the section flags.
    ///
    /// This will return 0 if unset.
    pub const fn alignment(&self) -> u32 {
        if self.contains(Self::TypeNoPad) {
            return 1;
        }

        let shamt = (self.bits() >> SECTION_FLAGS_ALIGN_SHIFT) & 0xf;
        if shamt > 0 { 1u32 << (shamt - 1) } else { 0 }
    }

    /// Sets the alignment flag to match `align`.
    ///
    /// Only valid alignment values are accepted (0, 1 or power of two <= 8192).
    /// An alignment of `0` will unset the alignment.
    ///
    /// # Panics
    /// Panics if an invalid alignment value is passed.
    pub const fn set_alignment(&mut self, align: u32) {
        self.0 &= pe::IMAGE_SCN_ALIGN_MASK;

        if align == 0 {
            return;
        } else if align == 1 {
            self.0 |= 1 << SECTION_FLAGS_ALIGN_SHIFT;
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

    /// Returns a new set of flags with only the `IMAGE_SCN_MEM_*` flags set.
    #[inline]
    pub const fn memory_flags(self) -> Self {
        Self(self.0 & 0xfe000000)
    }

    /// Returns a new set of flags with only the `IMAGE_SCN_CNT_*` flags set.
    #[inline]
    pub const fn contents_flags(self) -> Self {
        Self(self.0 & 0xe0)
    }

    /// Returns the union of
    /// [`SectionFlags::memory_flags()`] `|` [`SectionFlags::contents_flags()`]
    #[inline]
    pub const fn kind_flags(self) -> Self {
        Self(self.memory_flags().0 | self.contents_flags().0)
    }
}
