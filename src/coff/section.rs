use bitflags::bitflags;
use object::pe;

/// A COFF section header table
pub type SectionTable<'a> = object::coff::SectionTable<'a>;

/// Shift value for extracting the alignment from section flags
pub const SECTION_FLAGS_ALIGN_SHIFT: usize = 20;

/// Trait for abstracting various routines when dealing with sections.
///
/// This allows querying information about a section without needing to use the
/// underlying const values.
pub trait Section {
    /// Returns the name of the section.
    ///
    /// This could either be the full section name or the short form of it
    /// depending on if the concrete section type stores that information.
    fn name_bytes(&self) -> &[u8];

    /// Returns the `SizeOfRawData` field used for the section.
    ///
    /// This is either the size of the file-backed data or the size of an
    /// uninitialized section.
    fn size_of_raw_data(&self) -> u32;

    /// Returns the `Characteristics` flags from the section.
    fn characteristics(&self) -> u32;

    /// Returns [`SectionFlags`] representation of the characteristics for
    /// extracting specific section information.
    fn section_flags(&self) -> SectionFlags {
        SectionFlags(self.characteristics())
    }

    /// Returns `true` if this is a COMDAT section.
    fn is_comdat(&self) -> bool {
        self.characteristics() & pe::IMAGE_SCN_LNK_COMDAT != 0
    }

    /// Returns the section alignment
    fn alignment(&self) -> u32 {
        self.section_flags().alignment()
    }

    /// Returns `true` if this section contains uninitialized data.
    fn contains_uninitialized_data(&self) -> bool {
        self.characteristics() & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
    }

    /// Returns `true` if this section contains executable code
    fn contains_code(&self) -> bool {
        let flags = pe::IMAGE_SCN_CNT_CODE | pe::IMAGE_SCN_MEM_EXECUTE;
        self.characteristics() & flags == flags
    }

    /// Returns `true` if this is a debug section with codeview debug information.
    fn is_codeview(&self) -> bool {
        let names = [b".debug$F", b".debug$P", b".debug$S", b".debug$T"];

        let debug_flags =
            pe::IMAGE_SCN_CNT_CODE | pe::IMAGE_SCN_MEM_READ | pe::IMAGE_SCN_MEM_DISCARDABLE;
        let scn_flags = self.characteristics();
        let name = self.name_bytes();
        scn_flags & debug_flags == debug_flags
            && scn_flags & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA == 0
            && self.size_of_raw_data() > 0
            && names.iter().any(|&n| n == name)
    }

    /// Returns `true` if the `IMAGE_SCN_MEM_DISCARDABLE` flag is set
    fn is_mem_discardable(&self) -> bool {
        self.characteristics() & pe::IMAGE_SCN_MEM_DISCARDABLE != 0
    }

    /// Returns `true` if this section contains import metadata.
    fn contains_import_data(&self) -> bool {
        let names = [
            b".idata$2",
            b".idata$3",
            b".idata$4",
            b".idata$5",
            b".idata$6",
            b".idata$7",
        ];

        // MinGW will not set the `IMAGE_SCN_CNT_INITIALIZED_DATA` flag properly
        // in import libraries. Just test if the section is readable and
        // !(executable or code or uninitialized data)

        let scn_flags = self.characteristics();
        let name = self.name_bytes();
        scn_flags & pe::IMAGE_SCN_MEM_READ != 0
            && scn_flags
                & (pe::IMAGE_SCN_MEM_EXECUTE
                    | pe::IMAGE_SCN_CNT_CODE
                    | pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                == 0
            && names.iter().any(|&n| n == name)
    }
}

impl Section for &pe::ImageSectionHeader {
    fn name_bytes(&self) -> &[u8] {
        self.raw_name()
    }

    fn size_of_raw_data(&self) -> u32 {
        self.size_of_raw_data.get(object::LittleEndian)
    }

    fn characteristics(&self) -> u32 {
        self.characteristics.get(object::LittleEndian)
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
    pub const fn memory_flags(self) -> Self {
        Self(self.0 & 0xfe000000)
    }

    /// Returns a new set of flags with only the `IMAGE_SCN_CNT_*` flags set.
    pub const fn contents_flags(self) -> Self {
        Self(self.0 & 0xe0)
    }

    /// Returns the union of
    /// [`SectionFlags::memory_flags()`] `|` [`SectionFlags::contents_flags()`]
    pub const fn kind_flags(self) -> Self {
        Self(self.memory_flags().0 | self.contents_flags().0)
    }
}

/// Computes a section checksum from the specified data.
///
/// This is the JamCRC checksum with an init value of -1
pub fn compute_checksum(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new_with_initial(u32::MAX);
    h.update(data);
    !h.finalize()
}
