use object::pe;

pub trait SectionChunk<'a> {
    /// Raw name of the section.
    ///
    /// Either the short or long name.
    fn name_bytes(&self) -> &'a [u8];

    /// The `IMAGE_SCN_CNT_*` flags of the section
    fn contents_flags(&self) -> u32;

    /// The `IMAGE_SCN_MEM_*` flags of the section
    fn memory_flags(&self) -> u32;

    /// Section alignment as a power of 2.
    fn p2align(&self) -> P2Align;

    #[inline]
    fn alignment(&self) -> u32 {
        self.p2align().value()
    }

    #[inline]
    fn is_codeview(&self) -> bool {
        let names = [b".debug$F", b".debug$S", b".debug$P", b".debug$T"];
        let name = self.name_bytes();
        self.memory_flags() & pe::IMAGE_SCN_MEM_DISCARDABLE != 0 && names.iter().any(|&n| name == n)
    }

    #[inline]
    fn is_dwarf_debug(&self) -> bool {
        self.memory_flags() & pe::IMAGE_SCN_MEM_DISCARDABLE != 0
            && self.name_bytes().starts_with(b".debug_")
    }

    #[inline]
    fn is_debug(&self) -> bool {
        self.is_codeview() || self.is_dwarf_debug()
    }

    #[inline]
    fn is_idata(&self) -> bool {
        let name = self.name_bytes();
        name == b".idata" || name.starts_with(b".idata$")
    }

    #[inline]
    fn is_import_dir(&self) -> bool {
        self.name_bytes() == b".idata$2"
    }

    #[inline]
    fn is_import_lookup(&self) -> bool {
        self.name_bytes() == b".idata$4"
    }

    #[inline]
    fn is_import_address(&self) -> bool {
        self.name_bytes() == b".idata$5"
    }

    #[inline]
    fn is_import_hintname(&self) -> bool {
        self.name_bytes() == b".idata$6"
    }

    #[inline]
    fn is_import_dllname(&self) -> bool {
        self.name_bytes() == b".idata$7"
    }

    #[inline]
    fn is_gc_retained(&self) -> bool {
        self.is_idata() || self.is_debug()
    }
}

/// Alignment value internally represented as log2
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct P2Align(u8);

impl P2Align {
    #[inline]
    pub const fn value(&self) -> u32 {
        1u32 << self.0
    }

    /// Extracts the section alignment from the specified `IMAGE_SCN_*`
    /// flags
    #[inline]
    pub fn from_scn_flags(flags: u32) -> Self {
        if flags & pe::IMAGE_SCN_TYPE_NO_PAD != 0 {
            return Self(1);
        }

        let v = ((flags >> 20) & 0xf).saturating_sub(1) as u8;
        Self(v.min(13))
    }

    /// Converts the alignment to a set of `IMAGE_SCN_*` flags
    #[inline]
    pub fn to_scn_flags(&self) -> u32 {
        ((self.0 + 1) as u32) << 20
    }

    #[inline]
    pub fn from_value(value: u32) -> Self {
        let value = value.max(1);

        assert!(value.is_power_of_two(), "align value be a power of two");
        assert!(
            value <= 8192,
            "align value must be within range 0 <= align <= 8192"
        );

        Self(value.ilog2() as u8)
    }
}

#[derive(Debug, Default, Clone)]
pub struct Chunk {
    pub rva: u32,
    p2align: u8,
}

impl Chunk {
    #[inline]
    pub fn set_alignment(&mut self, value: usize) {
        let value = value.max(1);
        assert!(
            value.is_power_of_two(),
            "alignment value must be a power of two"
        );
        assert!(
            value <= 8192,
            "alignment must be within range 0 <= align <= 8192"
        );

        self.p2align = value.ilog2() as u8;
    }

    #[inline]
    pub const fn alignment(&self) -> usize {
        1usize << self.p2align
    }
}

pub fn compute_checksum(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new_with_initial(!0);
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use object::pe;

    use super::P2Align;

    #[test]
    fn p2align_scn_roundtrip() {
        let tests = [
            pe::IMAGE_SCN_ALIGN_1BYTES,
            pe::IMAGE_SCN_ALIGN_2BYTES,
            pe::IMAGE_SCN_ALIGN_4BYTES,
            pe::IMAGE_SCN_ALIGN_8BYTES,
            pe::IMAGE_SCN_ALIGN_16BYTES,
            pe::IMAGE_SCN_ALIGN_32BYTES,
            pe::IMAGE_SCN_ALIGN_64BYTES,
            pe::IMAGE_SCN_ALIGN_128BYTES,
            pe::IMAGE_SCN_ALIGN_256BYTES,
            pe::IMAGE_SCN_ALIGN_512BYTES,
            pe::IMAGE_SCN_ALIGN_1024BYTES,
            pe::IMAGE_SCN_ALIGN_2048BYTES,
            pe::IMAGE_SCN_ALIGN_4096BYTES,
            pe::IMAGE_SCN_ALIGN_8192BYTES,
        ];

        for input in tests {
            let align = P2Align::from_scn_flags(input);
            let val = align.to_scn_flags();
            assert_eq!(val, input);
        }
    }
}
