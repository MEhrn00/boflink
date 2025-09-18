use std::collections::HashMap;

use typed_arena::Arena;

use super::{
    ArchiveMemberIndex, ArchiveMemberMetadata, MemberSize, longnames::ArchiveMemberName,
    make_archive_member_buffer,
};

#[derive(Default)]
pub struct ArchiveMapBuilder {
    /// The archive member indicies
    indicies: Arena<ArchiveMemberIndex>,

    /// The string table
    string_table: Arena<u8>,
}

impl ArchiveMapBuilder {
    /// Adds a symbol to the archive map
    pub fn add_symbol(&self, index: ArchiveMemberIndex, symbol: impl AsRef<str>) {
        self.indicies.alloc(index);
        self.string_table.alloc_str(symbol.as_ref());
        self.string_table.alloc(0);
    }

    /// Builds the armap with the specified offsets
    pub fn build(mut self, archive_map: &HashMap<ArchiveMemberIndex, usize>) -> Vec<u8> {
        let mut buffer = make_archive_member_buffer(
            &ArchiveMemberName::Value("/".to_string()),
            &ArchiveMemberMetadata {
                date: Some(0),
                uid: Some(0),
                gid: Some(0),
                mode: Some(0),
            },
            &self,
        );

        // Number of symbols
        buffer.extend((self.indicies.len() as u32).to_be_bytes());

        // Offsets
        for archive_index in self.indicies.iter_mut() {
            let offset = *archive_map
                .get(archive_index)
                .unwrap_or_else(|| unreachable!());
            buffer.extend((offset as u32).to_be_bytes());
        }

        // String table
        buffer.append(&mut self.string_table.into_vec());

        // Padding
        if !buffer.len().is_multiple_of(2) {
            buffer.push(b'\n');
        }

        buffer
    }
}

impl MemberSize for ArchiveMapBuilder {
    fn member_data_size(&self) -> usize {
        4 + 4 * self.indicies.len() + self.string_table.len()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::archive::builder::ArchiveMemberIndex;

    use super::ArchiveMapBuilder;

    #[test]
    fn correct_symbol_count() {
        const TEST_COUNTS: &[usize] = &[5, 10, 20, 100, 1024];

        for &test_count in TEST_COUNTS {
            let symbol_map = ArchiveMapBuilder::default();

            for v in 0..test_count {
                symbol_map.add_symbol(ArchiveMemberIndex(0), format!("{v}"));
            }

            let built = symbol_map.build(&HashMap::from([(ArchiveMemberIndex(0), 0)]));
            let found_symbol_count = u32::from_be_bytes(built[60..60 + 4].try_into().unwrap());

            assert_eq!(
                test_count as u32, found_symbol_count,
                "expected number of symbols in the built archive map does not match the found value"
            );
        }
    }

    #[test]
    fn table_entries_remapped() {
        const TEST_VALUES: &[(ArchiveMemberIndex, usize)] = &[
            (ArchiveMemberIndex(0), 10),
            (ArchiveMemberIndex(1), 20),
            (ArchiveMemberIndex(0), 10),
            (ArchiveMemberIndex(2), 100),
            (ArchiveMemberIndex(3), 200),
        ];

        let test_symbols = TEST_VALUES
            .iter()
            .enumerate()
            .map(|(idx, _)| format!("symbol{idx}"))
            .collect::<Vec<_>>();

        let symbol_map = ArchiveMapBuilder::default();

        for ((member_idx, _), symbol) in TEST_VALUES.iter().zip(test_symbols.iter()) {
            symbol_map.add_symbol(*member_idx, symbol);
        }

        let symbol_remap: HashMap<ArchiveMemberIndex, usize> =
            HashMap::from_iter(TEST_VALUES.iter().copied());

        let built = symbol_map.build(&symbol_remap);
        let armap_data = &built[60..];

        let symbol_count = u32::from_be_bytes(armap_data[..4].try_into().unwrap());
        assert_eq!(
            TEST_VALUES.len(),
            symbol_count as usize,
            "not all symbols were added to the archive map"
        );

        let mut offset_iter = armap_data[4..].chunks_exact(4);
        for (_, expected_offset) in TEST_VALUES {
            let found_offset = u32::from_be_bytes(offset_iter.next().unwrap().try_into().unwrap());
            assert_eq!(
                *expected_offset, found_offset as usize,
                "found offset value for built symbol map does not match expected value"
            );
        }
    }

    #[test]
    fn aligned() {
        const TEST_VALUES: &[(ArchiveMemberIndex, usize)] = &[
            (ArchiveMemberIndex(0), 10),
            (ArchiveMemberIndex(1), 100),
            (ArchiveMemberIndex(0), 1000),
            (ArchiveMemberIndex(0), 2000),
            (ArchiveMemberIndex(2), 10000),
            (ArchiveMemberIndex(3), 100000),
        ];

        let test_symbols = TEST_VALUES
            .iter()
            .map(|(_, idx)| format!("symbol{idx}"))
            .collect::<Vec<_>>();

        for i in 1..=TEST_VALUES.len() {
            let symbol_map = ArchiveMapBuilder::default();
            for ((member_idx, _), symbol) in TEST_VALUES.iter().take(i).zip(test_symbols.iter()) {
                symbol_map.add_symbol(*member_idx, symbol);
            }

            let archive_map: HashMap<ArchiveMemberIndex, usize> =
                HashMap::from_iter(TEST_VALUES.iter().take(i).copied());

            let built = symbol_map.build(&archive_map);
            assert!(
                built.len() % 2 == 0,
                "built archive map member with {i} symbols should be 2-byte aligned",
            );
        }
    }
}
