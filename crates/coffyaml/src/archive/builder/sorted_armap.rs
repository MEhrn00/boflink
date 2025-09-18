use std::collections::{HashMap, HashSet};

use indexmap::IndexSet;

use super::{
    ArchiveMemberIndex, ArchiveMemberMetadata, MemberSize, longnames::ArchiveMemberName,
    make_archive_member_buffer,
};

#[derive(Default)]
pub struct SortedArchiveMapBuilder {
    member_indicies: HashSet<ArchiveMemberIndex>,
    string_indicies: HashSet<(String, ArchiveMemberIndex)>,
    string_table_size: usize,
}

impl SortedArchiveMapBuilder {
    pub fn add_symbol(&mut self, index: ArchiveMemberIndex, symbol: impl AsRef<str>) {
        let symbol_len = symbol.as_ref().len();
        if !self
            .string_indicies
            .insert((symbol.as_ref().to_string(), index))
        {
            return;
        }

        self.member_indicies.insert(index);
        self.string_table_size += symbol_len + 1;
    }

    pub fn build(self, archive_map: &HashMap<ArchiveMemberIndex, usize>) -> Vec<u8> {
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

        // Create the sorted member offsets
        let mut member_offsets: IndexSet<usize> =
            IndexSet::from_iter(self.member_indicies.into_iter().map(|member_id| {
                *archive_map
                    .get(&member_id)
                    .unwrap_or_else(|| unreachable!())
            }));

        member_offsets.sort();

        // Add the number of members
        buffer.extend((member_offsets.len() as u32).to_le_bytes());

        // Add the member offsets
        buffer.extend(
            member_offsets
                .iter()
                .flat_map(|offset| (*offset as u32).to_le_bytes()),
        );

        // Create the sorted strings
        let mut string_table = self.string_indicies.into_iter().collect::<Vec<_>>();
        string_table.sort_by(|(a, _), (b, _)| a.cmp(b));

        // Add the number of symbols
        buffer.extend((string_table.len() as u32).to_le_bytes());

        // Add the symbol indices
        for (_, archive_idx) in &string_table {
            let member_offset = *archive_map
                .get(archive_idx)
                .unwrap_or_else(|| unreachable!());

            let table_index = member_offsets
                .get_index_of(&member_offset)
                .unwrap_or_else(|| unreachable!());

            buffer.extend(u16::try_from(table_index + 1).unwrap().to_le_bytes());
        }

        // Add the strings
        for (symbol, _) in string_table {
            buffer.extend(symbol.as_bytes());
            buffer.push(0);
        }

        // Padding
        if !buffer.len().is_multiple_of(2) {
            buffer.push(b'\n');
        }

        buffer
    }
}

impl MemberSize for SortedArchiveMapBuilder {
    fn member_data_size(&self) -> usize {
        4 + 4 * self.member_indicies.len()
            + 4
            + 2 * self.string_indicies.len()
            + self.string_table_size
    }
}
