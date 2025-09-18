use std::collections::{HashMap, hash_map};

use typed_arena::Arena;

use super::{ArchiveMemberMetadata, MemberSize, make_archive_member_buffer};

#[derive(Debug, PartialEq, Eq)]
pub enum ArchiveMemberName {
    LongNameOffset(usize),
    Value(String),
}

impl ArchiveMemberName {
    pub fn to_name_array(&self) -> [u8; 16] {
        match self {
            Self::LongNameOffset(offset) => {
                let s = format!("/{offset}");
                let mut buffer = [b' '; 16];
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer
            }
            Self::Value(s) => {
                debug_assert!(s.len() < std::mem::offset_of!(object::archive::Header, date));
                debug_assert!(s.chars().last().is_some_and(|v| v == '/'));

                let mut buffer = [b' '; 16];
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer
            }
        }
    }
}

#[derive(Default)]
pub struct ArchiveLongNamesBuilder<const DELIM: u8> {
    offset_map: HashMap<String, usize>,
    longnames: Arena<u8>,
}

impl<const DELIM: u8> ArchiveLongNamesBuilder<DELIM> {
    pub fn add_name(&mut self, name: impl Into<String>) -> ArchiveMemberName {
        let mut name = name.into();
        name.push('/');

        if name.len() < 16 {
            ArchiveMemberName::Value(name)
        } else {
            ArchiveMemberName::LongNameOffset(match self.offset_map.entry(name) {
                hash_map::Entry::Occupied(entry) => *entry.get(),
                hash_map::Entry::Vacant(entry) => {
                    let offset = self.longnames.len();

                    self.longnames.alloc_str(entry.key().as_str());
                    self.longnames.alloc(DELIM);

                    entry.insert(offset);
                    offset
                }
            })
        }
    }

    fn is_empty(&self) -> bool {
        self.longnames.len() == 0
    }

    pub fn build(self) -> Vec<u8> {
        // Do not build the long names member if it is empty
        if self.is_empty() {
            return Vec::new();
        }

        let mut buffer = make_archive_member_buffer(
            &ArchiveMemberName::Value("//".to_string()),
            &ArchiveMemberMetadata {
                ..Default::default()
            },
            &self,
        );

        buffer.append(&mut self.longnames.into_vec());

        // Padding
        if !buffer.len().is_multiple_of(2) {
            buffer.push(b'\n');
        }

        buffer
    }
}

impl<const DELIM: u8> MemberSize for ArchiveLongNamesBuilder<DELIM> {
    fn member_data_size(&self) -> usize {
        self.longnames.len()
    }

    fn member_size(&self) -> usize {
        // Return 0 if the longnames are empty
        if self.member_data_size() == 0 {
            return 0;
        }

        let size = std::mem::size_of::<object::archive::Header>() + self.member_data_size();
        if !size.is_multiple_of(2) {
            size + 1
        } else {
            size
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::archive::builder::MemberSize;

    use super::{ArchiveLongNamesBuilder, ArchiveMemberName};

    #[test]
    fn empty_build() {
        let longnames_member = ArchiveLongNamesBuilder::<b'\0'>::default();

        assert_eq!(
            longnames_member.member_size(),
            0,
            "calculated member size should be 0 for empty long names members"
        );

        let built = longnames_member.build();
        assert!(
            built.is_empty(),
            "long names member without any entries should be empty when built"
        );
    }

    #[test]
    fn trailing_slash() {
        let mut longnames_member = ArchiveLongNamesBuilder::<b'\0'>::default();
        assert_eq!(
            longnames_member.add_name("hello"),
            ArchiveMemberName::Value("hello/".to_string()),
            "trailing forward slash should have been added to the long names return value"
        );
    }

    #[test]
    fn offsets_valid() {
        let mut longnames_member = ArchiveLongNamesBuilder::<b'\0'>::default();
        let firstname = "abcdefghijklmnopqrstuvwxyz";

        assert_eq!(
            longnames_member.add_name(firstname),
            ArchiveMemberName::LongNameOffset(0),
            "this entry should be the first entry in the long names member"
        );

        let secondname = "testnametestnametestname";
        assert_eq!(
            longnames_member.add_name(secondname),
            ArchiveMemberName::LongNameOffset(firstname.len() + 2),
            "offset for the second entry in the long names member should be after the first",
        );

        let thirdname = "testingtestingtestingtest";

        assert_eq!(
            longnames_member.add_name(thirdname),
            ArchiveMemberName::LongNameOffset(firstname.len() + 2 + secondname.len() + 2)
        );
    }

    #[test]
    fn duplicates_same_offset() {
        let mut longnames_member = ArchiveLongNamesBuilder::<b'\0'>::default();

        let testvalue = "abcdefghijklmnopqrstuvwxyz";

        let first_value = longnames_member.add_name(testvalue);
        longnames_member.add_name("testnametestnametestname");

        let duplicate_value = longnames_member.add_name(testvalue);

        assert_eq!(
            first_value, duplicate_value,
            "duplicate strings inserted in the long names member should return the same offset"
        );
    }

    #[test]
    fn built_data_valid() {
        let mut longnames_member = ArchiveLongNamesBuilder::<b'\0'>::default();

        let first_string = "abcdefghijklmnopqrstuvwxyz";
        let first_name = longnames_member.add_name(first_string);

        let second_string = "testnametestnametestname";
        let second_name = longnames_member.add_name(second_string);

        let third_string = "testingtestingtestingtest";
        let third_name = longnames_member.add_name(third_string);

        let built_data = longnames_member.longnames.into_vec();

        let mut check_offset = 0;
        for (expected_string, expected_name) in [first_string, second_string, third_string]
            .iter()
            .zip([first_name, second_name, third_name])
        {
            assert_eq!(
                expected_name,
                ArchiveMemberName::LongNameOffset(check_offset),
                "found offset value for string '{expected_string}' in the long names data does not match the value returned when the string was inserted"
            );

            let check_str = std::ffi::CStr::from_bytes_until_nul(&built_data[check_offset..])
                .unwrap()
                .to_str()
                .unwrap();

            assert_eq!(
                format!("{expected_string}/"),
                check_str,
                "string value at offset {check_offset} does not match the expected value"
            );

            check_offset += check_str.len() + 1;
        }
    }

    #[test]
    fn aligned() {
        let name = "abcdefghijklmnopqrstuvwxyz";

        // The test name should have an even length
        assert!(
            name.len().is_multiple_of(2),
            "test string '{name}' length should be even"
        );

        let mut longnames_member = ArchiveLongNamesBuilder::<b'\0'>::default();
        longnames_member.add_name(name);

        let built = longnames_member.build();
        assert!(
            !built.is_empty(),
            "built long names member should not be empty"
        );

        assert!(
            built.len() % 2 == 0,
            "built long names member for an even data length is not 2 byte aligned. length = {}",
            built.len()
        );

        let name = "abcdefghijklmnopqrstuvwxy";

        // The test name should have an odd length
        assert!(
            !name.len().is_multiple_of(2),
            "test string '{name}' length should be odd"
        );

        let mut longnames_member = ArchiveLongNamesBuilder::<b'\0'>::default();
        longnames_member.add_name(name);

        let built = longnames_member.build();
        assert!(
            !built.is_empty(),
            "built long names member should not be empty"
        );

        assert!(
            built.len() % 2 == 0,
            "built long names member for an odd data length is not 2 byte aligned. length = {}",
            built.len()
        );
    }
}
