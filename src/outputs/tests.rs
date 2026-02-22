use std::borrow::Cow;

use object::SectionIndex;

use crate::object::ObjectFileId;

use super::{MappedSection, SectionMappingTable};

#[test]
fn find_object_mappings() {
    let table = SectionMappingTable(vec![
        MappedSection {
            remaining: 1,
            obj: ObjectFileId::new(0),
            index: SectionIndex(1),
            relocs: Cow::Borrowed(&[]),
            rva: 0,
        },
        MappedSection {
            remaining: 0,
            obj: ObjectFileId::new(0),
            index: SectionIndex(1),
            relocs: Cow::Borrowed(&[]),
            rva: 0,
        },
        MappedSection {
            remaining: 3,
            obj: ObjectFileId::new(1),
            index: SectionIndex(1),
            relocs: Cow::Borrowed(&[]),
            rva: 0,
        },
        MappedSection {
            remaining: 2,
            obj: ObjectFileId::new(1),
            index: SectionIndex(2),
            relocs: Cow::Borrowed(&[]),
            rva: 0,
        },
        MappedSection {
            remaining: 1,
            obj: ObjectFileId::new(1),
            index: SectionIndex(3),
            relocs: Cow::Borrowed(&[]),
            rva: 0,
        },
        MappedSection {
            remaining: 0,
            obj: ObjectFileId::new(1),
            index: SectionIndex(4),
            relocs: Cow::Borrowed(&[]),
            rva: 0,
        },
        MappedSection {
            remaining: 2,
            obj: ObjectFileId::new(1),
            index: SectionIndex(2),
            relocs: Cow::Borrowed(&[]),
            rva: 0,
        },
        MappedSection {
            remaining: 1,
            obj: ObjectFileId::new(1),
            index: SectionIndex(3),
            relocs: Cow::Borrowed(&[]),
            rva: 0,
        },
        MappedSection {
            remaining: 2,
            obj: ObjectFileId::new(2),
            index: SectionIndex(1),
            relocs: Cow::Borrowed(&[]),
            rva: 0,
        },
        MappedSection {
            remaining: 1,
            obj: ObjectFileId::new(2),
            index: SectionIndex(2),
            relocs: Cow::Borrowed(&[]),
            rva: 0,
        },
        MappedSection {
            remaining: 0,
            obj: ObjectFileId::new(2),
            index: SectionIndex(3),
            relocs: Cow::Borrowed(&[]),
            rva: 0,
        },
    ]);

    let slice = table.find_object_mappings(ObjectFileId::new(0));
    assert!(slice.len() == 2);
    assert!(slice.iter().all(|m| m.obj == ObjectFileId::new(0)));

    let slice = table.find_object_mappings(ObjectFileId::new(3));
    assert!(slice.is_empty());
}
