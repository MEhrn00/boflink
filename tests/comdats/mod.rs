use boflink::linker::LinkerTargetArch;
use object::{Object, ObjectSection, coff::CoffFile, pe::IMAGE_SCN_LNK_COMDAT};

use crate::link_yaml;

#[test]
fn any() {
    let linked = link_yaml!("any.yaml", LinkerTargetArch::Amd64);

    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("Could not parse linked COFF");

    let rdata_section = coff
        .section_by_name(".rdata")
        .expect("Could not find .rdata section");

    let flags = rdata_section
        .coff_section()
        .characteristics
        .get(object::LittleEndian);
    assert_eq!(
        flags & IMAGE_SCN_LNK_COMDAT,
        0,
        "IMAGE_SCN_LNK_COMDAT flag should have been removed from the section characteristics"
    );

    let rdata_size = rdata_section
        .coff_section()
        .size_of_raw_data
        .get(object::LittleEndian);

    assert_eq!(
        rdata_size, 12,
        ".rdata section size should be 12. Section was not deduplicated"
    );
}

#[test]
fn associative() {
    let linked = link_yaml!("associative.yaml", LinkerTargetArch::Amd64);

    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("Could not parse linked COFF");

    let root_section = coff
        .section_by_name(".root")
        .expect("Could not find .root section");

    let root_data = root_section
        .data()
        .expect("Could not get .root section data");

    assert_eq!(root_data.len(), 16, ".root section data should be 16 bytes");

    assert!(
        root_data.iter().all(|b| *b == 0),
        ".root section data should be all zeros {root_data:x?}"
    );

    let assoc_section = coff
        .section_by_name(".assoc")
        .expect("Could not find .assoc section");

    let assoc_data = assoc_section
        .data()
        .expect("Could not get .assoc section data");

    assert_eq!(
        assoc_data.len(),
        16,
        ".assoc section data should be 16 bytes"
    );

    assert!(
        assoc_data.iter().all(|b| *b == 0),
        ".assoc section data should be all zeros"
    );
}
