use boflink::linker::LinkerTargetArch;
use object::{
    Object,
    coff::CoffFile,
    pe::{
        IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE,
        IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    },
};

use crate::setup_linker;

#[test]
fn externals_relaxation() {
    // The entrypoint will be added as an undefined external. Since there will
    // be no references and the symbol is undefined, the BOF should link
    let _ = setup_linker!("externals_relaxation.yaml", LinkerTargetArch::Amd64)
        .entrypoint("go")
        .build()
        .link()
        .expect("Could not link files");
}

#[test]
fn no_merge_groups() {
    let linked = setup_linker!("no_merge_groups.yaml", LinkerTargetArch::Amd64)
        .merge_grouped_sections(false)
        .build()
        .link()
        .expect("Could not link inputs");

    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("Could not parse linked output");

    let test_sections: &[(&str, u32)] = &[
        (
            ".text$a",
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        ),
        (
            ".text$b",
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        ),
        (
            ".text$c",
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        ),
        (
            ".data$a",
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        ),
        (
            ".data$b",
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        ),
        (
            ".data$c",
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        ),
    ];

    for &(test_name, test_characteristics) in test_sections {
        let section = coff
            .section_by_name(test_name)
            .unwrap_or_else(|| panic!("Could not find section {test_name}"));

        let characteristics = section
            .coff_section()
            .characteristics
            .get(object::LittleEndian);

        assert!(
            characteristics & test_characteristics == test_characteristics,
            "{test_name} section has invalid characteristics. characteristics = {characteristics:#x?}, test_characteristics = {test_characteristics:#x?}, contained = {:#x?}",
            characteristics & test_characteristics
        );
    }
}
