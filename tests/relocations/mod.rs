use boflink::linker::LinkerTargetArch;
use object::{
    Object, ObjectSection, ObjectSymbol,
    coff::{CoffFile, ImageSymbol},
    pe::IMAGE_REL_AMD64_ADDR64,
};

use crate::link_yaml;

#[test]
fn same_section_flattened() {
    let linked = link_yaml!("same_section_flattened.yaml", LinkerTargetArch::Amd64);
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("Could not parse linked COFF");

    let text_section = coff
        .section_by_name(".text")
        .expect("Could not find .text section in linked COFF");

    assert_eq!(
        text_section
            .coff_section()
            .number_of_relocations
            .get(object::LittleEndian),
        0,
        ".text section header should have 0 for the number of relocations"
    );

    let reloc_count = text_section
        .coff_relocations()
        .expect("Could not get COFF relocations")
        .len();
    assert_eq!(reloc_count, 0, ".text section should have 0 relocations");

    // Check the relocation to see if it was applied properly so that it points
    // to the target symbol
    let target_symbol = coff
        .symbol_by_name("external_function")
        .expect("Could not get external_function symbol");

    let symbol_addr = target_symbol.coff_symbol().value.get(object::LittleEndian);

    let section_data = text_section
        .data()
        .expect("Could not get .text section data");

    let found_reloc_val = u32::from_le_bytes(section_data[2..6].try_into().unwrap());
    let expected_reloc_val = symbol_addr - 2 - 4;

    assert_eq!(
        found_reloc_val, expected_reloc_val,
        "Flattened relocation value does not point to the target symbol"
    );
}

#[test]
fn section_target_shifted() {
    let linked = link_yaml!("section_target_shifted.yaml", LinkerTargetArch::Amd64);
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("Could not parse linked COFF");

    let text_section = coff
        .section_by_name(".text")
        .expect("Could not find .text section in linked COFF");

    let reloc = text_section
        .coff_relocations()
        .expect("Could not get .text section relocation")
        .iter()
        .next()
        .expect(".text section should have a relocation");

    let reloc_addr = reloc.virtual_address.get(object::LittleEndian);

    let section_data = text_section
        .data()
        .expect("Could not get .text section data");

    let found_reloc_val = u32::from_le_bytes(
        section_data[reloc_addr as usize..reloc_addr as usize + 4]
            .try_into()
            .unwrap(),
    );

    assert_eq!(
        found_reloc_val, 16,
        "Relocation value should point to virtual address of shifted section"
    );
}

#[test]
fn defined_symbol_target_no_shift() {
    let linked = link_yaml!(
        "defined_symbol_target_no_shift.yaml",
        LinkerTargetArch::Amd64
    );
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("Could not parse linked COFF");

    let text_section = coff
        .section_by_name(".text")
        .expect("Could not find .text section in linked COFF");

    let reloc = text_section
        .coff_relocations()
        .expect("Could not get .text section relocation")
        .iter()
        .next()
        .expect(".text section should have a relocation");

    let target_symbol = coff
        .symbol_by_index(reloc.symbol())
        .expect("Could not get relocation target symbol");

    let target_name = target_symbol
        .name()
        .expect("Could not get target symbol name");

    assert_eq!(
        target_name, "target_symbol",
        "Relocation target symbol name should be 'target_symbol'"
    );

    let reloc_addr = reloc.virtual_address.get(object::LittleEndian);

    let section_data = text_section
        .data()
        .expect("Could not get .text section data");

    let found_reloc_val = u32::from_le_bytes(
        section_data[reloc_addr as usize..reloc_addr as usize + 4]
            .try_into()
            .unwrap(),
    );

    assert_eq!(
        found_reloc_val, 0,
        "Relocation value should not have shifted"
    );
}

#[test]
fn same_section_symbol_flattened() {
    let linked = link_yaml!(
        "same_section_symbol_flattened.yaml",
        LinkerTargetArch::Amd64
    );

    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("Could not parse linked COFF");

    let text_section = coff
        .section_by_name(".text")
        .expect("Could not find .text section in linked COFF");

    let text_section_data = text_section
        .data()
        .expect("Could not get .text section data");

    // Get the relocation from the source2_function symbol which calls the
    // other symbol
    let source2_function = coff
        .symbol_by_name("source2_function")
        .expect("Could not find source2_function symbol");

    let other = coff
        .symbol_by_name("other")
        .expect("Could not find other symbol");

    let reloc_addr = source2_function.coff_symbol().value() + 9;

    let found_reloc_val = u32::from_le_bytes(
        text_section_data[reloc_addr as usize..reloc_addr as usize + 4]
            .try_into()
            .unwrap(),
    );

    // The reloc value should = target symbol - 4 - reloc_addr
    let expected_reloc_val = other.coff_symbol().value() - 4 - reloc_addr;

    assert_eq!(
        found_reloc_val, expected_reloc_val,
        "Relocation value in the 'source2_function' that references the other did not get adjusted correctly"
    );
}

#[test]
fn addr_intrasection() {
    let linked = link_yaml!("addr_intrasection.yaml", LinkerTargetArch::Amd64);

    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("Could not parse linked COFF");

    let text_section = coff
        .section_by_name(".text")
        .expect("Could not find .text section in linked COFF");

    let text_section_data = text_section
        .data()
        .expect("Could not get .text section data");

    let tests = [
        (IMAGE_REL_AMD64_ADDR64, 0, 0),
        (IMAGE_REL_AMD64_ADDR64, 8, 48),
        (IMAGE_REL_AMD64_ADDR64, 16, 0),
        (IMAGE_REL_AMD64_ADDR64, 24, 0),
        (IMAGE_REL_AMD64_ADDR64, 32, 48),
        (IMAGE_REL_AMD64_ADDR64, 48, 48),
        (IMAGE_REL_AMD64_ADDR64, 56, 0),
    ];

    for (idx, (reloc, (typ, addr, value))) in text_section
        .coff_relocations()
        .expect("Could not get COFF relocations")
        .iter()
        .zip(tests)
        .enumerate()
    {
        assert_eq!(
            reloc.typ.get(object::LittleEndian),
            typ,
            "{}: expected reloc type = {}, found = {}",
            idx + 1,
            typ,
            reloc.typ.get(object::LittleEndian),
        );
        assert_eq!(
            reloc.virtual_address.get(object::LittleEndian),
            addr,
            "{}: expected virtual address = {}, found = {}",
            idx + 1,
            addr,
            reloc.virtual_address.get(object::LittleEndian),
        );

        let addr = addr as usize;

        let reloc_value = u64::from_le_bytes(text_section_data[addr..addr + 8].try_into().unwrap());
        assert_eq!(
            reloc_value,
            value,
            "{}: expected reloc value = {}, found = {}",
            idx + 1,
            value,
            reloc_value,
        );
    }
}
