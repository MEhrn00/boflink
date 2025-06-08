use crate::{link_yaml, setup_linker};
use boflink::linker::LinkerTargetArch;
use object::{
    Object, ObjectSection, ObjectSymbol,
    coff::{CoffFile, ImageSymbol},
};

#[test]
fn resized() {
    let linked = link_yaml!("resized.yaml", LinkerTargetArch::Amd64);
    let parsed: CoffFile = CoffFile::parse(linked.as_slice()).expect("Could not parse linked COFF");
    let bss_section = parsed
        .section_by_name(".bss")
        .expect("Could not find .bss section");

    assert_eq!(
        bss_section
            .coff_section()
            .size_of_raw_data
            .get(object::LittleEndian),
        48,
        ".bss section size should be 64"
    );
}

#[test]
fn common_symbols() {
    let linked = link_yaml!("commons.yaml", LinkerTargetArch::Amd64);
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("Could not parse linked COFF");

    const TEST_SYMBOLS: [(&str, u32); 2] = [("other_common", 0), ("common_symbol", 8)];

    for (symbol_name, symbol_value) in TEST_SYMBOLS {
        let symbol = coff
            .symbol_by_name(symbol_name)
            .unwrap_or_else(|| panic!("Could not find symbol '{symbol_name}'"));

        let section_idx = symbol
            .section_index()
            .unwrap_or_else(|| panic!("Could not get section index for symbol '{symbol_name}'"));

        let section = coff
            .section_by_index(section_idx)
            .unwrap_or_else(|e| panic!("Could not get section '{symbol_name}' is defined in: {e}"));

        let section_name = section.name().expect("Could not get section name");
        assert_eq!(
            section_name, ".bss",
            "'{symbol_name}' is not defined in the .bss section"
        );

        let value = symbol.coff_symbol().value.get(object::LittleEndian);
        assert_eq!(
            value, symbol_value,
            "'{symbol_name}' should be defined at address {symbol_value}"
        );
    }
}

#[test]
fn merged_bss_data() {
    let linked = setup_linker!("merged.yaml", LinkerTargetArch::Amd64)
        .merge_bss(true)
        .build()
        .link()
        .expect("Could not link files");

    let parsed: CoffFile = CoffFile::parse(linked.as_slice()).expect("Could not parse linked COFF");

    assert!(
        parsed.section_by_name(".bss").is_none_or(|section| section
            .coff_section()
            .size_of_raw_data
            .get(object::LittleEndian)
            == 0),
        "Output COFF should have an empty .bss section or none at all"
    );

    let data_section = parsed
        .section_by_name(".data")
        .expect("Could not find .data section");
    assert_eq!(
        data_section
            .coff_section()
            .size_of_raw_data
            .get(object::LittleEndian),
        32,
        ".data section size is not correct"
    );

    let data_section_data = data_section
        .data()
        .expect("Could not get .data section data");
    assert_eq!(
        data_section_data.len(),
        32,
        ".data section should have 32 bytes of initialized data"
    );
}

#[test]
fn commons_sorted() {
    let linker =
        setup_linker!("commons_sorted.yaml", LinkerTargetArch::Amd64).link_graph_path("graph.dot");

    let linked = linker.build().link().expect("Could not link files");

    let parsed: CoffFile = CoffFile::parse(linked.as_slice()).expect("Could not parse linked COFF");

    let mut symbols = parsed
        .symbols()
        .filter(|symbol| symbol.is_global())
        .map(|symbol| {
            (
                symbol.name().expect("Could not parse symbol name"),
                symbol.coff_symbol().value(),
            )
        })
        .collect::<Vec<_>>();

    // Sort the symbols by virtual address
    symbols.sort_by_key(|(_, address)| *address);

    // This is the order the symbols should be laid out. Largest should be at
    // the beginning of the section with smallest at the end.
    let expected_order: [&str; 8] = [
        "very_large",
        "large",
        "medium",
        "larger_than_small",
        "small",
        "smaller",
        "smallerer",
        "smallest",
    ];

    assert_eq!(
        expected_order.len(),
        symbols.len(),
        "The length of the expected symbol order list should match the number of symbols. Test is not setup correctly."
    );

    for ((found, _), expected) in symbols.iter().zip(expected_order.iter()) {
        assert_eq!(
            found, expected,
            "Symbols are not in the correct order: {symbols:#?}"
        );
    }
}
