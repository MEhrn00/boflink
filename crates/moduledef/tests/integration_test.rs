#[test]
fn basic_def() {
    let data = include_str!("basic.def");

    let module = moduledef::ModuleFile::parse(data).expect("Could not parse basic.def");

    assert_eq!(module.module_name(), Some("basic"));

    let test_exports = ["BasicExport1", "BasicExport2", "BasicExport3"];
    for (export, test_export) in module.exports().zip(test_exports) {
        let export = export.expect("Could not parse export definition");
        assert_eq!(export.entryname(), test_export);
    }
}
