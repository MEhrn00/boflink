use assert_cmd::cargo::cargo_bin_cmd;
use object::{Object, ObjectSection, ObjectSymbol, coff::CoffFile};
use tempfile::NamedTempFile;

use crate::utils::tools::{asm, asm1, dlltool};

mod utils;

#[test]
fn bss_resized() {
    let objs = asm([
        r#"
.section .bss
.space 32
"#,
        r#"
.section .bss
.space 16
"#,
    ]
    .iter());

    let out = NamedTempFile::new().expect("failed creating output tempfile");

    cargo_bin_cmd!()
        .arg("-o")
        .arg(out.path())
        .args(objs.paths())
        .assert()
        .success();

    let linked = std::fs::read(out.path()).expect("failed reading output");
    let parsed: CoffFile =
        CoffFile::parse(linked.as_slice()).expect("failed parsing linked output");

    let bss_section = parsed
        .section_by_name(".bss")
        .expect("Could not find .bss section");

    assert_eq!(
        bss_section
            .coff_section()
            .size_of_raw_data
            .get(object::LittleEndian),
        48,
        ".bss section size should be 48"
    );
}

#[test]
fn commons_sorting() {
    let obj = asm1(
        r#"
.comm small,4
.comm large,32"#,
    );

    let out = NamedTempFile::new().expect("failed creating output tempfile");

    cargo_bin_cmd!()
        .arg("-o")
        .arg(out.path())
        .args(obj.paths())
        .assert()
        .success();

    let linked = std::fs::read(out.path()).expect("failed reading output");
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("failed parsing linked output");

    let small = coff
        .symbol_by_name("small")
        .expect("failed finding small symbol");
    let large = coff
        .symbol_by_name("large")
        .expect("failed finding large symbol");

    // Larger common symbols should be placed at lower addresses
    assert!(
        large.address() < small.address(),
        "common symbol ordering is out of place"
    );
}

#[test]
fn any_comdat_first_seen() {
    let objs = asm([
        r#"
.globl foo
.section .text$foo,"x",discard,foo
foo:
  ret
"#,
        r#"
.globl foo
.section .text$foo,"x",discard,foo
foo:
  nop
  nop
  nop
  ret
"#,
    ]
    .iter());

    let out = NamedTempFile::new().expect("failed creating output tempfile");

    cargo_bin_cmd!()
        .arg("-o")
        .arg(out.path())
        .args(objs.paths())
        .assert()
        .success();

    let linked = std::fs::read(out.path()).expect("failed reading output");
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("failed parsing linked output");

    let code = coff
        .section_by_name(".text")
        .expect("cannot find .text section")
        .data()
        .expect("cannot parse .text section data");

    // Only the function with the single ret instruction should have been kept
    assert_eq!(code, b"\xc3");
}

#[test]
fn fail_no_gc_roots() {
    let obj = asm1(
        r#"
.globl foo
.text
foo:
  ret"#,
    );

    let out = NamedTempFile::new().expect("failed creating output tempfile");

    // This should fail since GC roots could not be found
    cargo_bin_cmd!()
        .arg("-o")
        .arg(out.path())
        .arg("--gc-sections")
        .args(obj.paths())
        .assert()
        .failure();
}

#[test]
fn dfr_prefix() {
    let obj = asm1(".globl __imp_foo");
    let importlib = dlltool(
        r#"
LIBRARY foolib.dll
EXPORTS
foo"#,
    );

    let out = NamedTempFile::new().expect("failed creating output tempfile");

    cargo_bin_cmd!()
        .arg("-o")
        .arg(out.path())
        .args(obj.paths())
        .arg(importlib.path())
        .assert()
        .success();

    let linked = std::fs::read(out.path()).expect("failed reading output");
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("failed parsing linked output");

    // Look for the DFR symbol
    assert!(coff.symbol_by_name("__imp_foolib$foo").is_some());
}

#[test]
fn dllimport_thunks() {
    let obj = asm1(
        r#"
.globl go, memset
.text
go:
  call memset
  nop
  nop
  nop
        "#,
    );

    let importlib = dlltool(
        r#"
LIBRARY MSVCRT.dll
EXPORTS
memset"#,
    );

    let out = NamedTempFile::new().expect("failed creating output tempfile");

    cargo_bin_cmd!()
        .arg("-o")
        .arg(out.path())
        .args(obj.paths())
        .arg(importlib.path())
        .assert()
        .success();

    let linked = std::fs::read(out.path()).expect("failed reading output");
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("failed parsing linked output");

    let code_section = coff
        .section_by_name(".text")
        .expect("failed getting code section");

    let code = code_section
        .data()
        .expect("failed getting code section data");

    // Original memset call should now be resolved to the memset thunk at .text+0x8
    // call $+8
    assert_eq!(code[..5], [0xe8, 0x03, 0x00, 0x00, 0x00]);

    // The memset symbol should now be defined as a jmp [rip] thunk with a
    // relocation that targets __imp_MSVCRT$memset
    assert_eq!(code[8..14], [0xff, 0x25, 0x00, 0x00, 0x00, 0x00]);

    let code_relocs = code_section
        .coff_relocations()
        .expect("failed getting code section relocs");

    let thunk_reloc = code_relocs
        .iter()
        .find(|reloc| reloc.virtual_address.get(object::LittleEndian) == 10)
        .expect("cannot find memset thunk relocation");

    let import_symbol = coff
        .symbol_by_index(thunk_reloc.symbol())
        .expect("failed getting import symbol for thunk");

    let name = import_symbol
        .name()
        .expect("failed getting import symbol name");

    assert_eq!(name, "__imp_MSVCRT$memset");
}

#[test]
fn no_merge_groups() {
    let obj = asm1(
        r#"
.section .text$a,"x"
.quad 0
.section .text$b,"x"
.quad 0
.section .text$c,"x"
.quad 0"#,
    );

    let out = NamedTempFile::new().expect("failed creating output tempfile");

    cargo_bin_cmd!()
        .arg("-o")
        .arg(out.path())
        .arg("--no-merge-groups")
        .args(obj.paths())
        .assert()
        .success();

    let linked = std::fs::read(out.path()).expect("failed reading output");
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("failed parsing linked output");

    // Grouped sections should not be merged
    assert!(coff.section_by_name(".text$a").is_some());
    assert!(coff.section_by_name(".text$b").is_some());
    assert!(coff.section_by_name(".text$c").is_some());
}

#[test]
fn relative_relocation_flattening() {
    let obj = asm1(
        r#"
.section .text$a,"x"
call foo
nop
nop
nop
.section .text$b,"x"
foo:
  ret"#,
    );

    let out = NamedTempFile::new().expect("failed creating output tempfile");

    cargo_bin_cmd!()
        .arg("-o")
        .arg(out.path())
        .args(obj.paths())
        .assert()
        .success();

    let linked = std::fs::read(out.path()).expect("failed reading output");
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("failed parsing linked output");

    let code = coff
        .section_by_name(".text")
        .expect("failed getting code section")
        .data()
        .expect("failed getting code section data");

    // The original `call foo` relocation in .text$a should now be resolved to a
    // call $+8
    assert_eq!(code[..5], [0xe8, 0x03, 0x00, 0x00, 0x00]);
}

#[test]
fn section_symbol_relocations_shift() {
    let obj = asm1(
        r#"
.text
jmp .rdata$2
.section .rdata$1,"r"
.quad 0
.section .rdata$2,"r"
.quad 0"#,
    );

    let out = NamedTempFile::new().expect("failed creating output tempfile");

    cargo_bin_cmd!()
        .arg("-o")
        .arg(out.path())
        .args(obj.paths())
        .assert()
        .success();

    let linked = std::fs::read(out.path()).expect("failed reading output");
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("failed parsing linked output");

    let code = coff
        .section_by_name(".text")
        .expect("failed getting code section")
        .data()
        .expect("failed getting code section data");

    // jmp reference to `.rdata$2` should be resolved to `.rdata+8`
    assert_eq!(code[..5], [0xe9, 0x08, 0x00, 0x00, 0x00]);
}

#[test]
fn local_symbol_relocation_target_no_change() {
    let obj = asm1(
        r#"
.text
jmp local_data
.section .rdata$1,"r"
.quad 0
.section .rdata$2,"r"
local_data:
.quad 0"#,
    );

    let out = NamedTempFile::new().expect("failed creating output tempfile");

    cargo_bin_cmd!()
        .arg("-o")
        .arg(out.path())
        .args(obj.paths())
        .assert()
        .success();

    let linked = std::fs::read(out.path()).expect("failed reading output");
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("failed parsing linked output");

    let code = coff
        .section_by_name(".text")
        .expect("failed getting code section")
        .data()
        .expect("failed getting code section data");

    // jmp reference should be left as is since it targets a locally defined
    // symbol
    assert_eq!(code[..5], [0xe9, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn intrasection_addr_relocations() {
    let obj = asm1(
        r#"
.section .text$a,"x"
.quad .text$b
.section .text$b,"x"
.quad 0"#,
    );

    let out = NamedTempFile::new().expect("failed creating output tempfile");

    cargo_bin_cmd!()
        .arg("-o")
        .arg(out.path())
        .args(obj.paths())
        .assert()
        .success();

    let linked = std::fs::read(out.path()).expect("failed reading output");
    let coff: CoffFile = CoffFile::parse(linked.as_slice()).expect("failed parsing linked output");

    let code_section = coff
        .section_by_name(".text")
        .expect("failed getting code section");

    let code = code_section
        .data()
        .expect("failed getting code section data");

    // ADDR64 relocation to the same output section should be left with
    // the relocation value shifting by 8
    assert_eq!(code[..8], [0x8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let code_relocs = code_section
        .coff_relocations()
        .expect("failed getting code section relocs");

    assert!(!code_relocs.is_empty());
}
