use boflink::linker::{LinkerTargetArch, error::LinkError};

use crate::setup_linker;

#[test]
fn no_gcroots() {
    let linked = setup_linker!("no_gcroots.yaml", LinkerTargetArch::Amd64)
        .entrypoint("go")
        .gc_sections(true)
        .build()
        .link();

    let e = linked.expect_err("Expected linker to return an error");
    assert!(
        matches!(e, LinkError::EmptyGcRoots),
        "Returned error should be a LinkError::EmptyGcRoots error"
    );
}
