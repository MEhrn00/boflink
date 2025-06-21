use boflink::linker::LinkerTargetArch;

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
