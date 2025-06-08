use boflink::linker::{
    LinkerTargetArch,
    error::{LinkError, LinkerSymbolErrorKind},
};

use crate::setup_linker;

#[test]
fn entrypoint_validation() {
    let linker =
        setup_linker!("entrypoint_validation.yaml", LinkerTargetArch::Amd64).entrypoint("go");

    let link_error = linker
        .build()
        .link()
        .expect_err("Linking should have returned an error");

    match link_error {
        LinkError::Symbol(symbol_errors) => {
            let go_error = symbol_errors
                .errors()
                .iter()
                .find(|symbol_error| symbol_error.name == "go")
                .unwrap_or_else(|| {
                    panic!(
                        "Could not find error for the 'go' symbol.\n{:#?}",
                        symbol_errors.errors()
                    )
                });

            assert!(
                matches!(go_error.kind, LinkerSymbolErrorKind::Undefined(_)),
                "Symbol error kind should be undefined.\n{go_error:#?}"
            );
        }
        o => panic!("Incorrect link error variant: {o:#?}"),
    };
}
