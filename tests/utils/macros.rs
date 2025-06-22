#[macro_export]
macro_rules! link_yaml {
    ($input:literal, $arch:expr) => {{
        const __INPUT_DOC: &str = include_str!($input);
        link_yaml!(__INPUT_DOC, $arch)
    }};

    ($input:ident, $arch:expr) => {{
        $crate::setup_linker!($input, $arch)
            .build()
            .link()
            .expect("Could not link files")
    }};
}

#[macro_export]
macro_rules! setup_linker {
    ($input:literal, $arch:expr) => {{
        const __INPUT_DOC: &str = include_str!($input);
        setup_linker!(__INPUT_DOC, $arch)
    }};

    ($input:ident, $arch:expr) => {{
        use serde::Deserialize;
        let mut __searcher = $crate::utils::archive_searcher::MemoryArchiveSearcher::new();
        let mut __input_libraries = Vec::new();
        let mut __input_coffs = Vec::new();

        for (idx, document) in serde_yml::Deserializer::from_str($input).enumerate() {
            let yaml_input = $crate::utils::build::YamlInput::deserialize(document).unwrap();
            match yaml_input {
                $crate::utils::build::YamlInput::Coff(c) => {
                    __input_coffs.push(boflink::pathed_item::PathedItem::new(
                        format!("file{}", idx + 1).into(),
                        c.build().unwrap(),
                    ));
                }
                $crate::utils::build::YamlInput::Importlib(c) => {
                    let library_name = format!("file{}", idx + 1);
                    __searcher.add_library(library_name.clone(), c.build($arch.into()).unwrap());
                    __input_libraries.push(library_name);
                }
            };
        }

        boflink::linker::LinkerBuilder::new()
            .architecture($arch)
            .merge_grouped_sections(true)
            .library_searcher(__searcher)
            .add_inputs(__input_coffs)
            .add_libraries(__input_libraries)
    }};
}
