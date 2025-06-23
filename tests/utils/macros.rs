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
        let mut __linker = boflink::linker::LinkerBuilder::new()
            .library_searcher($crate::utils::archive_searcher::MemoryArchiveSearcher::new())
            .architecture($arch)
            .merge_grouped_sections(true);

        for (idx, document) in serde_yml::Deserializer::from_str($input).enumerate() {
            let yaml_input = $crate::utils::build::YamlInput::deserialize(document).unwrap();
            match yaml_input {
                $crate::utils::build::YamlInput::Coff(c) => {
                    __linker.add_file_memory(
                        std::path::PathBuf::from(format!("file{}", idx + 1)),
                        c.build().unwrap(),
                    );
                }
                $crate::utils::build::YamlInput::Importlib(c) => {
                    __linker.add_file_memory(
                        std::path::PathBuf::from(format!("file{}", idx + 1)),
                        c.build($arch.into()).unwrap(),
                    );
                }
            };
        }

        __linker
    }};
}
