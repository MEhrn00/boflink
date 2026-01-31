use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

use os_str_bytes::OsStrBytesExt;

use crate::{coff::ImageFileMachine, inputs::ObjectFile};

type BumpBox<'a, T> = bumpalo::boxed::Box<'a, T>;

#[derive(Debug)]
pub struct Linker<'a> {
    pub architecture: ImageFileMachine,
    pub objs: Vec<BumpBox<'a, ObjectFile<'a>>>,
}

fn find_library(
    search_paths: &[PathBuf],
    name: impl AsRef<OsStr>,
    find_static: bool,
) -> Option<(PathBuf, Vec<u8>)> {
    let try_open_path = |path: &Path| -> Option<Vec<u8>> {
        std::fs::read(path)
            .inspect_err(|e| log::debug!("attempt to open {} failed: {e}", path.display()))
            .ok()
    };

    let name = name.as_ref();

    if let Some(filename) = name.strip_prefix(':') {
        search_paths.iter().find_map(|search_path| {
            let full_path = search_path.join(filename);
            try_open_path(&full_path).map(|buffer| (full_path, buffer))
        })
    } else if find_static {
        let patterns = [("lib", name, ".a"), ("", name, ".lib")];

        patterns.into_iter().find_map(|(prefix, name, ext)| {
            let mut filename = OsString::new();
            filename.push(prefix);
            filename.push(name);
            filename.push(ext);

            search_paths.iter().find_map(|search_path| {
                let full_path = search_path.join(&filename);
                try_open_path(&full_path).map(|buffer| (full_path, buffer))
            })
        })
    } else {
        let patterns = [
            ("lib", name, ".dll.a"),
            ("", name, ".dll.a"),
            ("lib", name, ".a"),
            ("", name, ".lib"),
            ("lib", name, ".lib"),
            ("", name, ".a"),
        ];

        search_paths.iter().find_map(|search_path| {
            patterns.into_iter().find_map(|(prefix, name, ext)| {
                let mut filename = OsString::new();
                filename.push(prefix);
                filename.push(name);
                filename.push(ext);
                let full_path = search_path.join(filename);
                try_open_path(&full_path).map(|buffer| (full_path, buffer))
            })
        })
    }
}
