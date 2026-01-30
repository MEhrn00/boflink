use std::path::{Path, PathBuf};

use indexmap::IndexSet;

pub trait LibraryFind {
    fn find_library(&self, name: impl AsRef<str>) -> Option<(PathBuf, Vec<u8>)>;
}

/// Used for finding link libraries.
#[derive(Debug, Default)]
pub struct LibrarySearcher {
    search_paths: IndexSet<PathBuf>,
}

impl LibrarySearcher {
    pub fn new() -> LibrarySearcher {
        Default::default()
    }

    pub fn extend_search_paths<I, P>(&mut self, search_paths: I)
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.search_paths
            .extend(search_paths.into_iter().map(|v| v.into()));
    }
}

impl LibraryFind for LibrarySearcher {
    fn find_library(&self, name: impl AsRef<str>) -> Option<(PathBuf, Vec<u8>)> {
        let name = name.as_ref();

        if let Some(filename) = name.strip_prefix(':') {
            self.search_paths.iter().find_map(|search_path| {
                let full_path = search_path.join(filename);
                try_open_path(&full_path).map(|buffer| (full_path, buffer))
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

            self.search_paths.iter().find_map(|search_path| {
                patterns.into_iter().find_map(|(prefix, name, ext)| {
                    let filename = format!("{prefix}{name}{ext}");
                    let full_path = search_path.join(filename);
                    try_open_path(&full_path).map(|buffer| (full_path, buffer))
                })
            })
        }
    }
}

fn try_open_path(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path)
        .inspect_err(|e| log::debug!("attempt to open {} failed: {e}", path.display()))
        .ok()
}
