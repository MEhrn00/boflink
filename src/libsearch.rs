use std::{borrow::Cow, io::ErrorKind, path::PathBuf};

use indexmap::IndexSet;
use log::debug;

use crate::pathed_item::PathedItem;

pub trait LibraryFind {
    fn find_library(&self, name: impl AsRef<str>) -> Result<FoundLibrary, LibsearchError>;
}

#[derive(Debug, thiserror::Error)]
pub enum LibsearchError {
    #[error("unable to find library -l{0}")]
    NotFound(String),

    #[error("could not open link library {}: {error}", .path.display())]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
}

/// A search library name
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct SearchLibraryName<'a>(&'a str);

impl SearchLibraryName<'_> {
    pub fn value(&self) -> &str {
        self.0.trim_start_matches(':')
    }

    pub fn is_filename(&self) -> bool {
        self.0.starts_with(':')
    }
}

impl<'a> From<&'a str> for SearchLibraryName<'a> {
    fn from(value: &'a str) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for SearchLibraryName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A read in link library found from the [`LibrarySearcher`].
pub type FoundLibrary = PathedItem<PathBuf, Vec<u8>>;

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
    fn find_library(&self, name: impl AsRef<str>) -> Result<FoundLibrary, LibsearchError> {
        if self.search_paths.is_empty() {
            return Err(LibsearchError::NotFound(name.as_ref().to_string()));
        }

        let library = SearchLibraryName::from(name.as_ref());

        let library_filenames: Vec<Cow<'_, str>> = if !library.is_filename() {
            let name = library.value();
            // Create a vec with the library file names to check.
            vec![
                format!("lib{name}.dll.a").into(),
                format!("{name}.dll.a").into(),
                format!("lib{name}.a").into(),
                format!("{name}.lib").into(),
                format!("lib{name}.lib").into(),
                format!("{name}.a").into(),
            ]
        } else {
            vec![Cow::Borrowed(library.value())]
        };

        for search_path in &self.search_paths {
            for filename in &library_filenames {
                let full_path = search_path.join(filename.as_ref());
                match std::fs::read(&full_path) {
                    Ok(data) => {
                        return Ok(FoundLibrary::new(full_path, data));
                    }
                    Err(e) if e.kind() != ErrorKind::NotFound => {
                        return Err(LibsearchError::Io {
                            path: full_path,
                            error: e,
                        });
                    }
                    Err(e) => {
                        debug!("attempt to open {} failed ({})", full_path.display(), e);
                    }
                };
            }
        }

        Err(LibsearchError::NotFound(name.as_ref().to_string()))
    }
}
