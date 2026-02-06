use std::path::{Component, PathBuf};

use private::Sealed;

pub trait PathExt: Sealed {
    /// Lexically normalizes the path using the C++ `std::filesystem::path::lexically_normal()`
    /// normalization algorithm.
    ///
    /// This normalization process is different than [`std::path::Path::normalize_lexically()`]
    /// and is not compatible for this project.
    fn normalize_lexically_cpp(&self) -> PathBuf;
}

impl Sealed for std::path::Path {}

impl PathExt for std::path::Path {
    fn normalize_lexically_cpp(&self) -> PathBuf {
        let mut iter = self.components().peekable();

        let root = match iter.peek() {
            None => return PathBuf::new(),
            Some(p @ Component::RootDir) | Some(p @ Component::Prefix(_)) => Some(*p),
            _ => None,
        };

        let mut normalized = PathBuf::new();

        while let Some(component) = iter.next() {
            match component {
                Component::CurDir => continue,
                Component::Normal(_) if iter.next_if_eq(&Component::ParentDir).is_some() => {
                    continue;
                }
                Component::ParentDir => {
                    if !normalized.pop() {
                        if let Some(root) = root {
                            normalized.push(root);
                        } else {
                            normalized.push(Component::ParentDir);
                        }
                    }
                }
                o => {
                    normalized.push(o);
                }
            }
        }

        if normalized.components().next().is_none() {
            normalized.push(Component::CurDir);
        }

        normalized
    }
}

mod private {
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use super::PathExt;
    use std::path::Path;

    #[test]
    fn normalize_lexically_cpp() {
        let tests = [
            ("", ""),
            ("./", "."),
            ("./foo", "foo"),
            ("foo////////", "foo/"),
            ("foo/./bar", "foo/bar"),
            ("foo/./bar/..", "foo/"),
            // Allow traversing up the filesystem
            ("../foo", "../foo"),
            ("foo/./bar/../../../baz", "../baz"),
            // Check root normalization
            ("/root/not/in/path/../../../foo/bar", "/root/foo/bar"),
            ("/root/not/in/path///./../../../foo/bar", "/root/foo/bar"),
            // New root
            ("/root/foo/../../bar", "/bar"),
        ];

        for case in tests {
            let test_path = Path::new(case.0);
            let expected = Path::new(case.1);
            assert_eq!(
                test_path.normalize_lexically_cpp(),
                expected,
                "case: {case:?}",
            );
        }
    }
}
