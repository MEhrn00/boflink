use std::path::{Component, Path, PathBuf};

/// Lexically normalizes `path` using C++ `std::filesystem::path::lexically_normal()`
/// normalization algorithm.
///
/// This normalization process will traverse up the filesystem which does
/// not follow [`std::path::Path::normalize_lexically()`].
pub fn lexically_normalize_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    let mut iter = path.components().peekable();

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

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn lexically_normalize_path() {
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
                super::lexically_normalize_path(test_path),
                expected,
                "case: {case:?}",
            );
        }
    }
}
