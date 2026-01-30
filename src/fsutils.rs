use private::Sealed;

use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use unix as sys;

#[cfg(windows)]
use windows as sys;

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

pub trait UniqueFileExt: Sealed {
    fn unique_id(&self) -> Result<UniqueFileId, std::io::Error>;
}

impl Sealed for std::fs::File {}

/// Identifier for checking if two open file handles refer to the same file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct UniqueFileId(sys::UniqueFileIdInner);

impl UniqueFileId {
    fn compute_id(file: &std::fs::File) -> Result<UniqueFileId, std::io::Error> {
        Ok(UniqueFileId(sys::UniqueFileIdInner::compute_id(file)?))
    }
}

impl UniqueFileExt for std::fs::File {
    /// Computes a unique identifier for the file handle.
    ///
    /// This identifier can be used for checking if two handles refer to the
    /// same file on the file system.
    fn unique_id(&self) -> Result<UniqueFileId, std::io::Error> {
        UniqueFileId::compute_id(self)
    }
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::MetadataExt;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct UniqueFileIdInner {
        device: u64,
        inode: u64,
    }

    impl UniqueFileIdInner {
        pub fn compute_id(file: &std::fs::File) -> std::io::Result<Self> {
            let metadata = file.metadata()?;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::os::windows::io::AsRawHandle;

    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx},
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct UniqueFileIdInner {
        volume_serial_number: u64,
        file_id: u128,
    }

    impl UniqueFileIdInner {
        pub fn compute_id(file: &std::fs::File) -> std::io::Result<Self> {
            let mut fileinfo = FILE_ID_INFO::default();

            unsafe {
                GetFileInformationByHandleEx(
                    HANDLE(file.as_raw_handle()),
                    FileIdInfo,
                    &raw mut fileinfo as _,
                    std::mem::size_of_val(&fileinfo) as u32,
                )
                .map_err(|e| std::io::Error::from(e))?;
            }

            Ok(Self {
                volume_serial_number: fileinfo.VolumeSerialNumber,
                file_id: u128::from_ne_bytes(fileinfo.FileId.Identifier),
            })
        }
    }
}

mod private {
    pub trait Sealed {}
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
