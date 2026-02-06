use private::Sealed;

#[cfg(unix)]
use unix as platform;

#[cfg(windows)]
use windows as platform;

/// Extension trait for [`std::fs::File`]
pub trait FileExt: Sealed {
    fn unique_id(&self) -> Result<UniqueFileId, std::io::Error>;
}

impl Sealed for std::fs::File {}

impl FileExt for std::fs::File {
    /// Computes a unique identifier for the file handle.
    ///
    /// This identifier can be used for checking if two handles refer to the
    /// same file on the file system.
    fn unique_id(&self) -> Result<UniqueFileId, std::io::Error> {
        Ok(UniqueFileId(platform::UniqueFileId::compute_id(self)?))
    }
}

/// Identifier for checking if two open file handles refer to the same file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct UniqueFileId(platform::UniqueFileId);

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::MetadataExt;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct UniqueFileId {
        device: u64,
        inode: u64,
    }

    impl UniqueFileId {
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
