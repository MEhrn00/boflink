use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

use memmap2::Mmap;
use object::read::archive::ArchiveFile;
use os_str_bytes::OsStrBytesExt;
use rayon::Scope;

use crate::{
    ErrorContext,
    arena::{ArenaHandle, ArenaRef, TypedArena},
    bail,
    cli::{InputArg, InputArgContext, InputArgVariant},
    coff::ImageFileMachine,
    context::LinkContext,
    make_error,
    object::{ObjectFile, ObjectFileId},
    stdext::{
        fs::{FileExt, UniqueFileId},
        path::PathExt,
    },
};

#[derive(Default)]
pub struct InputsStore<'a> {
    pub files: TypedArena<InputFile<'a>>,
    pub mappings: TypedArena<Mmap>,
    pub objs: TypedArena<ObjectFile<'a>>,
}

#[derive(Debug)]
pub struct InputFile<'a> {
    pub data: &'a [u8],
    pub path: &'a Path,
    pub parent: Option<&'a InputFile<'a>>,
}

impl<'a> InputFile<'a> {
    /// Makes a new internal input file
    pub fn internal() -> InputFile<'a> {
        InputFile {
            data: &[],
            path: Path::new(""),
            parent: None,
        }
    }

    pub fn is_internal(&self) -> bool {
        self.path.as_os_str().is_empty()
    }

    pub fn source(&self) -> InputFileSource<'a> {
        self.parent
            .map(|parent| InputFileSource::Member {
                archive: parent.path,
                path: self.path,
            })
            .unwrap_or_else(|| {
                if self.is_internal() {
                    InputFileSource::Internal
                } else {
                    InputFileSource::Disk(self.path)
                }
            })
    }
}

/// Full source of an input file.
///
/// Used for diagnostic messages.
///
/// The [`std::fmt::Display`] implementation will display the file path if the
/// file was read directly from disk or it will display `path(member)` if
/// the file is a member of an archive.
///
/// [`InputFileSource::to_short()`] can be used for only displaying the file name
/// parts instead of the full paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InputFileSource<'a> {
    /// Internal file that is created for misc usage
    Internal,

    /// An input file read directly from disk.
    Disk(&'a Path),

    /// An archive member.
    Member { archive: &'a Path, path: &'a Path },
}

impl<'a> InputFileSource<'a> {
    /// Returns the [`ShortInputFileSource`] from of this input source
    pub fn to_short(&self) -> ShortInputFileSource<'a> {
        let fname_or_path =
            |path: &'a Path| -> &'a OsStr { path.file_name().unwrap_or(path.as_os_str()) };

        match self {
            Self::Internal => ShortInputFileSource::Internal,
            Self::Disk(path) => ShortInputFileSource::Disk(fname_or_path(path)),
            Self::Member { archive, path } => ShortInputFileSource::Member {
                archive: fname_or_path(archive),
                filename: fname_or_path(path),
            },
        }
    }
}

impl std::fmt::Display for InputFileSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "<internal>"),
            Self::Disk(path) => write!(f, "{}", path.display()),
            Self::Member {
                archive: parent,
                path,
            } => {
                write!(f, "{}({})", parent.display(), path.display())
            }
        }
    }
}

/// A short form version of an input source with only the filename components.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ShortInputFileSource<'a> {
    Internal,

    /// The name of the file read from disk.
    Disk(&'a OsStr),

    /// An archive member
    Member {
        archive: &'a OsStr,
        filename: &'a OsStr,
    },
}

impl std::fmt::Display for ShortInputFileSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "<internal>"),
            Self::Disk(file) => write!(f, "{}", file.display()),
            Self::Member { archive, filename } => {
                write!(f, "{}({})", archive.display(), filename.display())
            }
        }
    }
}

/// Type of input file derived from the file data magic bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileKind {
    /// Archive file
    Archive,

    /// Regular COFF
    Coff,

    /// Short form COFF import file
    Import,

    /// Module definition file
    ModuleDef,
}

impl FileKind {
    /// Attempts to detect the [`FileKind`] based on the passed in data.
    pub fn detect(data: &[u8]) -> Result<FileKind, UnknownFileError> {
        let Some(magic) = data.get(..18) else {
            return Err(UnknownFileError);
        };

        let detect_archive = || {
            let magic = magic.get(..object::archive::MAGIC.len())?;
            (magic == object::archive::MAGIC || magic == object::archive::THIN_MAGIC)
                .then_some(FileKind::Archive)
        };

        let detect_coff = || match magic[..5] {
            [0x00, 0x00, 0xff, 0xff, 0x00, 0x00] => Some(FileKind::Import),
            [0x64, 0x86, ..]
            | [0x4c, 0x01, ..]
            | [0xc0, 0x01, ..]
            | [0x64, 0xaa, ..]
            | [0x41, 0xa6, ..]
            | [0x4e, 0xa6, ..]
            | [0xc4, 0x1, ..]
            | [0xc2, 0x1, ..] => Some(FileKind::Coff),
            _ => None,
        };

        let detect_module = || {
            if magic.iter().any(|c| c.is_ascii()) {
                let data_str = std::str::from_utf8(data).ok()?;
                data_str
                    .lines()
                    .any(|line| {
                        line.starts_with(';')
                            || line.contains("LIBRARY")
                            || line.contains("EXPORTS")
                            || line.contains("NAME")
                    })
                    .then_some(FileKind::ModuleDef)
            } else {
                None
            }
        };

        detect_archive()
            .or_else(detect_coff)
            .or_else(detect_module)
            .ok_or(UnknownFileError)
    }
}

#[derive(Debug)]
pub struct UnknownFileError;

impl std::fmt::Display for UnknownFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unknown file type")
    }
}

impl std::error::Error for UnknownFileError {}

pub struct InputsReader<'r, 'a: 'r> {
    pub architecture: ImageFileMachine,
    strings: &'r ArenaHandle<'a, u8>,
    store: &'a InputsStore<'a>,
    input_objs: &'r TypedArena<ArenaRef<'a, ObjectFile<'a>>>,
    unique_paths: HashSet<(&'a Path, InputArgContext)>,
    unique_mappings: HashSet<(UniqueFileId, InputArgContext)>,
    unique_libraries: HashSet<(&'a OsStr, InputArgContext)>,
}

impl<'r, 'a: 'r> InputsReader<'r, 'a> {
    pub fn new(
        architecture: ImageFileMachine,
        strings: &'r ArenaHandle<'a, u8>,
        store: &'a InputsStore<'a>,
        objs: &'r TypedArena<ArenaRef<'a, ObjectFile<'a>>>,
    ) -> Self {
        let this = Self {
            architecture,
            strings,
            store,
            input_objs: objs,
            unique_paths: HashSet::new(),
            unique_mappings: HashSet::new(),
            unique_libraries: HashSet::new(),
        };

        this.create_internal_file();
        this
    }

    fn create_internal_file(&self) {
        assert!(
            self.input_objs.len() == 0,
            "InputsReader::create_internal_file() must be called before inputs are added"
        );

        let obj = ArenaRef::new_in(ObjectFile::internal_obj(), &self.store.objs);
        self.input_objs.alloc(obj);
    }

    pub fn read_cli_inputs<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        scope: &Scope<'scope>,
        inputs: &'a [InputArg],
    ) where
        'r: 'scope,
    {
        for input in inputs {
            match input.variant {
                InputArgVariant::File(ref path) => {
                    if let Err(e) = self.read_path(ctx, scope, input.context, path.as_path()) {
                        log::error!(logger: ctx, "{e}");
                    }
                }
                InputArgVariant::Library(ref library) => {
                    if let Err(e) =
                        self.read_library(ctx, scope, input.context, library.as_os_str())
                    {
                        log::error!(logger: ctx, "{e}");
                    }
                }
            }
        }
    }

    fn read_path<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        path: &'a Path,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        if let Some(file) = self.open_unique_path(path, input_ctx) {
            self.read_file(ctx, scope, input_ctx, path, file?)
        } else {
            Ok(())
        }
    }

    fn read_library<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        library: &'a OsStr,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        if let Some(found) = self.find_unique_library(ctx, library, input_ctx) {
            let (path, file) = found?;
            let path = Path::new(*self.strings.alloc_os_str(path.as_os_str()));
            self.read_file(ctx, scope, input_ctx, path, file)
        } else {
            Ok(())
        }
    }

    fn read_file<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        path: &'a Path,
        file: std::fs::File,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        if let Some(mapping) = self.map_unique_file(file, input_ctx) {
            let mapping = mapping.with_context(|| format!("cannot open {}", path.display()))?;
            ctx.stats.read.files.fetch_add(1, Ordering::Relaxed);
            self.parse_input_file(
                ctx,
                scope,
                input_ctx,
                InputFile {
                    data: mapping,
                    path,
                    parent: None,
                },
            )
        } else {
            Ok(())
        }
    }

    fn parse_input_file<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        file: InputFile<'a>,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        let kind = FileKind::detect(file.data)
            .with_context(|| format!("cannot parse {}", file.source()))?;

        match kind {
            FileKind::Coff => {
                let machine = ObjectFile::identify_coff_machine(file.data, 0)?;
                self.validate_architecture(&file, machine)?;
                let obj = self.make_new_object_file(ctx, input_ctx, file);
                let obj = self.input_objs.alloc(obj);
                scope.spawn(move |_| {
                    if let Err(e) = obj.parse_coff(ctx) {
                        log::error!(logger: ctx, "cannot parse {}: {e}", obj.source());
                    }
                });
            }
            FileKind::Import => {
                todo!("import files");
            }
            FileKind::Archive => {
                if file.parent.is_some() {
                    log::warn!("{}: skipping archive file member in archive", file.source());
                    return Ok(());
                }

                self.parse_archive_file(ctx, scope, input_ctx, file)?;
            }
            FileKind::ModuleDef => {
                todo!("module definition files");
            }
        }

        Ok(())
    }

    fn make_new_object_file<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        input_ctx: InputArgContext,
        file: InputFile<'a>,
    ) -> ArenaRef<'a, ObjectFile<'a>>
    where
        'r: 'scope,
    {
        let have_parent = file.parent.is_some();
        if !have_parent {
            ctx.stats.read.coffs.fetch_add(1, Ordering::Relaxed);
        }

        let obj = ObjectFile::new(
            ObjectFileId::new(self.input_objs.len()),
            file,
            input_ctx.in_lib || (have_parent && !input_ctx.in_whole_archive),
        );
        ArenaRef::new_in(obj, &self.store.objs)
    }

    fn validate_architecture(
        &mut self,
        file: &InputFile<'a>,
        machine: ImageFileMachine,
    ) -> crate::Result<()> {
        if !(machine == ImageFileMachine::Amd64 || machine == ImageFileMachine::I386) {
            bail!(
                "cannot parse {}: unsupported COFF architecture '{machine:#}'",
                file.source(),
            );
        }

        if self.architecture == ImageFileMachine::Unknown {
            self.architecture = machine;
        } else if self.architecture != machine {
            bail!(
                "cannot parse {}: expected machine value '{}' but found '{machine}'",
                file.source(),
                self.architecture,
            );
        }

        Ok(())
    }

    fn parse_archive_file<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        file: InputFile<'a>,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        let archive = ArchiveFile::parse(file.data)
            .with_context(|| format!("cannot parse {}", file.source()))?;

        ctx.stats.read.archives.fetch_add(1, Ordering::Relaxed);

        let file = &*self.store.files.alloc(file);
        if archive.is_thin() {
            self.parse_thin_archive_members(ctx, scope, input_ctx, file, archive)
        } else {
            self.parse_archive_members(ctx, scope, input_ctx, file, archive)
        }
    }

    fn parse_archive_members<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        file: &'a InputFile<'a>,
        archive: ArchiveFile<'a>,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        for member in archive.members() {
            let member = member.with_context(|| format!("cannot parse {}", file.source()))?;
            let offset = member.file_range().0;
            let member_name = std::str::from_utf8(member.name()).map_err(|_| {
                make_error!(
                    "cannot parse {}({offset}): member name is not a valid utf8 string",
                    file.path.display()
                )
            })?;
            let member_path = Path::new(member_name);
            let member_data = member.data(file.data).with_context(|| {
                format!(
                    "cannot parse {}({})",
                    file.path.display(),
                    member_path.display()
                )
            })?;

            self.parse_input_file(
                ctx,
                scope,
                input_ctx,
                InputFile {
                    data: member_data,
                    path: member_path,
                    parent: Some(file),
                },
            )?;
        }

        Ok(())
    }

    fn parse_thin_archive_members<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        file: &'a InputFile<'a>,
        archive: ArchiveFile<'a>,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        for member in archive.members() {
            let member = member.with_context(|| format!("cannot parse {}", file.source()))?;
            let offset = member.file_range().0;
            let member_name = std::str::from_utf8(member.name()).map_err(|_| {
                make_error!(
                    "cannot parse {}({offset}): member name is not a valid utf8 string",
                    file.path.display()
                )
            })?;
            let member_path = {
                let member_path = Path::new(member_name);
                let normalized = member_path.normalize_lexically_cpp();
                if normalized == member_path {
                    member_path
                } else {
                    Path::new(*self.strings.alloc_os_str(normalized.as_os_str()))
                }
            };

            let source = InputFileSource::Member {
                archive: file.path,
                path: member_path,
            };
            let disk_path = file.path.join(member_path.normalize_lexically_cpp());
            let handle = std::fs::File::open(&disk_path)
                .with_context(|| format!("cannot open {source}: thin archive member"))?;
            if let Some(mapping) = self.map_unique_file(handle, input_ctx) {
                let mapping = mapping
                    .with_context(|| format!("cannot open {source}: thin archive member"))?;
                self.parse_input_file(
                    ctx,
                    scope,
                    input_ctx,
                    InputFile {
                        path: member_path,
                        parent: Some(file),
                        data: mapping,
                    },
                )?;
            }
        }

        Ok(())
    }

    fn open_unique_path(
        &mut self,
        path: &'a Path,
        input_ctx: InputArgContext,
    ) -> Option<crate::Result<std::fs::File>> {
        if self.unique_paths.insert((path, input_ctx)) {
            Some(
                std::fs::File::open(path)
                    .with_context(|| format!("cannot open {}", path.display())),
            )
        } else {
            None
        }
    }

    fn map_unique_file(
        &mut self,
        file: std::fs::File,
        input_ctx: InputArgContext,
    ) -> Option<crate::Result<&'a Mmap>> {
        let ufid = match file.unique_id() {
            Ok(ufid) => ufid,
            Err(e) => return Some(Err(e.into())),
        };

        if self.unique_mappings.insert((ufid, input_ctx)) {
            Some(
                unsafe { Mmap::map(&file) }
                    .map(|mapping| &*self.store.mappings.alloc(mapping))
                    .map_err(crate::Error::from),
            )
        } else {
            None
        }
    }

    fn find_unique_library(
        &mut self,
        ctx: &LinkContext<'a>,
        name: &'a OsStr,
        input_ctx: InputArgContext,
    ) -> Option<crate::Result<(PathBuf, std::fs::File)>> {
        if self.unique_libraries.insert((name, input_ctx)) {
            let found = find_library(&ctx.options.library_path, input_ctx.in_static, name);
            Some(found.with_context(|| format!("unable to find library -l{}", name.display())))
        } else {
            None
        }
    }
}

fn find_library(
    search_paths: &[PathBuf],
    find_static: bool,
    name: &OsStr,
) -> Option<(PathBuf, std::fs::File)> {
    let try_open_path = |path: &Path| -> Option<std::fs::File> {
        std::fs::File::open(path)
            .inspect_err(|e| log::debug!("attempt to open {} failed: {e}", path.display()))
            .ok()
    };

    let mut buf = PathBuf::with_capacity(256);

    if let Some(name) = name.strip_prefix(':') {
        let filename = Path::new(name);
        if filename.is_absolute() {
            return try_open_path(filename).map(|f| (filename.to_path_buf(), f));
        }

        return search_paths.iter().find_map(|search_path| {
            buf.clear();
            buf.push(search_path);
            buf.push(filename);
            try_open_path(&buf).map(|f| (buf.to_owned(), f))
        });
    }

    if find_static {
        let mut namebuf = OsString::new();
        return [("lib", "a"), ("", "lib")]
            .into_iter()
            .find_map(|(prefix, ext)| {
                let mut filename = name;
                if !prefix.is_empty() {
                    namebuf.clear();
                    namebuf.push(prefix);
                    namebuf.push(name);
                    filename = &namebuf;
                }
                search_paths.iter().find_map(|search_path| {
                    buf.clear();
                    buf.push(search_path);
                    buf.push(filename);
                    buf.add_extension(ext);
                    try_open_path(&buf).map(|f| (buf.to_owned(), f))
                })
            });
    }

    // lib<name>.dll.a
    // <name>.dll.a
    // lib<name>.a
    // <name>.lib
    let mut namebuf = OsString::new();
    search_paths.iter().find_map(|search_path| {
        buf.clear();
        buf.push(search_path);
        buf.push(name);
        [("lib", "dll.a"), ("", "dll.a"), ("lib", "a"), ("", "lib")]
            .into_iter()
            .find_map(|(prefix, ext)| {
                let mut filename = name;
                if !prefix.is_empty() {
                    namebuf.clear();
                    namebuf.push(prefix);
                    namebuf.push(name);
                    filename = &namebuf;
                }

                buf.set_file_name(filename);
                buf.add_extension(ext);
                try_open_path(&buf).map(|f| (buf.to_owned(), f))
            })
    })
}
