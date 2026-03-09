use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

use boflink_arena::{BumpHandle, TypedArena, TypedArenaHandle, TypedArenaRef};
use boflink_index::Idx;
use memmap2::Mmap;
use object::read::archive::ArchiveFile;
use os_str_bytes::OsStrBytesExt;
use rayon::Scope;

use crate::{
    ErrorContext, bail,
    cli::{Emulation, InputArg, InputArgContext, InputArgVariant},
    coff::ImageFileMachine,
    context::LinkContext,
    make_error,
    object::{ObjectFile, ObjectFileId},
    stdext::{
        fs::{FileExt, UniqueFileId},
        path::PathExt,
    },
    symbols::SyncSymbolMap,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InputFilePath<'a> {
    pub disk: &'a Path,
    pub member: Option<&'a Path>,
}

impl<'a> InputFilePath<'a> {
    #[inline]
    pub fn is_internal(&self) -> bool {
        self.member.is_none() && self.disk.as_os_str().is_empty()
    }

    #[inline]
    pub fn is_archive_member(&self) -> bool {
        self.member.is_some()
    }
}

impl Default for InputFilePath<'_> {
    fn default() -> Self {
        Self {
            disk: Path::new(""),
            member: None,
        }
    }
}

impl<'a> std::fmt::Display for InputFilePath<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(member) = self.member {
            write!(f, "{}({})", self.disk.display(), member.display(),)
        } else if self.disk.as_os_str().is_empty() {
            f.write_str("<internal>")
        } else {
            write!(f, "{}", self.disk.display())
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct InputFile<'a> {
    pub path: InputFilePath<'a>,
    pub data: &'a [u8],
}

impl<'a> InputFile<'a> {
    #[inline]
    pub fn is_internal(&self) -> bool {
        self.path.is_internal()
    }

    #[inline]
    pub fn is_archive_member(&self) -> bool {
        self.path.is_archive_member()
    }
}

impl<'a> std::fmt::Display for InputFile<'a> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.path, f)
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
    bump: BumpHandle<'a>,
    mappings: TypedArenaHandle<'a, Mmap>,
    objs: &'r TypedArena<TypedArenaRef<'a, ObjectFile<'a>>>,
    obj_arena: TypedArenaHandle<'a, ObjectFile<'a>>,
    pub live_objs: Vec<ObjectFileId>,
    unique_paths: HashSet<(&'a Path, InputArgContext)>,
    unique_mappings: HashSet<(UniqueFileId, InputArgContext)>,
    unique_libraries: HashSet<(&'a OsStr, InputArgContext)>,
}

impl<'r, 'a: 'r> InputsReader<'r, 'a> {
    pub fn new(
        ctx: &LinkContext<'a>,
        objs: &'r TypedArena<TypedArenaRef<'a, ObjectFile<'a>>>,
    ) -> Self {
        Self {
            architecture: ctx
                .options
                .machine
                .map(|machine| match machine {
                    Emulation::I386Pep => ImageFileMachine::Amd64,
                    Emulation::I386Pe => ImageFileMachine::I386,
                })
                .unwrap_or(ImageFileMachine::Unknown),
            bump: ctx.bump_pool.get(),
            mappings: ctx.mapping_pool.get(),
            obj_arena: ctx.obj_pool.get(),
            live_objs: Vec::new(),
            unique_paths: HashSet::new(),
            unique_mappings: HashSet::new(),
            unique_libraries: HashSet::new(),
            objs,
        }
    }

    pub fn read_cli_inputs<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        scope: &Scope<'scope>,
        inputs: &'a [InputArg],
        symbols: &'r SyncSymbolMap<'a>,
    ) where
        'r: 'scope,
    {
        let mut handle_input = |input: &'a InputArg| match input.variant {
            InputArgVariant::File(ref path) => {
                self.read_path(ctx, symbols, scope, input.context, path.as_path())
            }
            InputArgVariant::Library(ref library) => {
                self.read_library(ctx, symbols, scope, input.context, library.as_os_str())
            }
        };

        for input in inputs {
            if let Err(e) = handle_input(input) {
                log::error!(logger: ctx, "{e}");
            }
        }
    }

    fn read_path<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        symbols: &'r SyncSymbolMap<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        path: &'a Path,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        self.open_unique_path(path, input_ctx)
            .map_or(Ok(()), |file| {
                self.read_file(ctx, symbols, scope, input_ctx, path, file?)
            })
    }

    fn read_library<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        symbols: &'r SyncSymbolMap<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        library: &'a OsStr,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        self.find_unique_library(ctx, library, input_ctx)
            .map_or(Ok(()), |found| {
                let (path, file) = found?;
                let path = alloc_path(&self.bump, path.as_path());
                self.read_file(ctx, symbols, scope, input_ctx, path, file)
            })
    }

    fn read_file<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        symbols: &'r SyncSymbolMap<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        path: &'a Path,
        file: std::fs::File,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        self.map_unique_file(file, input_ctx)
            .map_or(Ok(()), |mapping| {
                let mapping = mapping.with_context(|| format!("cannot open {}", path.display()))?;
                ctx.stats.read.files.fetch_add(1, Ordering::Relaxed);
                self.parse_input_file(
                    ctx,
                    symbols,
                    scope,
                    input_ctx,
                    InputFile {
                        path: InputFilePath {
                            disk: path,
                            member: None,
                        },
                        data: &mapping,
                    },
                )
            })
    }

    fn parse_input_file<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        symbols: &'r SyncSymbolMap<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        file: InputFile<'a>,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        let kind = FileKind::detect(file.data).with_context(|| format!("cannot parse {file}"))?;

        match kind {
            FileKind::Coff => {
                let machine = ObjectFile::identify_coff_machine(file.data, 0)
                    .with_context(|| format!("cannot parse {file}"))?;
                self.validate_architecture(&file, machine)?;
                let id = ObjectFileId::from_usize(self.objs.len());
                let obj = {
                    let obj = self.obj_arena.alloc_ref(ObjectFile::default());
                    self.objs.alloc(obj)
                };

                if !file.is_archive_member() {
                    ctx.stats.read.coffs.fetch_add(1, Ordering::Relaxed);
                }

                let archive_lazy = file.is_archive_member() && !input_ctx.in_whole_archive;
                let cmdline_lazy = !file.is_archive_member() && !input_ctx.in_lib;
                let lazy = cmdline_lazy || archive_lazy;

                if !lazy {
                    self.live_objs.push(id);
                }

                scope.spawn(move |_| {
                    let do_parse = || -> crate::Result<()> {
                        *obj.as_mut() = ObjectFile::parse(ctx, file, lazy, symbols)?;
                        Ok(())
                    };

                    if let Err(e) = do_parse() {
                        log::error!(logger: ctx, "{e}");
                    }
                });
            }
            FileKind::Import => {
                todo!("import files");
            }
            FileKind::Archive => {
                if file.is_archive_member() {
                    log::warn!("{file}: skipping archive file member in archive");
                    return Ok(());
                }

                self.parse_archive_file(ctx, symbols, scope, input_ctx, file)?;
            }
            FileKind::ModuleDef => {
                todo!("module definition files");
            }
        }

        Ok(())
    }

    fn validate_architecture(
        &mut self,
        path: &InputFile<'a>,
        machine: ImageFileMachine,
    ) -> crate::Result<()> {
        if !(machine == ImageFileMachine::Amd64 || machine == ImageFileMachine::I386) {
            bail!("cannot parse {path}: unsupported COFF architecture '{machine:#}'",);
        }

        if self.architecture == ImageFileMachine::Unknown {
            self.architecture = machine;
        } else if self.architecture != machine {
            bail!(
                "cannot parse {path}: expected machine value '{}' but found '{machine}'",
                self.architecture,
            );
        }

        Ok(())
    }

    fn parse_archive_file<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        symbols: &'r SyncSymbolMap<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        file: InputFile<'a>,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        let archive =
            ArchiveFile::parse(file.data).with_context(|| format!("cannot parse {file}"))?;
        ctx.stats.read.archives.fetch_add(1, Ordering::Relaxed);
        if archive.is_thin() {
            self.parse_thin_archive_members(ctx, symbols, scope, input_ctx, &file, archive)
        } else {
            self.parse_archive_members(ctx, symbols, scope, input_ctx, &file, archive)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_archive_members<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        symbols: &'r SyncSymbolMap<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        file: &InputFile<'a>,
        archive: ArchiveFile<'a>,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        for member in archive.members() {
            let member = member.with_context(|| format!("cannot parse {file}"))?;
            let offset = member.file_range().0;
            let member_name =
                std::str::from_utf8(member.name()).map_err(|_| {
                    make_error!(
                        "cannot parse {file}({offset}): member name is not a valid utf8 string",
                    )
                })?;
            let member_path = Path::new(member_name);
            let member_path = InputFilePath {
                disk: file.path.disk,
                member: Some(member_path),
            };

            let member_data = member
                .data(file.data)
                .with_context(|| format!("cannot parse {member_path}"))?;

            self.parse_input_file(
                ctx,
                symbols,
                scope,
                input_ctx,
                InputFile {
                    path: member_path,
                    data: member_data,
                },
            )?;
        }

        Ok(())
    }

    fn parse_thin_archive_members<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        symbols: &'r SyncSymbolMap<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        file: &InputFile<'a>,
        archive: ArchiveFile<'a>,
    ) -> crate::Result<()>
    where
        'r: 'scope,
    {
        for member in archive.members() {
            let member = member.with_context(|| format!("cannot parse {file}"))?;
            let offset = member.file_range().0;
            let member_name =
                std::str::from_utf8(member.name()).map_err(|_| {
                    make_error!(
                        "cannot parse {file}({offset}): member name is not a valid utf8 string",
                    )
                })?;
            let member_path = {
                let member_path = Path::new(member_name);
                let normalized = member_path.normalize_lexically_cpp();
                if normalized == member_path {
                    member_path
                } else {
                    let bytes = self
                        .bump
                        .alloc_bytes(normalized.as_os_str().as_encoded_bytes());
                    Path::new(unsafe { OsStr::from_encoded_bytes_unchecked(bytes) })
                }
            };

            let disk_path = file.path.disk.join(member_path.normalize_lexically_cpp());
            let member_path = InputFilePath {
                disk: file.path.disk,
                member: Some(member_path),
            };

            let handle = std::fs::File::open(&disk_path)
                .with_context(|| format!("cannot open {member_path}: thin archive member"))?;
            if let Some(mapping) = self.map_unique_file(handle, input_ctx) {
                let mapping = mapping
                    .with_context(|| format!("cannot open {member_path}: thin archive member"))?;
                self.parse_input_file(
                    ctx,
                    symbols,
                    scope,
                    input_ctx,
                    InputFile {
                        path: member_path,
                        data: &mapping,
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
        self.unique_paths.insert((path, input_ctx)).then(|| {
            std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))
        })
    }

    fn map_unique_file(
        &mut self,
        file: std::fs::File,
        input_ctx: InputArgContext,
    ) -> Option<crate::Result<&'a Mmap>> {
        file.unique_id()
            .map_err(crate::Error::from)
            .and_then(|ufid| {
                self.unique_mappings
                    .insert((ufid, input_ctx))
                    .then(|| {
                        unsafe { Mmap::map(&file) }
                            .map(|mapping| &*self.mappings.alloc(mapping))
                            .map_err(crate::Error::from)
                    })
                    .transpose()
            })
            .transpose()
    }

    fn find_unique_library(
        &mut self,
        ctx: &LinkContext<'a>,
        name: &'a OsStr,
        input_ctx: InputArgContext,
    ) -> Option<crate::Result<(PathBuf, std::fs::File)>> {
        self.unique_libraries.insert((name, input_ctx)).then(|| {
            find_library(&ctx.options.library_path, input_ctx.in_static, name)
                .with_context(|| format!("unable to find library -l{}", name.display()))
        })
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
    // lib<name>.lib
    let mut namebuf = OsString::new();
    search_paths.iter().find_map(|search_path| {
        buf.clear();
        buf.push(search_path);
        buf.push(name);
        [
            ("lib", "dll.a"),
            ("", "dll.a"),
            ("lib", "a"),
            ("", "lib"),
            ("lib", "lib"),
        ]
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

fn alloc_path<'a>(bump: &BumpHandle<'a>, path: &Path) -> &'a Path {
    let bytes = bump.alloc_bytes(path.as_os_str().as_encoded_bytes());
    Path::new(unsafe { OsStr::from_encoded_bytes_unchecked(bytes) })
}
