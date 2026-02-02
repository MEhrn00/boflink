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
use typed_arena::Arena;

use crate::{
    ErrorContext, bail,
    cli::{InputArg, InputArgContext, InputArgVariant},
    coff::ImageFileMachine,
    context::LinkContext,
    error,
    fsutils::{UniqueFileExt, UniqueFileId},
    inputs::{FileKind, InputFile, ObjectFile, ObjectFileId, ObjectFileVariant},
    syncpool::{BumpBox, BumpRef},
    timing::ScopedTimer,
};

#[derive(Debug, Default)]
pub struct Linker<'a> {
    pub architecture: ImageFileMachine,
    pub objs: Vec<BumpBox<'a, ObjectFile<'a>>>,
}

impl<'a> Linker<'a> {
    pub fn read_inputs(
        ctx: &LinkContext<'a>,
        inputs: &'a [InputArg],
        mappings: &'a Arena<Mmap>,
    ) -> crate::Result<Self> {
        let _timer = ScopedTimer::msg("read inputs");

        let objs: Arena<BumpBox<ObjectFile>> = Arena::new();
        let bump = ctx.bump_pool.get();

        let mut reader = InputsReader {
            architecture: ctx
                .options
                .machine
                .map(|machine| machine.into_machine())
                .unwrap_or(ImageFileMachine::Unknown),
            bump: &bump,
            mappings,
            objs_arena: &objs,
            unique_paths: HashSet::new(),
            unique_mappings: HashSet::new(),
            unique_libraries: HashSet::new(),
        };

        rayon::in_place_scope(|scope| {
            reader.read_cli_inputs(ctx, scope, inputs);
        });

        Ok(Self {
            architecture: reader.architecture,
            objs: objs.into_vec(),
        })
    }
}

struct InputsReader<'r, 'a> {
    architecture: ImageFileMachine,
    bump: &'r BumpRef<'a>,
    mappings: &'a Arena<Mmap>,
    objs_arena: &'r Arena<BumpBox<'a, ObjectFile<'a>>>,
    unique_paths: HashSet<(&'a Path, InputArgContext)>,
    unique_mappings: HashSet<(UniqueFileId, InputArgContext)>,
    unique_libraries: HashSet<(&'a OsStr, InputArgContext)>,
}

impl<'r, 'a> InputsReader<'r, 'a> {
    fn read_cli_inputs<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        scope: &Scope<'scope>,
        inputs: &'a [InputArg],
    ) where
        'r: 'scope,
        'a: 'scope,
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

        ctx.check_errored();
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
        'a: 'scope,
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
        'a: 'scope,
    {
        if let Some(found) = self.find_unique_library(ctx, library, input_ctx) {
            let (path, file) = found?;
            let path = {
                let path_bytes = &*self.bump.alloc_bytes(path.as_os_str().as_encoded_bytes());
                Path::new(unsafe { OsStr::from_encoded_bytes_unchecked(path_bytes) })
            };

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
        'a: 'scope,
    {
        if let Some(mapping) = self.map_unique_file(path, file, input_ctx) {
            let mapping = mapping?;
            ctx.stats.input_files.fetch_add(1, Ordering::Relaxed);
            self.parse_input_file(
                ctx,
                scope,
                input_ctx,
                InputFile {
                    data: &mapping,
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
        'a: 'scope,
    {
        let kind = FileKind::detect(file.data)
            .with_context(|| format!("cannot parse {}", file.source()))?;

        match kind {
            FileKind::Coff => {
                self.parse_object_file(
                    ctx,
                    scope,
                    input_ctx,
                    file,
                    ObjectFileVariant::Coff(Default::default()),
                )?;
            }
            FileKind::Import => {
                self.parse_object_file(
                    ctx,
                    scope,
                    input_ctx,
                    file,
                    ObjectFileVariant::Import(Default::default()),
                )?;
            }
            FileKind::Archive => {
                if file.parent.is_some() {
                    log::warn!("{}: skipping archive file member in archive", file.source());
                    return Ok(());
                }

                self.parse_archive_file(ctx, scope, input_ctx, file)?;
            }
            FileKind::ModuleDef => {
                unimplemented!("parse module def");
            }
        }

        Ok(())
    }

    fn parse_object_file<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        file: InputFile<'a>,
        variant: ObjectFileVariant<'a>,
    ) -> crate::Result<()>
    where
        'r: 'scope,
        'a: 'scope,
    {
        if file.parent.is_some() {
            ctx.stats
                .input_archive_members
                .fetch_add(1, Ordering::Relaxed);
        } else {
            ctx.stats.input_coffs.fetch_add(1, Ordering::Relaxed);
        }

        let obj = {
            let have_parent = file.parent.is_some();
            let obj = self.bump.alloc_boxed(ObjectFile::new(
                ObjectFileId::new(self.objs_arena.len()),
                file,
                input_ctx.in_lib || (have_parent && !input_ctx.in_whole_archive),
                variant,
            ));
            self.objs_arena.alloc(obj)
        };

        self.validate_object_architecture(obj)?;

        ctx.stats.parsed_coffs.fetch_add(1, Ordering::Relaxed);
        scope.spawn(move |_| {
            if let Err(e) = obj.parse(ctx) {
                log::error!(logger: ctx, "{e}");
            }
        });

        Ok(())
    }

    fn validate_object_architecture(&mut self, obj: &ObjectFile) -> crate::Result<()> {
        let machine = ObjectFile::identify_machine(obj.file().data)?;
        if !(machine == ImageFileMachine::Amd64 || machine == ImageFileMachine::I386) {
            bail!(
                "cannot parse {}: unsupported COFF architecture '{machine:#}'",
                obj.source(),
            );
        }

        if self.architecture == ImageFileMachine::Unknown {
            self.architecture = machine;
        } else if self.architecture != machine {
            bail!(
                "cannot parse {}: expected machine value '{}' but found '{machine}'",
                obj.source(),
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
        'a: 'scope,
    {
        let archive = ArchiveFile::parse(file.data)
            .with_context(|| format!("cannot parse {}", file.source()))?;

        ctx.stats.input_archives.fetch_add(1, Ordering::Relaxed);
        if archive.is_thin() {
            return self.parse_thin_archive(ctx, scope, input_ctx, file, archive);
        }

        let file = &*self.bump.alloc(file);

        for member in archive.members() {
            let member = member.with_context(|| format!("cannot parse {}", file.source()))?;
            let offset = member.file_range().0;
            let member_name = std::str::from_utf8(member.name()).map_err(|_| {
                error!(
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

    fn parse_thin_archive<'scope>(
        &mut self,
        ctx: &'scope LinkContext<'a>,
        scope: &Scope<'scope>,
        input_ctx: InputArgContext,
        file: InputFile<'a>,
        archive: ArchiveFile<'a>,
    ) -> crate::Result<()>
    where
        'r: 'scope,
        'a: 'scope,
    {
        todo!("thin archives")
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
        path: &'a Path,
        file: std::fs::File,
        input_ctx: InputArgContext,
    ) -> Option<crate::Result<&'a Mmap>> {
        let ufid = match file
            .unique_id()
            .with_context(|| format!("cannot open {}", path.display()))
        {
            Ok(ufid) => ufid,
            Err(e) => return Some(Err(e)),
        };

        if self.unique_mappings.insert((ufid, input_ctx)) {
            Some(
                unsafe { Mmap::map(&file) }
                    .with_context(|| format!("cannot open {}", path.display()))
                    .map(|mapping| &*self.mappings.alloc(mapping)),
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
            Some(
                found.with_context(|| {
                    format!("unable to find library -l{}", name.to_string_lossy())
                }),
            )
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
