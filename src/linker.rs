use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

use memmap2::Mmap;
use object::read::archive::ArchiveFile;
use os_str_bytes::OsStrBytesExt;
use rayon::{
    Scope,
    iter::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator},
};

use crate::{
    ErrorContext,
    arena::{ArenaHandle, ArenaRef, TypedArena},
    bail,
    cli::{InputArg, InputArgContext, InputArgVariant},
    coff::ImageFileMachine,
    context::LinkContext,
    fsutils::{UniqueFileExt, UniqueFileId},
    inputs::{FileKind, InputFile, ObjectFile, ObjectFileId},
    make_error,
    symbols::SymbolId,
    timing::ScopedTimer,
};

pub struct Linker<'a> {
    pub architecture: ImageFileMachine,
    strings: ArenaHandle<'a, u8>,
    pub objs: Vec<ArenaRef<'a, ObjectFile<'a>>>,
    pub root_symbols: Vec<SymbolId>,
}

impl<'a> Linker<'a> {
    pub fn read_inputs(
        ctx: &LinkContext<'a>,
        inputs: &'a [InputArg],
        store: &'a InputsStore<'a>,
    ) -> crate::Result<Self> {
        let _timer = ScopedTimer::msg("read inputs");

        let input_objs = TypedArena::new();
        let strings = ctx.string_pool.get();

        let mut reader = InputsReader {
            architecture: ctx
                .options
                .machine
                .map(|machine| machine.into_machine())
                .unwrap_or(ImageFileMachine::Unknown),
            strings: &strings,
            store,
            input_objs: &input_objs,
            unique_paths: HashSet::new(),
            unique_mappings: HashSet::new(),
            unique_libraries: HashSet::new(),
        };

        rayon::in_place_scope(|scope| {
            reader.create_internal_file();
            reader.read_cli_inputs(ctx, scope, inputs);
        });

        Ok(Self {
            architecture: reader.architecture,
            strings,
            objs: input_objs.into_vec(),
            root_symbols: Vec::new(),
        })
    }

    pub fn mangle(&self, name: &'a [u8]) -> &'a [u8] {
        if self.architecture != ImageFileMachine::I386 {
            return name;
        }

        self.strings.alloc_bytes([b"_", name].concat().as_slice())
    }

    pub fn add_root_symbol(&mut self, ctx: &mut LinkContext<'a>, name: &'a [u8]) {
        if let Some(symbol) = ctx
            .symbol_map
            .get_exclusive_or_default_new(self.mangle(name))
        {
            self.root_symbols.push(symbol);
        }
    }

    pub fn resolve_symbols(&mut self, ctx: &mut LinkContext<'a>) {
        let _timer = ScopedTimer::msg("symbol resolution");
        self.objs.par_iter().for_each(|obj| {
            obj.resolve_symbols(ctx, &self.objs);
        });
    }
}

#[derive(Default)]
pub struct InputsStore<'a> {
    pub files: TypedArena<InputFile<'a>>,
    pub mappings: TypedArena<Mmap>,
    pub objs: TypedArena<ObjectFile<'a>>,
}

struct InputsReader<'r, 'a: 'r> {
    architecture: ImageFileMachine,
    strings: &'r ArenaHandle<'a, u8>,
    store: &'a InputsStore<'a>,
    input_objs: &'r TypedArena<ArenaRef<'a, ObjectFile<'a>>>,
    unique_paths: HashSet<(&'a Path, InputArgContext)>,
    unique_mappings: HashSet<(UniqueFileId, InputArgContext)>,
    unique_libraries: HashSet<(&'a OsStr, InputArgContext)>,
}

impl<'r, 'a: 'r> InputsReader<'r, 'a> {
    fn create_internal_file(&self) {
        assert!(
            self.input_objs.len() == 0,
            "InputsReader::create_internal_file() must be called before inputs are added"
        );

        let obj = ArenaRef::new_in(ObjectFile::new_internal(), &self.store.objs);
        self.input_objs.alloc(obj);
    }

    fn read_cli_inputs<'scope>(
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
                let machine = ObjectFile::identify_importfile_machine(file.data)?;
                self.validate_architecture(&file, machine)?;
                let obj = self.make_new_object_file(ctx, input_ctx, file);
                let obj = self.input_objs.alloc(obj);
                scope.spawn(move |_| {
                    if let Err(e) = obj.parse_importfile(ctx) {
                        log::error!(logger: ctx, "cannot parse {}: {e}", obj.source());
                    }
                });
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
        if have_parent {
            ctx.stats
                .input_archive_members
                .fetch_add(1, Ordering::Relaxed);
        } else {
            ctx.stats.input_coffs.fetch_add(1, Ordering::Relaxed);
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

        ctx.stats.input_archives.fetch_add(1, Ordering::Relaxed);
        if archive.is_thin() {
            return self.parse_thin_archive(ctx, scope, input_ctx, file, archive);
        }

        let file = &*self.store.files.alloc(file);

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
                    .map(|mapping| &*self.store.mappings.alloc(mapping)),
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
