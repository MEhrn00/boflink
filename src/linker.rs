use std::{
    collections::HashSet,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use indexmap::IndexMap;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use object::{
    Object, ObjectSymbol,
    coff::CoffFile,
    pe::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386},
};
use typed_arena::Arena;

use crate::{
    api::ApiSymbols,
    cli::{InputArg, InputArgVariant},
    graph::{LinkGraph, LinkGraphArena, SpecLinkGraph},
    linkobject::archive::{LinkArchive, LinkArchiveMemberVariant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum LinkerTargetArch {
    Amd64 = IMAGE_FILE_MACHINE_AMD64,
    I386 = IMAGE_FILE_MACHINE_I386,
}

impl From<LinkerTargetArch> for object::Architecture {
    fn from(value: LinkerTargetArch) -> Self {
        match value {
            LinkerTargetArch::Amd64 => object::Architecture::X86_64,
            LinkerTargetArch::I386 => object::Architecture::I386,
        }
    }
}

impl TryFrom<object::Architecture> for LinkerTargetArch {
    type Error = object::Architecture;

    fn try_from(value: object::Architecture) -> Result<Self, Self::Error> {
        Ok(match value {
            object::Architecture::X86_64 => Self::Amd64,
            object::Architecture::I386 => Self::I386,
            _ => return Err(value),
        })
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CoffPath<'a> {
    pub file_path: &'a Path,
    pub member_path: Option<&'a Path>,
}

impl std::fmt::Display for CoffPath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(member) = self.member_path {
            write!(f, "{}({})", self.file_path.display(), member.display())
        } else {
            write!(f, "{}", self.file_path.display())
        }
    }
}

/// Process the linker inputs
pub struct LinkInputProcessor<'b, 'a> {
    /// Arena for holding opened files
    arena: &'a Arena<(PathBuf, Vec<u8>)>,

    /// Used for finding link libraries
    search_paths: &'b [PathBuf],

    /// The names of opened link libraries
    pub opened_library_names: HashSet<String>,

    /// Parsed COFF inputs.
    pub coffs: IndexMap<CoffPath<'a>, CoffFile<'a>>,

    /// Parsed lazily linked libraries.
    pub link_libraries: IndexMap<&'a Path, LinkArchive<'a>>,

    /// Spec graph
    spec: SpecLinkGraph,
}

impl<'b, 'a> LinkInputProcessor<'b, 'a> {
    pub fn with_capacity(
        arena: &'a Arena<(PathBuf, Vec<u8>)>,
        search_paths: &'b [PathBuf],
        capacity: usize,
    ) -> LinkInputProcessor<'b, 'a> {
        Self {
            arena,
            search_paths,
            opened_library_names: HashSet::with_capacity(capacity),
            coffs: IndexMap::with_capacity(capacity),
            link_libraries: IndexMap::with_capacity(capacity),
            spec: SpecLinkGraph::new(),
        }
    }

    pub fn alloc_arena(&self) -> LinkGraphArena {
        self.spec.alloc_arena()
    }

    pub fn alloc_graph<'c>(
        &self,
        arena: &'c LinkGraphArena,
        architecture: LinkerTargetArch,
    ) -> LinkGraph<'c, 'a> {
        self.spec.alloc_graph(arena, architecture)
    }

    pub fn process_input(&mut self, input: InputArg) -> anyhow::Result<()> {
        match input.variant {
            InputArgVariant::File(file_path) => {
                let buffer = std::fs::read(&file_path)
                    .with_context(|| format!("cannot open {}", file_path.display()))?;
                let (file_path, buffer) = self.arena.alloc((file_path, buffer));

                if object_is_archive(buffer.as_slice()) {
                    let library = LinkArchive::parse(buffer.as_slice())
                        .with_context(|| format!("cannot parse {}", file_path.display()))?;

                    if input.context.in_whole_archive {
                        self.add_archive_members(file_path.as_path(), library)
                            .with_context(|| format!("{}", file_path.display()))?;
                    } else if !self.link_libraries.contains_key(file_path.as_path()) {
                        self.link_libraries.insert(file_path.as_path(), library);
                    }
                } else {
                    let coff: CoffFile = CoffFile::parse(buffer.as_slice())
                        .with_context(|| format!("cannot parse {}", file_path.display()))?;

                    if let indexmap::map::Entry::Vacant(coff_entry) = self.coffs.entry(CoffPath {
                        file_path: file_path.as_path(),
                        member_path: None,
                    }) {
                        self.spec.add_coff(&coff);
                        coff_entry.insert(coff);
                    }
                }
            }
            InputArgVariant::Library(library_name) => {
                let library_name = library_name.to_string_lossy().to_string();
                if !self.opened_library_names.contains(&library_name) {
                    let (library_path, library_buffer) =
                        find_library(self.search_paths, &library_name)
                            .with_context(|| format!("unable to find library -l{library_name}"))?;

                    self.opened_library_names.insert(library_name);

                    if input.context.in_whole_archive {
                        let (library_path, library_buffer) =
                            self.arena.alloc((library_path, library_buffer));
                        let archive = LinkArchive::parse(library_buffer.as_slice())
                            .with_context(|| format!("cannot parse {}", library_path.display()))?;

                        self.add_archive_members(library_path.as_path(), archive)
                            .with_context(|| format!("{}", library_path.display()))?;
                    } else if !self.link_libraries.contains_key(library_path.as_path()) {
                        let (library_path, library_buffer) =
                            self.arena.alloc((library_path, library_buffer));
                        let archive = LinkArchive::parse(library_buffer.as_slice())
                            .with_context(|| format!("cannot parse {}", library_path.display()))?;

                        self.link_libraries.insert(library_path.as_path(), archive);
                    }
                }
            }
        }

        Ok(())
    }

    fn add_archive_members(
        &mut self,
        archive_path: &'a Path,
        archive: LinkArchive<'a>,
    ) -> anyhow::Result<()> {
        for member in archive.coff_members() {
            let (member_path, coff) = member?;

            if let indexmap::map::Entry::Vacant(coff_entry) = self.coffs.entry(CoffPath {
                file_path: archive_path,
                member_path: Some(member_path),
            }) {
                self.spec.add_coff(&coff);
                coff_entry.insert(coff);
            }
        }

        Ok(())
    }

    pub fn open_custom_api(&mut self, library: String) -> anyhow::Result<ApiSymbols<'a>> {
        let custom_api = match std::fs::read(&library) {
            Ok(buffer) => (PathBuf::from(library), buffer),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let found = find_library(self.search_paths, &library)
                    .with_context(|| format!("unable to find --custom-api: {library}"))?;
                self.opened_library_names.insert(library);
                found
            }
            Err(e) => {
                bail!("cannot open {library}: {e}");
            }
        };

        let (api_path, api_buffer) = self.arena.alloc(custom_api);

        let api_archive = LinkArchive::parse(api_buffer.as_slice())
            .with_context(|| format!("cannot parse {}", api_path.display()))?;

        ApiSymbols::new(api_path.as_path(), api_archive)
            .with_context(|| format!("{}", api_path.display()))
    }

    pub fn ensure_entrypoint(&mut self, entrypoint: &str) {
        if !self.coffs.values().any(|coff| {
            coff.symbol_by_name(entrypoint)
                .is_some_and(|symbol| symbol.is_global() && symbol.is_definition())
        }) {
            for (library_path, library) in &self.link_libraries {
                if let Some(symbol) = library
                    .symbols()
                    .filter_map(|symbol| symbol.ok())
                    .find(|symbol| symbol.name() == entrypoint)
                {
                    if let Ok((member_path, LinkArchiveMemberVariant::Coff(coff_member))) =
                        symbol.extract()
                    {
                        self.coffs.insert(
                            CoffPath {
                                file_path: library_path,
                                member_path: Some(member_path),
                            },
                            coff_member,
                        );
                    }

                    return;
                }
            }
        }
    }
}

fn object_is_archive(buffer: impl AsRef<[u8]>) -> bool {
    buffer
        .as_ref()
        .get(..object::archive::MAGIC.len())
        .is_some_and(|magic| magic == object::archive::MAGIC)
}

pub fn find_library(search_paths: &[PathBuf], name: impl AsRef<str>) -> Option<(PathBuf, Vec<u8>)> {
    let try_open_path = |path: &Path| -> Option<Vec<u8>> {
        std::fs::read(path)
            .inspect_err(|e| log::debug!("attempt to open {} failed: {e}", path.display()))
            .ok()
    };

    let name = name.as_ref();

    if let Some(filename) = name.strip_prefix(':') {
        search_paths.iter().find_map(|search_path| {
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

        search_paths.iter().find_map(|search_path| {
            patterns.into_iter().find_map(|(prefix, name, ext)| {
                let filename = format!("{prefix}{name}{ext}");
                let full_path = search_path.join(filename);
                try_open_path(&full_path).map(|buffer| (full_path, buffer))
            })
        })
    }
}
