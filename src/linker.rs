use std::{
    collections::{HashSet, VecDeque},
    io::{BufWriter, ErrorKind},
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use indexmap::{IndexMap, IndexSet};
use log::warn;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use object::{
    Object, ObjectSymbol,
    coff::CoffFile,
    pe::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386},
};
use typed_arena::Arena;

use crate::{
    api::ApiSymbols,
    drectve,
    graph::SpecLinkGraph,
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

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct LinkInput {
    pub variant: LinkInputVariant,
    pub options: LinkInputOptions,
}

/// The linker input types.
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum LinkInputVariant {
    /// A file path passed on the command line.
    File(PathBuf),

    /// A link library passed on the command line.
    Library(String),
}

/// The input attributes.
#[derive(Debug, Default, PartialEq, Eq, Hash)]
pub struct LinkInputOptions {
    /// If the input is a static archive, include all the members as inputs
    pub whole: bool,
}

#[derive(Debug, Default)]
pub struct Config {
    pub custom_api: Option<String>,
    pub entrypoint: Option<String>,
    pub gc_sections: bool,
    pub gc_roots: IndexSet<String>,
    pub ignored_unresolved_symbols: HashSet<String>,
    pub inputs: IndexSet<LinkInput>,
    pub link_graph_output: Option<PathBuf>,
    pub merge_bss: bool,
    pub merge_grouped_sections: bool,
    pub print_gc_sections: bool,
    pub search_paths: IndexSet<PathBuf>,
    pub target_architecture: Option<LinkerTargetArch>,
    pub warn_unresolved: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CoffPath<'a> {
    file_path: &'a Path,
    member_path: Option<&'a Path>,
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

/// A configured linker.
pub struct Linker {
    config: Config,
}

impl Linker {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn link(&mut self) -> anyhow::Result<Vec<u8>> {
        // Buffer arena
        let buffer_arena: Arena<(PathBuf, Vec<u8>)> =
            Arena::with_capacity(self.config.inputs.len());

        let mut input_processor = LinkInputProcessor::with_capacity(
            &buffer_arena,
            &self.config.search_paths,
            self.config.inputs.len(),
        );

        let mut errored = false;

        // Process the input files
        for link_input in std::mem::take(&mut self.config.inputs) {
            if let Err(e) = input_processor.process_input(link_input) {
                log::error!("{e:#}");
                errored = true;
            }
        }

        if let Some(entrypoint) = self.config.entrypoint.as_ref() {
            input_processor.ensure_entrypoint(entrypoint);
        }

        if errored {
            std::process::exit(1);
        }

        if input_processor.coffs.is_empty() {
            bail!("no input files");
        }

        let target_arch = self
            .config
            .target_architecture
            .take()
            .or_else(|| {
                input_processor
                    .coffs
                    .values()
                    .find_map(|coff| LinkerTargetArch::try_from(coff.architecture()).ok())
            })
            .context("cannot detect target architecture from input files")?;

        let string_arena = Arena::new();
        let api_symbols = self
            .config
            .custom_api
            .take()
            .map(|api| input_processor.open_custom_api(api))
            .unwrap_or_else(|| Ok(ApiSymbols::beacon(&string_arena, target_arch)))?;

        // Build the graph
        let graph_arena = input_processor.spec.alloc_arena();
        let mut graph = input_processor.spec.alloc_graph(&graph_arena, target_arch);

        // Add COFFs
        for (coff_path, coff) in &input_processor.coffs {
            for library_name in drectve::parse_defaultlibs_normalized(coff)
                .into_iter()
                .flatten()
            {
                if input_processor.opened_library_names.contains(library_name) {
                    continue;
                }

                let search_result = find_library(&self.config.search_paths, library_name)
                    .with_context(|| format!("{coff_path}: unable to find library {library_name}"));

                let (library_path, buffer) = match search_result {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!("{e}");
                        errored = true;
                        continue;
                    }
                };

                input_processor
                    .opened_library_names
                    .insert(library_name.to_string());

                if input_processor
                    .link_libraries
                    .contains_key(library_path.as_path())
                {
                    continue;
                }

                let (library_path, library_buffer) =
                    input_processor.arena.alloc((library_path, buffer));
                let archive = match LinkArchive::parse(library_buffer.as_slice()) {
                    Ok(parsed) => parsed,
                    Err(e) => {
                        log::error!("{}: {e}", library_path.as_path().display());
                        errored = true;
                        continue;
                    }
                };

                input_processor
                    .link_libraries
                    .insert(library_path.as_path(), archive);
            }

            if let Err(e) = graph.add_coff(coff_path.file_path, coff_path.member_path, coff) {
                log::error!("{coff_path}: {e}");
                errored = true;
            }
        }

        // Check for any errors
        if errored {
            std::process::exit(1);
        }

        let mut drectve_queue: VecDeque<((&Path, &Path), &str)> = VecDeque::new();

        let resolve_count = graph.archive_resolvable_externals().count();
        let mut symbol_search_buffer = VecDeque::with_capacity(resolve_count);
        let mut undefined_symbols: IndexSet<&str> = IndexSet::with_capacity(resolve_count);

        // Resolve symbols
        loop {
            // Get the list of undefined symbols to search for
            symbol_search_buffer.extend(
                graph
                    .archive_resolvable_externals()
                    .filter(|symbol| !undefined_symbols.contains(symbol)),
            );

            // If the search list is empty, finished resolving
            if symbol_search_buffer.is_empty() {
                break;
            }

            // Attempt to resolve each symbol in the search list
            'symbol: while let Some(symbol_name) = symbol_search_buffer.pop_front() {
                // Try resolving it as an API import first
                if let Some(api_import) = api_symbols.get(symbol_name) {
                    if let Err(e) = graph.add_api_import(symbol_name, api_import) {
                        log::error!("{}: {e}", api_symbols.archive_path().display());
                        errored = true;
                    }

                    continue;
                }

                // Open any pending libraries in the .drectve queue
                while let Some(((library_path, coff_path), drectve_library)) =
                    drectve_queue.pop_front()
                {
                    match find_library(&self.config.search_paths, drectve_library) {
                        Some(found) => {
                            if !input_processor
                                .opened_library_names
                                .contains(drectve_library)
                            {
                                input_processor
                                    .opened_library_names
                                    .insert(drectve_library.to_string());

                                let (library_path, library_buffer) = buffer_arena.alloc(found);

                                match LinkArchive::parse(library_buffer.as_slice()) {
                                    Ok(parsed) => {
                                        input_processor
                                            .link_libraries
                                            .insert(library_path.as_path(), parsed);
                                    }
                                    Err(e) => {
                                        log::error!(
                                            "{}({}): {e}",
                                            library_path.display(),
                                            coff_path.display()
                                        );
                                        errored = true;
                                    }
                                }
                            }
                        }
                        None => {
                            log::error!(
                                "{}({}): unable to find library {drectve_library}",
                                library_path.display(),
                                coff_path.display()
                            );
                            errored = true;
                        }
                    }
                }

                // Attempt to resolve the symbol using the opened link libraries
                for (library_path, library) in &input_processor.link_libraries {
                    let (member_path, member) = match library.extract_symbol(symbol_name) {
                        Ok(Some(extracted)) => extracted,
                        Ok(None) => {
                            continue;
                        }
                        Err(e) => {
                            log::error!("{}: {e}", library_path.display());
                            errored = true;
                            continue;
                        }
                    };

                    match member {
                        LinkArchiveMemberVariant::Coff(coff) => {
                            // Add any .drectve link libraries from linked in COFFs
                            // to the drectve queue
                            for drectve_library in drectve::parse_defaultlibs_normalized(&coff)
                                .into_iter()
                                .flatten()
                            {
                                if !input_processor
                                    .opened_library_names
                                    .contains(drectve_library)
                                {
                                    drectve_queue
                                        .push_back(((library_path, member_path), drectve_library));
                                }
                            }

                            if let Err(e) = graph.add_coff(library_path, Some(member_path), &coff) {
                                log::error!(
                                    "{}({}): {e}",
                                    library_path.display(),
                                    member_path.display()
                                );
                                errored = true;
                                continue;
                            }

                            continue 'symbol;
                        }
                        LinkArchiveMemberVariant::Import(import_member) => {
                            if let Err(e) = graph.add_library_import(symbol_name, &import_member) {
                                log::error!(
                                    "{}({}): {e}",
                                    library_path.display(),
                                    member_path.display()
                                );
                                errored = true;
                                continue;
                            }

                            continue 'symbol;
                        }
                    }
                }

                // Symbol could not be found in any of the link libraries
                undefined_symbols.insert(symbol_name);
            }
        }

        // Write out the link graph
        if let Some(graph_path) = self.config.link_graph_output.as_ref() {
            match std::fs::File::create(graph_path) {
                Ok(f) => {
                    if let Err(e) = graph.write_dot_graph(BufWriter::new(f)) {
                        warn!("cannot not write link graph: {e}");
                    }
                }
                Err(e) => {
                    warn!("cannot not open {}: {e}", graph_path.display());
                }
            }
        }

        // Check errors
        if errored {
            std::process::exit(1);
        }

        // Finish building the link graph
        let finish_result = if self.config.warn_unresolved {
            graph.finish_unresolved(&self.config.ignored_unresolved_symbols)
        } else {
            graph.finish(&self.config.ignored_unresolved_symbols)
        };

        let mut graph = match finish_result {
            Ok(graph) => graph,
            Err(_) => {
                std::process::exit(1);
            }
        };

        // Run GC sections
        if self.config.gc_sections {
            graph.gc_sections(self.config.entrypoint.as_ref(), self.config.gc_roots.iter())?;

            if self.config.print_gc_sections {
                graph.print_discarded_sections();
            }
        }

        // Run merge bss
        if self.config.merge_bss {
            graph.merge_bss();
        }

        // Build the linked output from the graph
        if self.config.merge_grouped_sections {
            Ok(graph.link_merge_groups()?)
        } else {
            Ok(graph.link()?)
        }
    }
}

/// Process the linker inputs
struct LinkInputProcessor<'b, 'a> {
    /// Arena for holding opened files
    arena: &'a Arena<(PathBuf, Vec<u8>)>,

    /// Used for finding link libraries
    search_paths: &'b IndexSet<PathBuf>,

    /// The names of opened link libraries
    opened_library_names: HashSet<String>,

    /// Parsed COFF inputs.
    coffs: IndexMap<CoffPath<'a>, CoffFile<'a>>,

    /// Parsed lazily linked libraries.
    link_libraries: IndexMap<&'a Path, LinkArchive<'a>>,

    /// Spec graph
    spec: SpecLinkGraph,
}

impl<'b, 'a> LinkInputProcessor<'b, 'a> {
    pub fn with_capacity(
        arena: &'a Arena<(PathBuf, Vec<u8>)>,
        search_paths: &'b IndexSet<PathBuf>,
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

    pub fn process_input(&mut self, input: LinkInput) -> anyhow::Result<()> {
        match input.variant {
            LinkInputVariant::File(file_path) => {
                let buffer = std::fs::read(&file_path)
                    .with_context(|| format!("cannot open {}", file_path.display()))?;
                let (file_path, buffer) = self.arena.alloc((file_path, buffer));

                if object_is_archive(buffer.as_slice()) {
                    let library = LinkArchive::parse(buffer.as_slice())
                        .with_context(|| format!("cannot parse {}", file_path.display()))?;

                    if input.options.whole {
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
            LinkInputVariant::Library(library_name) => {
                if !self.opened_library_names.contains(&library_name) {
                    let (library_path, library_buffer) =
                        find_library(self.search_paths, &library_name)
                            .with_context(|| format!("unable to find library -l{library_name}"))?;

                    self.opened_library_names.insert(library_name);

                    if input.options.whole {
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

    fn open_custom_api(&mut self, library: String) -> anyhow::Result<ApiSymbols<'a>> {
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

    fn ensure_entrypoint(&mut self, entrypoint: &str) {
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

fn find_library(
    search_paths: &IndexSet<PathBuf>,
    name: impl AsRef<str>,
) -> Option<(PathBuf, Vec<u8>)> {
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
