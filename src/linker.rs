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
    libsearch::{LibraryFind, LibrarySearcher},
    linkobject::archive::{LinkArchive, LinkArchiveMemberVariant},
};

pub trait LinkImpl {
    fn link(&mut self) -> anyhow::Result<Vec<u8>>;
}

#[derive(Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
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

/// The linker input types.
#[derive(PartialEq, Eq, Hash)]
pub(crate) enum LinkInput {
    /// A file path passed on the command line.
    File(PathBuf),

    /// A link library passed on the command line.
    Library(String),
}

/// The input attributes.
#[derive(Default)]
pub(crate) struct LinkInputItem {
    /// An already opened buffer associated with the input.
    pub buffer: Option<Vec<u8>>,

    /// If the input is a static archive, include all the members as inputs
    pub whole: bool,
}

/// Sets up inputs and configures a [`super::Linker`].
#[derive(Default)]
pub struct LinkerBuilder<L: LibraryFind + 'static> {
    /// The target architecture.
    pub(super) target_arch: Option<LinkerTargetArch>,

    /// The ordered link inputs and attributes.
    pub(super) inputs: IndexMap<LinkInput, LinkInputItem>,

    /// The name of the entrypoint symbol.
    pub(super) entrypoint: Option<String>,

    /// The custom BOF API library.
    pub(super) custom_api: Option<String>,

    /// Whether to merge the .bss section with the .data section.
    pub(super) merge_bss: bool,

    /// Merge grouped sections.
    pub(super) merge_grouped_sections: bool,

    /// Searcher for finding link libraries.
    pub(super) library_searcher: Option<L>,

    /// Output path for dumping the link graph.
    pub(super) link_graph_output: Option<PathBuf>,

    /// Perform GC sections.
    pub(super) gc_sections: bool,

    /// Keep the specified symbols during GC sections.
    pub(super) gc_keep_symbols: IndexSet<String>,

    /// Print sections discarded during GC sections.
    pub(super) print_gc_sections: bool,

    /// Report unresolved symbols as warnings.
    pub(super) warn_unresolved: bool,

    /// List of ignored unresolved symbols.
    pub(super) ignored_unresolved_symbols: HashSet<String>,
}

impl<L: LibraryFind + 'static> LinkerBuilder<L> {
    /// Creates a new [`LinkerBuilder`] with the defaults.
    pub fn new() -> Self {
        Self {
            target_arch: Default::default(),
            inputs: Default::default(),
            entrypoint: Default::default(),
            merge_bss: false,
            merge_grouped_sections: false,
            library_searcher: None,
            link_graph_output: None,
            custom_api: None,
            gc_sections: false,
            gc_keep_symbols: Default::default(),
            print_gc_sections: false,
            warn_unresolved: false,
            ignored_unresolved_symbols: HashSet::new(),
        }
    }

    /// Sets the target architecture for the linker.
    ///
    /// This is not needed if the linker can parse the target architecture
    /// from the input files.
    pub fn architecture(mut self, arch: LinkerTargetArch) -> Self {
        self.target_arch = Some(arch);
        self
    }

    /// Set the output path for dumping the link graph.
    pub fn link_graph_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.link_graph_output = Some(path.into());
        self
    }

    /// Merge the .bss section with the .data section.
    pub fn merge_bss(mut self, val: bool) -> Self {
        self.merge_bss = val;
        self
    }

    /// Merge grouped sections.
    pub fn merge_grouped_sections(mut self, val: bool) -> Self {
        self.merge_grouped_sections = val;
        self
    }

    /// Set the name of the entrypoint symbol.
    pub fn entrypoint(mut self, name: impl Into<String>) -> Self {
        self.entrypoint = Some(name.into());
        self
    }

    /// Custom BOF API to use instead of the Beacon API.
    pub fn custom_api(mut self, api: impl Into<String>) -> Self {
        self.custom_api = Some(api.into());
        self
    }

    /// Set the library searcher to use for finding link libraries.
    pub fn library_searcher(mut self, searcher: L) -> Self {
        self.library_searcher = Some(searcher);
        self
    }

    /// Enable GC sections.
    pub fn gc_sections(mut self, val: bool) -> Self {
        self.gc_sections = val;
        self
    }

    /// Print sections discarded during GC sections.
    pub fn print_gc_sections(mut self, val: bool) -> Self {
        self.print_gc_sections = val;
        self
    }

    /// Report unresolved symbols as warnings.
    pub fn warn_unresolved(mut self, val: bool) -> Self {
        self.warn_unresolved = val;
        self
    }

    /// Add a file path to link
    pub fn add_file_path(&mut self, path: impl Into<PathBuf>) {
        self.inputs.entry(LinkInput::File(path.into())).or_default();
    }

    /// Add a file path to link
    pub fn add_whole_file_path(&mut self, path: impl Into<PathBuf>) {
        let entry = self.inputs.entry(LinkInput::File(path.into())).or_default();
        entry.whole = true;
    }

    /// Add a link library to the linker.
    pub fn add_library(&mut self, name: impl Into<String>) {
        self.inputs
            .entry(LinkInput::Library(name.into()))
            .or_default();
    }

    /// Add a link library to the linker.
    pub fn add_whole_library(&mut self, name: impl Into<String>) {
        let entry = self
            .inputs
            .entry(LinkInput::Library(name.into()))
            .or_default();
        entry.whole = true;
    }

    /// Adds the list of symbols to keep during GC sections.
    pub fn add_gc_keep_symbols<S: Into<String>, I: IntoIterator<Item = S>>(
        mut self,
        symbols: I,
    ) -> Self {
        self.gc_keep_symbols
            .extend(symbols.into_iter().map(Into::into));
        self
    }

    /// Add ignored unresolved symbols.
    pub fn add_ignored_unresolved_symbols<S: Into<String>, I: IntoIterator<Item = S>>(
        &mut self,
        symbols: I,
    ) {
        self.ignored_unresolved_symbols
            .extend(symbols.into_iter().map(Into::into));
    }

    /// Finishes configuring the linker.
    pub fn build(mut self) -> Box<dyn LinkImpl> {
        if let Some(library_searcher) = self.library_searcher.take() {
            Box::new(ConfiguredLinker::with_opts(self, library_searcher))
        } else {
            Box::new(ConfiguredLinker::with_opts(self, LibrarySearcher::new()))
        }
    }
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
pub struct ConfiguredLinker<L: LibraryFind> {
    /// The target architecture.
    target_arch: Option<LinkerTargetArch>,

    /// The linker inputs
    inputs: IndexMap<LinkInput, LinkInputItem>,

    /// The link library searcher.
    library_searcher: L,

    /// The name of the entrypoint symbol.
    entrypoint: Option<String>,

    /// The custom BOF API library.
    custom_api: Option<String>,

    /// Whether to merge the .bss section with the .data section.
    merge_bss: bool,

    /// Whether to perform GC sections.
    gc_sections: bool,

    /// GC roots.
    gc_roots: IndexSet<String>,

    /// Merge grouped sections.
    merge_grouped_sections: bool,

    /// Print GC sections discarded.
    print_gc_sections: bool,

    /// Report unresolved symbols as warnings.
    warn_unresolved: bool,

    /// Ignored unresolved symbols.
    ignored_unresolved_symbols: HashSet<String>,

    /// Output path for dumping the link graph.
    link_graph_output: Option<PathBuf>,
}

impl<L: LibraryFind> ConfiguredLinker<L> {
    pub(super) fn with_opts<T: LibraryFind>(
        builder: LinkerBuilder<T>,
        library_searcher: L,
    ) -> ConfiguredLinker<L> {
        Self {
            target_arch: builder.target_arch,
            inputs: builder.inputs,
            library_searcher,
            entrypoint: builder.entrypoint,
            custom_api: builder.custom_api,
            merge_bss: builder.merge_bss,
            merge_grouped_sections: builder.merge_grouped_sections,
            link_graph_output: builder.link_graph_output,
            gc_sections: builder.gc_sections,
            gc_roots: builder.gc_keep_symbols,
            print_gc_sections: builder.print_gc_sections,
            warn_unresolved: builder.warn_unresolved,
            ignored_unresolved_symbols: builder.ignored_unresolved_symbols,
        }
    }
}

impl<L: LibraryFind> LinkImpl for ConfiguredLinker<L> {
    fn link(&mut self) -> anyhow::Result<Vec<u8>> {
        // Buffer arena
        let buffer_arena: Arena<(PathBuf, Vec<u8>)> = Arena::with_capacity(self.inputs.len());

        let mut input_processor = LinkInputProcessor::with_capacity(
            &buffer_arena,
            &self.library_searcher,
            self.inputs.len(),
        );

        let mut errored = false;

        // Process the input files
        for (link_input, link_item) in std::mem::take(&mut self.inputs) {
            if let Err(e) = input_processor.process_input(link_input, link_item) {
                log::error!("{e:#}");
                errored = true;
            }
        }

        if let Some(entrypoint) = self.entrypoint.as_ref() {
            input_processor.ensure_entrypoint(entrypoint);
        }

        if errored {
            std::process::exit(1);
        }

        if input_processor.coffs.is_empty() {
            bail!("no input files");
        }

        let target_arch = self
            .target_arch
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

                let search_result = self
                    .library_searcher
                    .find_library(library_name)
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
                    match self.library_searcher.find_library(drectve_library) {
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
        if let Some(graph_path) = self.link_graph_output.as_ref() {
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
        let finish_result = if self.warn_unresolved {
            graph.finish_unresolved(&self.ignored_unresolved_symbols)
        } else {
            graph.finish(&self.ignored_unresolved_symbols)
        };

        let mut graph = match finish_result {
            Ok(graph) => graph,
            Err(_) => {
                std::process::exit(1);
            }
        };

        // Run GC sections
        if self.gc_sections {
            graph.gc_sections(self.entrypoint.as_ref(), self.gc_roots.iter())?;

            if self.print_gc_sections {
                graph.print_discarded_sections();
            }
        }

        // Run merge bss
        if self.merge_bss {
            graph.merge_bss();
        }

        // Build the linked output from the graph
        if self.merge_grouped_sections {
            Ok(graph.link_merge_groups()?)
        } else {
            Ok(graph.link()?)
        }
    }
}

/// Process the linker inputs
struct LinkInputProcessor<'b, 'a, L: LibraryFind> {
    /// Arena for holding opened files
    arena: &'a Arena<(PathBuf, Vec<u8>)>,

    /// Used for finding link libraries
    library_searcher: &'b L,

    /// The names of opened link libraries
    opened_library_names: HashSet<String>,

    /// Parsed COFF inputs.
    coffs: IndexMap<CoffPath<'a>, CoffFile<'a>>,

    /// Parsed lazily linked libraries.
    link_libraries: IndexMap<&'a Path, LinkArchive<'a>>,

    /// Spec graph
    spec: SpecLinkGraph,
}

impl<'b, 'a, L: LibraryFind> LinkInputProcessor<'b, 'a, L> {
    pub fn with_capacity(
        arena: &'a Arena<(PathBuf, Vec<u8>)>,
        library_searcher: &'b L,
        capacity: usize,
    ) -> LinkInputProcessor<'b, 'a, L> {
        Self {
            arena,
            library_searcher,
            opened_library_names: HashSet::with_capacity(capacity),
            coffs: IndexMap::with_capacity(capacity),
            link_libraries: IndexMap::with_capacity(capacity),
            spec: SpecLinkGraph::new(),
        }
    }

    pub fn process_input(
        &mut self,
        input: LinkInput,
        mut item: LinkInputItem,
    ) -> anyhow::Result<()> {
        match input {
            LinkInput::File(file_path) => {
                let (file_path, buffer) = if let Some(existing_buffer) = item.buffer.take() {
                    self.arena.alloc((file_path, existing_buffer))
                } else {
                    let buffer = std::fs::read(&file_path)
                        .with_context(|| format!("cannot open {}", file_path.display()))?;
                    self.arena.alloc((file_path, buffer))
                };

                if object_is_archive(buffer.as_slice()) {
                    let library = LinkArchive::parse(buffer.as_slice())
                        .with_context(|| format!("cannot parse {}", file_path.display()))?;

                    if item.whole {
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
            LinkInput::Library(library_name) => {
                if !self.opened_library_names.contains(&library_name) {
                    let (library_path, library_buffer) = self
                        .library_searcher
                        .find_library(&library_name)
                        .with_context(|| format!("unable to find library -l{library_name}"))?;

                    self.opened_library_names.insert(library_name);

                    if item.whole {
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
                let found = self
                    .library_searcher
                    .find_library(&library)
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
