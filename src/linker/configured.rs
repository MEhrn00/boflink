use std::{
    collections::{HashSet, VecDeque},
    io::{BufWriter, ErrorKind},
    path::{Path, PathBuf},
};

use indexmap::{IndexMap, IndexSet};
use log::warn;
use object::{Object, ObjectSymbol, coff::CoffFile};
use typed_arena::Arena;

use crate::{
    api::ApiSymbols,
    drectve,
    graph::SpecLinkGraph,
    libsearch::LibraryFind,
    linker::error::{DrectveLibsearchError, LinkerSymbolErrors},
    linkobject::archive::{
        ArchiveMemberError, ExtractSymbolError, LinkArchive, LinkArchiveMemberVariant,
    },
    pathed_item::PathedItem,
};

use super::{
    LinkImpl, LinkInput, LinkInputItem, LinkerBuilder, LinkerTargetArch,
    error::{
        ApiSetupError, LinkError, LinkerPathErrorKind, LinkerSetupError, LinkerSetupErrors,
        LinkerSetupPathError,
    },
};

#[derive(Clone, Hash, PartialEq, Eq)]
struct CoffPath<'a> {
    file_path: &'a Path,
    member_path: Option<&'a Path>,
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

    /// Output path for dumping the link graph.
    link_graph_output: Option<PathBuf>,
}

impl<L: LibraryFind> ConfiguredLinker<L> {
    /// Returns a [`LinkerBuilder`] for configuring a linker.
    pub fn builder() -> LinkerBuilder<L> {
        LinkerBuilder::new()
    }

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
        }
    }
}

impl<L: LibraryFind> LinkImpl for ConfiguredLinker<L> {
    fn link(&mut self) -> Result<Vec<u8>, LinkError> {
        // Buffer arena
        let buffer_arena = Arena::with_capacity(self.inputs.len());

        let mut input_processor = LinkInputProcessor::with_capacity(
            &buffer_arena,
            &self.library_searcher,
            self.inputs.len(),
        );

        // Errors during setup
        let mut setup_errors = Vec::new();

        // Process the input files
        for (link_input, link_item) in std::mem::take(&mut self.inputs) {
            if let Err(e) = input_processor.process_input(link_input, link_item) {
                setup_errors.push(e);
            }
        }

        if let Some(entrypoint) = self.entrypoint.as_ref() {
            input_processor.ensure_entrypoint(entrypoint);
        }

        let target_arch = self.target_arch.take().or_else(|| {
            input_processor
                .coffs
                .values()
                .find_map(|coff| LinkerTargetArch::try_from(coff.architecture()).ok())
        });

        let target_arch = match target_arch {
            Some(target_arch) => target_arch,
            None => {
                if !setup_errors.is_empty() {
                    return Err(LinkError::Setup(LinkerSetupErrors(setup_errors)));
                }

                if input_processor.coffs.is_empty() {
                    return Err(LinkError::NoInput);
                }

                return Err(LinkError::ArchitectureDetect);
            }
        };

        let api_symbols = match self.custom_api.take() {
            Some(custom_api) => match input_processor.open_custom_api(custom_api) {
                Ok(api_symbols) => api_symbols,
                Err(e) => {
                    setup_errors.push(LinkerSetupError::Api(e));
                    return Err(LinkError::Setup(LinkerSetupErrors(setup_errors)));
                }
            },
            None => ApiSymbols::beacon(target_arch),
        };

        // Check errors
        if !setup_errors.is_empty() {
            return Err(LinkError::Setup(LinkerSetupErrors(setup_errors)));
        }

        if input_processor.coffs.is_empty() {
            return Err(LinkError::NoInput);
        }

        // Build the graph
        let graph_arena = input_processor.spec.alloc_arena();
        let mut graph = input_processor.spec.alloc_graph(&graph_arena, target_arch);

        // Add COFFs
        for (coff_path, coff) in &input_processor.coffs {
            for library_name in drectve::parse_drectve_libraries_normalized(coff)
                .into_iter()
                .flatten()
            {
                if !input_processor.opened_library_names.contains(library_name) {
                    let library = match self.library_searcher.find_library(library_name) {
                        Ok(found) => found,
                        Err(e) => {
                            setup_errors.push(LinkerSetupError::Path(LinkerSetupPathError::new(
                                coff_path.file_path,
                                coff_path.member_path,
                                LinkerPathErrorKind::DrectveLibrary(e.into()),
                            )));
                            continue;
                        }
                    };

                    input_processor
                        .opened_library_names
                        .insert(library_name.to_string());

                    if !input_processor
                        .link_libraries
                        .contains_key(library.path().as_path())
                    {
                        let library = input_processor.arena.alloc(library);
                        let archive = match LinkArchive::parse(library.as_slice()) {
                            Ok(parsed) => parsed,
                            Err(e) => {
                                setup_errors.push(LinkerSetupError::Path(
                                    LinkerSetupPathError::nomember(library.path(), e),
                                ));
                                continue;
                            }
                        };

                        input_processor
                            .link_libraries
                            .insert(library.path().as_path(), archive);
                    }
                }
            }

            if let Err(e) = graph.add_coff(coff_path.file_path, coff_path.member_path, coff) {
                setup_errors.push(LinkerSetupError::Path(LinkerSetupPathError::new(
                    coff_path.file_path,
                    coff_path.member_path,
                    e,
                )));
            }
        }

        // Return any errors
        if !setup_errors.is_empty() {
            return Err(LinkError::Setup(LinkerSetupErrors(setup_errors)));
        }

        let mut drectve_queue: VecDeque<((&Path, &Path), &str)> = VecDeque::new();

        let undefined_count = graph.undefined_symbols().count();
        let mut symbol_search_buffer = VecDeque::with_capacity(undefined_count);
        let mut undefined_symbols: IndexSet<&str> = IndexSet::with_capacity(undefined_count);

        // Resolve symbols
        loop {
            // Get the list of undefined symbols to search for
            symbol_search_buffer.extend(
                graph
                    .undefined_symbols()
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
                        setup_errors.push(LinkerSetupError::Path(LinkerSetupPathError::nomember(
                            api_symbols.archive_path(),
                            e,
                        )));
                    }

                    continue;
                }

                // Open any pending libraries in the .drectve queue
                while let Some(((library_path, coff_path), drectve_library)) =
                    drectve_queue.pop_front()
                {
                    match self.library_searcher.find_library(drectve_library) {
                        Ok(found) => {
                            if !input_processor
                                .opened_library_names
                                .contains(drectve_library)
                            {
                                input_processor
                                    .opened_library_names
                                    .insert(drectve_library.to_string());

                                let found = buffer_arena.alloc(found);

                                match LinkArchive::parse(found.as_slice()) {
                                    Ok(parsed) => {
                                        input_processor
                                            .link_libraries
                                            .insert(found.path().as_path(), parsed);
                                    }
                                    Err(e) => {
                                        setup_errors.push(LinkerSetupError::Path(
                                            LinkerSetupPathError::new(
                                                library_path,
                                                Some(coff_path),
                                                e,
                                            ),
                                        ));
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            setup_errors.push(LinkerSetupError::Path(LinkerSetupPathError::new(
                                library_path,
                                Some(coff_path),
                                DrectveLibsearchError::from(e),
                            )));
                        }
                    }
                }

                // Attempt to resolve the symbol using the opened link libraries
                for (library_path, library) in &input_processor.link_libraries {
                    let (member_path, member) =
                        match library.extract_symbol(symbol_name) {
                            Ok(extracted) => extracted,
                            Err(ExtractSymbolError::NotFound) => {
                                continue;
                            }
                            Err(ExtractSymbolError::ArchiveParse(e)) => {
                                setup_errors.push(LinkerSetupError::Path(
                                    LinkerSetupPathError::nomember(library_path, e),
                                ));
                                continue;
                            }
                            Err(ExtractSymbolError::MemberParse(e)) => {
                                setup_errors.push(LinkerSetupError::Path(
                                    LinkerSetupPathError::new(library_path, Some(e.path), e.kind),
                                ));
                                continue;
                            }
                        };

                    match member {
                        LinkArchiveMemberVariant::Coff(coff) => {
                            // Add any .drectve link libraries from linked in COFFs
                            // to the drectve queue
                            for drectve_library in
                                drectve::parse_drectve_libraries_normalized(&coff)
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
                                setup_errors.push(LinkerSetupError::Path(
                                    LinkerSetupPathError::new(library_path, Some(member_path), e),
                                ));
                                continue;
                            }

                            continue 'symbol;
                        }
                        LinkArchiveMemberVariant::Import(import_member) => {
                            if let Err(e) = graph.add_library_import(symbol_name, &import_member) {
                                setup_errors.push(LinkerSetupError::Path(
                                    LinkerSetupPathError::new(library_path, Some(member_path), e),
                                ));
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
                        warn!("could not write link graph: {e}");
                    }
                }
                Err(e) => {
                    warn!("could not open {}: {e}", graph_path.display());
                }
            }
        }

        // Return errors
        if !setup_errors.is_empty() {
            return Err(LinkError::Setup(LinkerSetupErrors(setup_errors)));
        }

        // Finish building the link graph
        let finish_result = if self.warn_unresolved {
            graph.finish_unresolved()
        } else {
            graph.finish()
        };

        let mut graph = match finish_result {
            Ok(graph) => graph,
            Err(e) => {
                return Err(LinkError::Symbol(LinkerSymbolErrors(
                    e.into_iter().map(|v| v.into()).collect(),
                )));
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
    arena: &'a Arena<PathedItem<PathBuf, Vec<u8>>>,

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
        arena: &'a Arena<PathedItem<PathBuf, Vec<u8>>>,
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
    ) -> Result<(), LinkerSetupError> {
        match input {
            LinkInput::File(file_path) => {
                let buffer = if let Some(existing_buffer) = item.buffer.take() {
                    self.arena
                        .alloc(PathedItem::new(file_path, existing_buffer))
                } else {
                    let buffer = std::fs::read(&file_path).map_err(|e| {
                        LinkerSetupError::Path(LinkerSetupPathError::nomember(&file_path, e))
                    })?;
                    self.arena.alloc(PathedItem::new(file_path, buffer))
                };

                if object_is_archive(buffer.as_slice()) {
                    let library = LinkArchive::parse(buffer.as_slice()).map_err(|e| {
                        LinkerSetupError::Path(LinkerSetupPathError::nomember(buffer.path(), e))
                    })?;

                    if item.whole {
                        self.add_archive_members(buffer.path().as_path(), library)
                            .map_err(LinkerSetupError::Path)?;
                    } else if !self.link_libraries.contains_key(&buffer.path().as_path()) {
                        self.link_libraries.insert(buffer.path().as_path(), library);
                    }
                } else {
                    let coff: CoffFile = CoffFile::parse(buffer.as_slice()).map_err(|e| {
                        LinkerSetupError::Path(LinkerSetupPathError::nomember(buffer.path(), e))
                    })?;

                    if let indexmap::map::Entry::Vacant(coff_entry) = self.coffs.entry(CoffPath {
                        file_path: buffer.path().as_path(),
                        member_path: None,
                    }) {
                        self.spec.add_coff(&coff);
                        coff_entry.insert(coff);
                    }
                }
            }
            LinkInput::Library(library_name) => {
                if !self.opened_library_names.contains(&library_name) {
                    let library = self
                        .library_searcher
                        .find_library(&library_name)
                        .map_err(LinkerSetupError::Library)?;

                    self.opened_library_names.insert(library_name);

                    if item.whole {
                        let library = self.arena.alloc(library);
                        let archive = LinkArchive::parse(library.as_slice()).map_err(|e| {
                            LinkerSetupError::Path(LinkerSetupPathError::nomember(
                                library.path(),
                                e,
                            ))
                        })?;

                        self.add_archive_members(library.path().as_path(), archive)
                            .map_err(LinkerSetupError::Path)?;
                    } else if !self.link_libraries.contains_key(library.path().as_path()) {
                        let library = self.arena.alloc(library);
                        let archive = LinkArchive::parse(library.as_slice()).map_err(|e| {
                            LinkerSetupError::Path(LinkerSetupPathError::nomember(
                                library.path(),
                                e,
                            ))
                        })?;

                        self.link_libraries
                            .insert(library.path().as_path(), archive);
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
    ) -> Result<(), LinkerSetupPathError> {
        for member in archive.coff_members() {
            let (member_path, coff) = member.map_err(|e| match e {
                ArchiveMemberError::ArchiveParse(e) => {
                    LinkerSetupPathError::nomember(archive_path, e)
                }
                ArchiveMemberError::MemberParse(e) => {
                    LinkerSetupPathError::new(archive_path, Some(e.path), e.kind)
                }
            })?;

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

    fn open_custom_api(&mut self, library: String) -> Result<ApiSymbols<'a>, ApiSetupError> {
        let custom_api = match std::fs::read(&library) {
            Ok(buffer) => PathedItem::new(PathBuf::from(library), buffer),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                match self.library_searcher.find_library(&library) {
                    Ok(found) => {
                        self.opened_library_names.insert(library);
                        found
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => {
                return Err(ApiSetupError::Io {
                    path: PathBuf::from(library),
                    error: e,
                });
            }
        };

        let custom_api = self.arena.alloc(custom_api);

        let api_archive =
            LinkArchive::parse(custom_api.as_slice()).map_err(|e| ApiSetupError::Parse {
                path: custom_api.path().to_path_buf(),
                error: e,
            })?;

        ApiSymbols::new(custom_api.path().as_path(), api_archive).map_err(|e| {
            ApiSetupError::ApiSymbols {
                path: custom_api.path().to_path_buf(),
                error: e,
            }
        })
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
