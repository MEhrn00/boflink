use std::{
    collections::VecDeque,
    io::BufWriter,
    path::{Path, PathBuf},
};

use indexmap::{IndexMap, IndexSet};
use log::warn;
use object::{Object, coff::CoffFile};
use typed_arena::Arena;

use crate::{
    api::{ApiSymbolError, ApiSymbolSource},
    drectve,
    graph::LinkGraph,
    libsearch::LibraryFind,
    linker::error::{DrectveLibsearchError, LinkerSymbolErrors},
    linkobject::archive::{ExtractMemberError, ExtractedMemberContents, LinkArchive},
    pathed_item::PathedItem,
};

use super::{
    ApiInit, ApiInitCtx, LinkImpl, LinkerBuilder, LinkerTargetArch,
    error::{LinkError, LinkerSetupError, LinkerSetupErrors, LinkerSetupPathError},
};

/// A configured linker.
pub struct ConfiguredLinker<L: LibraryFind, Api: ApiInit> {
    /// The target architecture.
    target_arch: Option<LinkerTargetArch>,

    /// The unparsed linker inputs
    inputs: Vec<PathedItem<PathBuf, Vec<u8>>>,

    /// The names of the link libraries.
    library_names: IndexSet<String>,

    /// The custom API.
    custom_api: Api,

    /// The link library searcher.
    library_searcher: L,

    /// The name of the entrypoint symbol.
    entrypoint: Option<String>,

    /// Whether to merge the .bss section with the .data section.
    merge_bss: bool,

    /// Whether to perform GC sections.
    gc_sections: bool,

    /// GC roots.
    gc_roots: IndexSet<String>,

    /// Print GC sections discarded.
    print_gc_sections: bool,

    /// Output path for dumping the link graph.
    link_graph_output: Option<PathBuf>,
}

impl<L: LibraryFind, Api: ApiInit> ConfiguredLinker<L, Api> {
    /// Returns a [`LinkerBuilder`] for configuring a linker.
    pub fn builder() -> LinkerBuilder<L> {
        LinkerBuilder::new()
    }

    pub(super) fn with_opts<T: LibraryFind>(
        builder: LinkerBuilder<T>,
        library_searcher: L,
        custom_api: Api,
    ) -> ConfiguredLinker<L, Api> {
        Self {
            target_arch: builder.target_arch,
            inputs: builder.inputs,
            library_names: builder.libraries,
            custom_api,
            library_searcher,
            entrypoint: builder.entrypoint,
            merge_bss: builder.merge_bss,
            link_graph_output: builder.link_graph_output,
            gc_sections: builder.gc_sections,
            gc_roots: builder.gc_keep_symbols,
            print_gc_sections: builder.print_gc_sections,
        }
    }
}

impl<L: LibraryFind, A: ApiInit> LinkImpl for ConfiguredLinker<L, A> {
    fn link(&mut self) -> Result<Vec<u8>, LinkError> {
        // Parsed input COFFs
        let mut parsed_inputs = Vec::with_capacity(self.inputs.len());

        // Errors during setup
        let mut setup_errors = Vec::new();

        // Parsed link libraries
        let mut link_libraries =
            IndexMap::with_capacity(self.inputs.len() + self.library_names.len());

        // The opened link library names including .drectve libraries
        let mut library_names: IndexSet<&str> =
            IndexSet::from_iter(self.library_names.iter().map(|v| v.as_str()));

        // Spec graph for calculating memory needed for allocating the link
        // graph.
        let mut spec = LinkGraph::spec();

        // Queue of .drectve libraries to open
        let mut drectve_queue = VecDeque::with_capacity(self.inputs.len());

        // Parse the command line input files
        for input in &self.inputs {
            // Check if this is an archive file passed in the command line
            if input
                .get(..object::archive::MAGIC.len())
                .is_some_and(|magic| magic == object::archive::MAGIC)
            {
                match LinkArchive::parse(input.as_slice())
                    .map_err(|e| LinkerSetupPathError::nomember(input.path(), e))
                {
                    Ok(parsed) => {
                        link_libraries.insert(input.path().as_path(), parsed);
                    }
                    Err(e) => {
                        setup_errors.push(LinkerSetupError::Path(e));
                    }
                };
            } else {
                match CoffFile::<_>::parse(input.as_slice())
                    .map_err(|e| LinkerSetupPathError::nomember(input.path(), e))
                {
                    Ok(parsed) => {
                        // Add .drectve libraries to the drectve_queue.
                        for library_name in drectve::parse_drectve_libraries(&parsed)
                            .into_iter()
                            .flatten()
                        {
                            let library_name = library_name.trim_end_matches(".lib");
                            if library_names.insert(library_name) {
                                drectve_queue.push_back((input.path().as_path(), library_name));
                            }
                        }

                        spec.add_coff(&parsed);

                        // Add the COFF to the list of parsed inputs.
                        parsed_inputs.push(PathedItem::new(input.path().as_path(), parsed));
                    }
                    Err(e) => {
                        setup_errors.push(LinkerSetupError::Path(e));
                    }
                }
            }
        }

        let library_arena = Arena::with_capacity(library_names.len() + 1);

        // Open link libraries
        for link_library in &self.library_names {
            let found = match self.library_searcher.find_library(link_library) {
                Ok(found) => {
                    if link_libraries.contains_key(found.path().as_path()) {
                        continue;
                    }

                    library_arena.alloc(found)
                }
                Err(e) => {
                    setup_errors.push(LinkerSetupError::Library(e));
                    continue;
                }
            };

            let parsed = match LinkArchive::parse(found.as_slice()) {
                Ok(parsed) => parsed,
                Err(e) => {
                    setup_errors.push(LinkerSetupError::Path(LinkerSetupPathError::nomember(
                        found.path(),
                        e,
                    )));
                    continue;
                }
            };

            link_libraries.insert(found.path().as_path(), parsed);
        }

        // Open drectve link libraries
        while let Some((coff_path, drectve_library)) = drectve_queue.pop_front() {
            let found = match self.library_searcher.find_library(drectve_library) {
                Ok(found) => {
                    if link_libraries.contains_key(found.path().as_path()) {
                        continue;
                    }

                    library_arena.alloc(found)
                }
                Err(e) => {
                    setup_errors.push(LinkerSetupError::Path(LinkerSetupPathError::nomember(
                        coff_path,
                        DrectveLibsearchError::from(e),
                    )));
                    continue;
                }
            };

            let parsed = match LinkArchive::parse(found.as_slice()) {
                Ok(parsed) => parsed,
                Err(e) => {
                    setup_errors.push(LinkerSetupError::Path(LinkerSetupPathError::nomember(
                        found.path(),
                        e,
                    )));
                    continue;
                }
            };

            link_libraries.insert(found.path().as_path(), parsed);
        }

        let target_arch = self.target_arch.take().or_else(|| {
            parsed_inputs
                .iter()
                .find_map(|coff| LinkerTargetArch::try_from(coff.architecture()).ok())
        });

        let target_arch = match target_arch {
            Some(target_arch) => target_arch,
            None => {
                if !setup_errors.is_empty() {
                    return Err(LinkError::Setup(LinkerSetupErrors(setup_errors)));
                }

                if self.inputs.is_empty() {
                    return Err(LinkError::NoInput);
                }

                return Err(LinkError::ArchitectureDetect);
            }
        };

        // Initialize the custom API
        let api_resolver = match self.custom_api.initialize_api(&ApiInitCtx {
            target_arch,
            library_searcher: &self.library_searcher,
            arena: &library_arena,
        }) {
            Ok(resolver) => resolver,
            Err(e) => {
                setup_errors.push(LinkerSetupError::ApiInit(e));
                return Err(LinkError::Setup(LinkerSetupErrors(setup_errors)));
            }
        };

        // Check errors
        if !setup_errors.is_empty() {
            return Err(LinkError::Setup(LinkerSetupErrors(setup_errors)));
        }

        if self.inputs.is_empty() {
            return Err(LinkError::NoInput);
        }

        // Build the graph
        let graph_arena = spec.alloc_arena();
        let mut graph = spec.alloc_graph(&graph_arena, target_arch);

        // Add COFFs
        for coff in parsed_inputs {
            if let Err(e) = graph.add_coff(coff.path(), None, &coff) {
                setup_errors.push(LinkerSetupError::Path(LinkerSetupPathError::nomember(
                    coff.path(),
                    e,
                )));
            }
        }

        // Return any errors
        if !setup_errors.is_empty() {
            return Err(LinkError::Setup(LinkerSetupErrors(setup_errors)));
        }

        // Add the entrypoint symbol so that it can be linked in from archives
        if let Some(entrypoint) = &mut self.entrypoint {
            if target_arch == LinkerTargetArch::I386 {
                *entrypoint = format!("_{entrypoint}");
            }
        }

        if let Some(entrypoint) = &self.entrypoint {
            graph.add_external_symbol(entrypoint);
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
                match api_resolver.extract_api_symbol(symbol_name) {
                    Ok(api_import) => {
                        if let Err(e) = graph.add_api_import(symbol_name, &api_import) {
                            setup_errors.push(LinkerSetupError::Path(
                                LinkerSetupPathError::nomember(api_resolver.api_path(), e),
                            ));
                        } else {
                            continue;
                        }
                    }
                    Err(ApiSymbolError::NotFound) => (),
                    Err(e) => {
                        setup_errors.push(LinkerSetupError::Path(LinkerSetupPathError::nomember(
                            api_resolver.api_path(),
                            e,
                        )));
                    }
                }

                // Open any pending libraries in the .drectve queue
                while let Some(((library_path, coff_path), drectve_library)) =
                    drectve_queue.pop_front()
                {
                    match self.library_searcher.find_library(drectve_library) {
                        Ok(found) => {
                            if library_names.insert(drectve_library) {
                                let found = library_arena.alloc(found);

                                match LinkArchive::parse(found.as_slice()) {
                                    Ok(parsed) => {
                                        link_libraries.insert(found.path().as_path(), parsed);
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
                for (library_path, library) in &link_libraries {
                    let extracted =
                        match library.extract_symbol(symbol_name) {
                            Ok(extracted) => extracted,
                            Err(ExtractMemberError::NotFound) => {
                                continue;
                            }
                            Err(ExtractMemberError::ArchiveParse(e)) => {
                                setup_errors.push(LinkerSetupError::Path(
                                    LinkerSetupPathError::nomember(library_path, e),
                                ));
                                continue;
                            }
                            Err(ExtractMemberError::MemberParse(e)) => {
                                setup_errors.push(LinkerSetupError::Path(
                                    LinkerSetupPathError::new(library_path, Some(e.path), e.kind),
                                ));
                                continue;
                            }
                        };

                    match extracted.contents() {
                        ExtractedMemberContents::Coff(coff) => {
                            // Add any .drectve link libraries from linked in COFFs
                            // to the drectve queue
                            for drectve_library in
                                drectve::parse_drectve_libraries(coff).into_iter().flatten()
                            {
                                let drectve_library_name = drectve_library.trim_end_matches(".lib");
                                if library_names.contains(drectve_library) {
                                    drectve_queue.push_back((
                                        (library_path, extracted.path()),
                                        drectve_library_name,
                                    ));
                                }
                            }

                            if let Err(e) =
                                graph.add_coff(library_path, Some(extracted.path()), coff)
                            {
                                setup_errors.push(LinkerSetupError::Path(
                                    LinkerSetupPathError::new(
                                        library_path,
                                        Some(extracted.path()),
                                        e,
                                    ),
                                ));
                                continue;
                            }

                            continue 'symbol;
                        }
                        ExtractedMemberContents::Import(import_member) => {
                            if let Err(e) = graph.add_library_import(symbol_name, import_member) {
                                setup_errors.push(LinkerSetupError::Path(
                                    LinkerSetupPathError::new(
                                        library_path,
                                        Some(extracted.path()),
                                        e,
                                    ),
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
        let mut graph = match graph.finish() {
            Ok(graph) => graph,
            Err(e) => {
                return Err(LinkError::Symbol(LinkerSymbolErrors(
                    e.into_iter().map(|v| v.into()).collect(),
                )));
            }
        };

        if self.gc_sections {
            graph.gc_sections(self.entrypoint.as_ref(), self.gc_roots.iter())?;

            if self.print_gc_sections {
                graph.print_discarded_sections();
            }
        }

        if self.merge_bss {
            graph.merge_bss();
        }

        Ok(graph.link()?)
    }
}
