use std::path::PathBuf;

use indexmap::IndexSet;

use crate::{
    api::BeaconApiInit,
    libsearch::{LibraryFind, LibrarySearcher},
    pathed_item::PathedItem,
};

use super::{ConfiguredLinker, CustomApiInit, LinkImpl, LinkerTargetArch};

/// Sets up inputs and configures a [`super::Linker`].
#[derive(Default)]
pub struct LinkerBuilder<L: LibraryFind + 'static> {
    /// The target architecture.
    pub(super) target_arch: Option<LinkerTargetArch>,

    /// The input files to link.
    pub(super) inputs: Vec<PathedItem<PathBuf, Vec<u8>>>,

    /// Link libraries.
    pub(super) libraries: IndexSet<String>,

    /// The name of the entrypoint symbol.
    pub(super) entrypoint: Option<String>,

    /// Custom BOF API to use.
    pub(super) custom_api: Option<String>,

    /// Whether to merge the .bss section with the .data section.
    pub(super) merge_bss: bool,

    /// Searcher for finding link libraries.
    pub(super) library_searcher: Option<L>,

    /// Output path for dumping the link graph.
    pub(super) link_graph_output: Option<PathBuf>,

    /// Perform GC sections.
    pub(super) gc_sections: bool,

    /// Keep the specified symbols during GC sections.
    pub(super) gc_keep_symbols: IndexSet<String>,
}

impl<L: LibraryFind + 'static> LinkerBuilder<L> {
    /// Creates a new [`LinkerBuilder`] with the defaults.
    pub fn new() -> Self {
        Self {
            target_arch: Default::default(),
            inputs: Default::default(),
            libraries: Default::default(),
            entrypoint: Default::default(),
            custom_api: Default::default(),
            merge_bss: false,
            library_searcher: None,
            link_graph_output: None,
            gc_sections: false,
            gc_keep_symbols: Default::default(),
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

    /// Add an input file to the linker.
    pub fn add_input(mut self, input: PathedItem<PathBuf, Vec<u8>>) -> Self {
        self.inputs.push(input);
        self
    }

    /// Add a set of input files to the linker.
    pub fn add_inputs(
        mut self,
        inputs: impl IntoIterator<Item = PathedItem<PathBuf, Vec<u8>>>,
    ) -> Self {
        self.inputs.extend(inputs);
        self
    }

    /// Add a link library to the linker.
    pub fn add_library(mut self, name: impl Into<String>) -> Self {
        self.libraries.insert(name.into());
        self
    }

    /// Add a set of link libraries to the linker.
    pub fn add_libraries<S: Into<String>, I: IntoIterator<Item = S>>(mut self, names: I) -> Self {
        self.libraries.extend(names.into_iter().map(Into::into));
        self
    }

    /// Add the specified symbol to keep during GC sections.
    pub fn add_gc_keep_symbol(mut self, symbol: impl Into<String>) -> Self {
        self.gc_keep_symbols.insert(symbol.into());
        self
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

    /// Finishes configuring the linker.
    pub fn build(mut self) -> Box<dyn LinkImpl> {
        if let Some(library_searcher) = self.library_searcher.take() {
            if let Some(custom_api) = self.custom_api.take() {
                Box::new(ConfiguredLinker::with_opts(
                    self,
                    library_searcher,
                    CustomApiInit::from(custom_api),
                ))
            } else {
                Box::new(ConfiguredLinker::with_opts(
                    self,
                    library_searcher,
                    BeaconApiInit,
                ))
            }
        } else if let Some(custom_api) = self.custom_api.take() {
            Box::new(ConfiguredLinker::with_opts(
                self,
                LibrarySearcher::new(),
                CustomApiInit::from(custom_api),
            ))
        } else {
            Box::new(ConfiguredLinker::with_opts(
                self,
                LibrarySearcher::new(),
                BeaconApiInit,
            ))
        }
    }
}
