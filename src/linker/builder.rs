use std::path::PathBuf;

use indexmap::{IndexMap, IndexSet};

use crate::libsearch::{LibraryFind, LibrarySearcher};

use super::{ConfiguredLinker, LinkImpl, LinkerTargetArch};

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

    /// Add a file from memory to link
    pub fn add_file_memory(&mut self, path: impl Into<PathBuf>, buffer: impl Into<Vec<u8>>) {
        let entry = self.inputs.entry(LinkInput::File(path.into())).or_default();
        entry.buffer = Some(buffer.into());
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

    /// Add a set of link libraries to the linker.
    pub fn add_libraries<S: Into<String>, I: IntoIterator<Item = S>>(&mut self, names: I) {
        names.into_iter().for_each(|name| self.add_library(name));
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
            Box::new(ConfiguredLinker::with_opts(self, library_searcher))
        } else {
            Box::new(ConfiguredLinker::with_opts(self, LibrarySearcher::new()))
        }
    }
}
