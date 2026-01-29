use std::{
    collections::{HashSet, VecDeque},
    io::{BufWriter, ErrorKind},
    path::{Path, PathBuf},
};

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
    api::{ApiSymbols, ApiSymbolsError},
    drectve,
    graph::{
        LinkGraphAddError, LinkGraphLinkError, SpecLinkGraph, SymbolError,
        node::{OwnedSymbolName, SymbolNode},
    },
    libsearch::{LibraryFind, LibrarySearcher, LibsearchError},
    linkobject::archive::{
        ArchiveMemberError, ArchiveParseError, ExtractSymbolError, LinkArchive,
        LinkArchiveMemberVariant, LinkArchiveParseError, MemberParseErrorKind,
    },
};

pub trait LinkImpl {
    fn link(&mut self) -> Result<Vec<u8>, LinkError>;
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

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("{0}")]
    Setup(LinkerSetupErrors),

    #[error("{0}")]
    Symbol(LinkerSymbolErrors),

    #[error("{0}")]
    Graph(#[from] LinkGraphLinkError),

    #[error("--gc-sections requires a defined --entry symbol or set of GC roots")]
    EmptyGcRoots,

    #[error("no input files")]
    NoInput,

    #[error("could not detect architecture")]
    ArchitectureDetect,
}

#[derive(Debug, thiserror::Error)]
#[error("{}", display_vec(.0))]
pub struct LinkerSetupErrors(pub(super) Vec<LinkerSetupError>);

impl LinkerSetupErrors {
    pub fn errors(&self) -> &[LinkerSetupError] {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LinkerSetupError {
    #[error("{0}")]
    Path(LinkerSetupPathError),

    #[error("{0}")]
    Library(LibsearchError),

    #[error("{0}")]
    Api(ApiSetupError),
}

#[derive(Debug, thiserror::Error)]
pub enum ApiSetupError {
    #[error("{}: could not open custom API: {error}", .path.display())]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },

    #[error("unable to find custom API '{0}'")]
    NotFound(String),

    #[error("{}: {error}", .path.display())]
    Parse {
        path: PathBuf,
        error: LinkArchiveParseError,
    },

    #[error("{}: {error}", .path.display())]
    ApiSymbols {
        path: PathBuf,
        error: ApiSymbolsError,
    },
}

impl From<LibsearchError> for ApiSetupError {
    fn from(value: LibsearchError) -> Self {
        match value {
            LibsearchError::NotFound(name) => Self::NotFound(name),
            LibsearchError::Io { path, error } => Self::Io { path, error },
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error(
    "{}{}: {error}",
    .path.display(),
    .member.as_ref().map(|p| format!("({})", p.display())).unwrap_or_default()
)]
pub struct LinkerSetupPathError {
    pub path: PathBuf,
    pub member: Option<PathBuf>,
    pub error: LinkerPathErrorKind,
}

impl LinkerSetupPathError {
    pub fn new<P: Into<PathBuf>>(
        path: impl Into<PathBuf>,
        member: Option<P>,
        error: impl Into<LinkerPathErrorKind>,
    ) -> LinkerSetupPathError {
        Self {
            path: path.into(),
            member: member.map(Into::into),
            error: error.into(),
        }
    }

    pub fn nomember(
        path: impl Into<PathBuf>,
        error: impl Into<LinkerPathErrorKind>,
    ) -> LinkerSetupPathError {
        Self {
            path: path.into(),
            member: None,
            error: error.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LinkerPathErrorKind {
    #[error("{0}")]
    DrectveLibrary(#[from] DrectveLibsearchError),

    #[error("{0}")]
    LinkArchive(#[from] LinkArchiveParseError),

    #[error("{0}")]
    ArchiveParse(#[from] ArchiveParseError),

    #[error("{0}")]
    ArchiveMember(#[from] MemberParseErrorKind),

    #[error("{0}")]
    GraphAdd(#[from] LinkGraphAddError),

    #[error("{0}")]
    Object(#[from] object::Error),

    #[error("{0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum DrectveLibsearchError {
    #[error("unable to find library {0}")]
    NotFound(String),

    #[error("could not open link library {}: {error}", .path.display())]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
}

impl From<LibsearchError> for DrectveLibsearchError {
    fn from(value: LibsearchError) -> Self {
        match value {
            LibsearchError::Io { path, error } => Self::Io { path, error },
            LibsearchError::NotFound(name) => Self::NotFound(name),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{}", display_vec(.0))]
pub struct LinkerSymbolErrors(pub(super) Vec<LinkerSymbolError>);

impl LinkerSymbolErrors {
    pub fn errors(&self) -> &[LinkerSymbolError] {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{kind}: {}{}", .name.quoted_demangle(), .display_demangled_context(kind))]
pub struct LinkerSymbolError {
    pub name: OwnedSymbolName,
    pub kind: LinkerSymbolErrorKind,
}

impl From<SymbolError<'_, '_>> for LinkerSymbolError {
    fn from(value: SymbolError<'_, '_>) -> Self {
        match value {
            SymbolError::Duplicate(duplicate_error) => {
                let symbol = duplicate_error.symbol();

                Self {
                    name: symbol.name().into_owned(),
                    kind: LinkerSymbolErrorKind::Duplicate(SymbolDefinitionsContext::new(symbol)),
                }
            }
            SymbolError::Undefined(undefined_error) => {
                let symbol = undefined_error.symbol();

                Self {
                    name: symbol.name().into_owned(),
                    kind: LinkerSymbolErrorKind::Undefined(SymbolReferencesContext::new(symbol)),
                }
            }
            SymbolError::MultiplyDefined(multiply_defined_error) => {
                let symbol = multiply_defined_error.symbol();

                Self {
                    name: symbol.name().into_owned(),
                    kind: LinkerSymbolErrorKind::MultiplyDefined(SymbolDefinitionsContext::new(
                        symbol,
                    )),
                }
            }
        }
    }
}

fn display_demangled_context(kind: &LinkerSymbolErrorKind) -> String {
    if !kind.context_is_empty() {
        format!("\n{}", kind.display_context())
    } else {
        Default::default()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LinkerSymbolErrorKind {
    #[error("duplicate symbol")]
    Duplicate(SymbolDefinitionsContext),

    #[error("undefined symbol")]
    Undefined(SymbolReferencesContext),

    #[error("multiply defined symbol")]
    MultiplyDefined(SymbolDefinitionsContext),
}

impl LinkerSymbolErrorKind {
    pub fn display_context(&self) -> &dyn std::fmt::Display {
        match self {
            LinkerSymbolErrorKind::Duplicate(ctx) => ctx as &dyn std::fmt::Display,
            LinkerSymbolErrorKind::Undefined(ctx) => ctx as &dyn std::fmt::Display,
            LinkerSymbolErrorKind::MultiplyDefined(ctx) => ctx as &dyn std::fmt::Display,
        }
    }

    pub fn context_is_empty(&self) -> bool {
        match self {
            LinkerSymbolErrorKind::Duplicate(ctx) => ctx.definitions.is_empty(),
            LinkerSymbolErrorKind::Undefined(ctx) => ctx.references.is_empty(),
            LinkerSymbolErrorKind::MultiplyDefined(ctx) => ctx.definitions.is_empty(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error(
    "{}{}",
    display_vec(.definitions),
    display_remaining_definitions(.remaining)
)]
pub struct SymbolDefinitionsContext {
    pub definitions: Vec<SymbolDefinition>,
    pub remaining: usize,
}

impl SymbolDefinitionsContext {
    pub fn new(symbol: &SymbolNode<'_, '_>) -> SymbolDefinitionsContext {
        let mut definition_iter = symbol.definitions().iter();
        let mut definitions = Vec::with_capacity(5);

        for definition in definition_iter.by_ref().take(5) {
            definitions.push(SymbolDefinition {
                coff_path: definition.target().coff().to_string(),
            });
        }

        let remaining = definition_iter.count();
        Self {
            definitions,
            remaining,
        }
    }
}

fn display_remaining_definitions(remaining: &usize) -> String {
    if *remaining != 0 {
        format!("\ndefined {remaining} more times")
    } else {
        Default::default()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("defined at {coff_path}")]
pub struct SymbolDefinition {
    pub coff_path: String,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "{}{}",
    display_vec(.references),
    display_remaining_references(.remaining),
)]
pub struct SymbolReferencesContext {
    pub references: Vec<SymbolReference>,
    pub remaining: usize,
}

impl SymbolReferencesContext {
    pub fn new(symbol: &SymbolNode<'_, '_>) -> SymbolReferencesContext {
        let mut reference_iter = symbol.symbol_references().peekable();

        let mut references = Vec::with_capacity(5);

        while references.len() < 5 {
            let reference = match reference_iter.next() {
                Some(reference) => reference,
                None => break,
            };

            let reloc = reference.relocation();
            let section = reference.section();
            let coff = section.coff();

            if reference.source_symbol().is_section_symbol() {
                if reference_iter.peek().is_some_and(|next_reference| {
                    next_reference.source_symbol().is_section_symbol()
                }) {
                    references.push(SymbolReference {
                        coff_path: coff.to_string(),
                        reference: format!("{}+{:#x}", section.name(), reloc.weight().address()),
                    });
                }
            } else {
                references.push(SymbolReference {
                    coff_path: coff.to_string(),
                    reference: reference
                        .source_symbol()
                        .name()
                        .quoted_demangle()
                        .to_string(),
                });
            }
        }

        SymbolReferencesContext {
            remaining: symbol.references().len().saturating_sub(references.len()),
            references,
        }
    }
}

fn display_remaining_references(remaining: &usize) -> String {
    if *remaining != 0 {
        format!("\nreferenced {remaining} more times")
    } else {
        Default::default()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("referenced by {coff_path}:({reference})")]
pub struct SymbolReference {
    pub coff_path: String,
    pub reference: String,
}

struct DisplayVec<'a, T: std::fmt::Display>(&'a Vec<T>);

impl<'a, T: std::fmt::Display> std::fmt::Display for DisplayVec<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut value_iter = self.0.iter();

        let first_value = match value_iter.next() {
            Some(v) => v,
            None => return Ok(()),
        };

        first_value.fmt(f)?;

        for val in value_iter {
            write!(f, "\n{val}")?;
        }

        Ok(())
    }
}

fn display_vec<T: std::fmt::Display>(errors: &Vec<T>) -> DisplayVec<'_, T> {
    DisplayVec(errors)
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

    /// Ignored unresolved symbols.
    ignored_unresolved_symbols: HashSet<String>,

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
            ignored_unresolved_symbols: builder.ignored_unresolved_symbols,
        }
    }
}

impl<L: LibraryFind> LinkImpl for ConfiguredLinker<L> {
    fn link(&mut self) -> Result<Vec<u8>, LinkError> {
        // Buffer arena
        let buffer_arena: Arena<(PathBuf, Vec<u8>)> = Arena::with_capacity(self.inputs.len());

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

        let string_arena = Arena::new();
        let api_symbols = match self.custom_api.take() {
            Some(custom_api) => match input_processor.open_custom_api(custom_api) {
                Ok(api_symbols) => api_symbols,
                Err(e) => {
                    setup_errors.push(LinkerSetupError::Api(e));
                    return Err(LinkError::Setup(LinkerSetupErrors(setup_errors)));
                }
            },
            None => ApiSymbols::beacon(&string_arena, target_arch),
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
            for library_name in drectve::parse_defaultlibs_normalized(coff)
                .into_iter()
                .flatten()
            {
                if !input_processor.opened_library_names.contains(library_name) {
                    let (library_path, library_buffer) = match self
                        .library_searcher
                        .find_library(library_name)
                    {
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
                        .contains_key(library_path.as_path())
                    {
                        let (library_path, library_buffer) =
                            input_processor.arena.alloc((library_path, library_buffer));
                        let archive = match LinkArchive::parse(library_buffer.as_slice()) {
                            Ok(parsed) => parsed,
                            Err(e) => {
                                setup_errors.push(LinkerSetupError::Path(
                                    LinkerSetupPathError::nomember(library_path.as_path(), e),
                                ));
                                continue;
                            }
                        };

                        input_processor
                            .link_libraries
                            .insert(library_path.as_path(), archive);
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

                                let (library_path, library_buffer) = buffer_arena.alloc(found);

                                match LinkArchive::parse(library_buffer.as_slice()) {
                                    Ok(parsed) => {
                                        input_processor
                                            .link_libraries
                                            .insert(library_path.as_path(), parsed);
                                    }
                                    Err(e) => {
                                        setup_errors.push(LinkerSetupError::Path(
                                            LinkerSetupPathError::new(
                                                library_path.as_path(),
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
            graph.finish_unresolved(&self.ignored_unresolved_symbols)
        } else {
            graph.finish(&self.ignored_unresolved_symbols)
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
    ) -> Result<(), LinkerSetupError> {
        match input {
            LinkInput::File(file_path) => {
                let (file_path, buffer) = if let Some(existing_buffer) = item.buffer.take() {
                    self.arena.alloc((file_path, existing_buffer))
                } else {
                    let buffer = std::fs::read(&file_path).map_err(|e| {
                        LinkerSetupError::Path(LinkerSetupPathError::nomember(&file_path, e))
                    })?;
                    self.arena.alloc((file_path, buffer))
                };

                if object_is_archive(buffer.as_slice()) {
                    let library = LinkArchive::parse(buffer.as_slice()).map_err(|e| {
                        LinkerSetupError::Path(LinkerSetupPathError::nomember(
                            file_path.as_path(),
                            e,
                        ))
                    })?;

                    if item.whole {
                        self.add_archive_members(file_path.as_path(), library)
                            .map_err(LinkerSetupError::Path)?;
                    } else if !self.link_libraries.contains_key(file_path.as_path()) {
                        self.link_libraries.insert(file_path.as_path(), library);
                    }
                } else {
                    let coff: CoffFile = CoffFile::parse(buffer.as_slice()).map_err(|e| {
                        LinkerSetupError::Path(LinkerSetupPathError::nomember(
                            file_path.as_path(),
                            e,
                        ))
                    })?;

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
                        .map_err(LinkerSetupError::Library)?;

                    self.opened_library_names.insert(library_name);

                    if item.whole {
                        let (library_path, library_buffer) =
                            self.arena.alloc((library_path, library_buffer));
                        let archive =
                            LinkArchive::parse(library_buffer.as_slice()).map_err(|e| {
                                LinkerSetupError::Path(LinkerSetupPathError::nomember(
                                    library_path.as_path(),
                                    e,
                                ))
                            })?;

                        self.add_archive_members(library_path.as_path(), archive)
                            .map_err(LinkerSetupError::Path)?;
                    } else if !self.link_libraries.contains_key(library_path.as_path()) {
                        let (library_path, library_buffer) =
                            self.arena.alloc((library_path, library_buffer));
                        let archive =
                            LinkArchive::parse(library_buffer.as_slice()).map_err(|e| {
                                LinkerSetupError::Path(LinkerSetupPathError::nomember(
                                    library_path.as_path(),
                                    e,
                                ))
                            })?;

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
            Ok(buffer) => (PathBuf::from(library), buffer),
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

        let (api_path, api_buffer) = self.arena.alloc(custom_api);

        let api_archive =
            LinkArchive::parse(api_buffer.as_slice()).map_err(|e| ApiSetupError::Parse {
                path: api_path.clone(),
                error: e,
            })?;

        ApiSymbols::new(api_path.as_path(), api_archive).map_err(|e| ApiSetupError::ApiSymbols {
            path: api_path.clone(),
            error: e,
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
