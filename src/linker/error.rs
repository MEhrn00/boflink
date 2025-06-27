use std::{collections::BTreeMap, path::PathBuf};

use crate::{
    api::ApiSymbolsError,
    graph::{LinkGraphAddError, LinkGraphLinkError, SymbolError, node::SymbolNode},
    libsearch::LibsearchError,
    linkobject::archive::{ArchiveParseError, LinkArchiveParseError, MemberParseErrorKind},
};

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
#[error("{kind}: {demangled}{}", .display_demangled_context(kind))]
pub struct LinkerSymbolError {
    pub name: String,
    pub demangled: String,
    pub kind: LinkerSymbolErrorKind,
}

impl From<SymbolError<'_, '_>> for LinkerSymbolError {
    fn from(value: SymbolError<'_, '_>) -> Self {
        match value {
            SymbolError::Duplicate(duplicate_error) => {
                let symbol = duplicate_error.symbol();

                Self {
                    name: symbol.name().to_string(),
                    demangled: symbol.name().demangle().to_string(),
                    kind: LinkerSymbolErrorKind::Duplicate(SymbolDefinitionsContext::new(symbol)),
                }
            }
            SymbolError::Undefined(undefined_error) => {
                let symbol = undefined_error.symbol();

                Self {
                    name: symbol.name().to_string(),
                    demangled: symbol.name().demangle().to_string(),
                    kind: LinkerSymbolErrorKind::Undefined(SymbolReferencesContext::new(symbol)),
                }
            }
            SymbolError::MultiplyDefined(multiply_defined_error) => {
                let symbol = multiply_defined_error.symbol();

                Self {
                    name: symbol.name().to_string(),
                    demangled: symbol.name().demangle().to_string(),
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
        format!("\n>>> defined {remaining} more times")
    } else {
        Default::default()
    }
}

#[derive(Debug, thiserror::Error)]
#[error(">>> defined at {coff_path}")]
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
        let mut reference_iter = symbol.references().iter();
        let mut references = Vec::with_capacity(5);

        for reference in reference_iter.by_ref().take(5) {
            let section = reference.source();
            let coff = section.coff();

            let symbol_defs =
                BTreeMap::from_iter(section.definitions().iter().filter_map(|definition| {
                    let ref_symbol = definition.source();
                    if ref_symbol.is_section_symbol() || ref_symbol.is_label() {
                        None
                    } else {
                        Some((definition.weight().address(), ref_symbol.name()))
                    }
                }));

            if let Some(reference_symbol) = symbol_defs
                .range(0..=reference.weight().address())
                .next_back()
            {
                references.push(SymbolReference {
                    coff_path: coff.to_string(),
                    reference: reference_symbol.1.demangle().to_string(),
                });
            } else {
                references.push(SymbolReference {
                    coff_path: coff.to_string(),
                    reference: format!("{}+{:#x}", section.name(), reference.weight().address()),
                });
            }
        }

        let remaining = reference_iter.count();

        SymbolReferencesContext {
            references,
            remaining,
        }
    }
}

fn display_remaining_references(remaining: &usize) -> String {
    if *remaining != 0 {
        format!("\n>>> referenced {remaining} more times")
    } else {
        Default::default()
    }
}

#[derive(Debug, thiserror::Error)]
#[error(">>> referenced by {coff_path}:({reference})")]
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
