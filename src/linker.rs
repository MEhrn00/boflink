use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use bumpalo::Bump;
use indexmap::{IndexMap, IndexSet};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use object::{
    coff::CoffFile,
    pe::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386},
};
use typed_arena::Arena;

use crate::{archive::LinkArchive, bofapi::ApiSymbols, cli::CliOptions, graph::SpecLinkGraph};

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

#[derive(Default)]
pub struct ErrHandler {
    limit: usize,
    error_count: AtomicUsize,
}

impl log::Log for ErrHandler {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        log::logger().enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        let logger = log::logger();
        if record.level() != log::Level::Error {
            // Fast path
            logger.log(record);
            return;
        }
        if self.error_count.fetch_add(1, Ordering::SeqCst) >= self.limit {
            log::error!(logger: logger, "too many errors emitted. Exiting.");
            std::process::exit(1);
        }
        logger.log(record);
    }

    fn flush(&self) {
        log::logger().flush();
    }
}

/// Main linker state
pub struct LinkContext<'a> {
    error_handler: ErrHandler,

    /// Arena for holding string data
    pub bump: &'a Bump,

    /// Arena for holding opened input files
    pub inputs_arena: &'a Arena<(PathBuf, Vec<u8>)>,

    /// Command line options
    pub options: CliOptions,

    /// The names of opened link libraries
    pub opened_library_names: HashSet<String>,

    /// Parsed COFF inputs
    pub input_coffs: IndexMap<CoffPath<'a>, CoffFile<'a>>,

    /// Parsed lazily loaded archives
    pub lazy_archives: IndexMap<&'a Path, LinkArchive<'a>>,

    /// Spec graph
    pub spec_graph: SpecLinkGraph,

    /// Symbols for the BOF API
    pub api_symbols: ApiSymbols<'a>,

    /// Symbols that were left unresolved
    pub unresolved_symbols: IndexSet<&'a str>,
}

impl<'a> LinkContext<'a> {
    pub fn new(
        bump: &'a Bump,
        inputs_arena: &'a Arena<(PathBuf, Vec<u8>)>,
        options: CliOptions,
    ) -> Self {
        Self {
            bump,
            inputs_arena,
            error_handler: ErrHandler {
                limit: options.error_limit,
                error_count: AtomicUsize::new(0),
            },
            options,
            opened_library_names: HashSet::new(),
            input_coffs: IndexMap::new(),
            lazy_archives: IndexMap::new(),
            spec_graph: SpecLinkGraph::new(),
            api_symbols: ApiSymbols::default(),
            unresolved_symbols: IndexSet::new(),
        }
    }

    pub fn logger(&self) -> &ErrHandler {
        &self.error_handler
    }
}

pub fn check_errored(ctx: &mut LinkContext) {
    if *ctx.error_handler.error_count.get_mut() > 0 {
        std::process::exit(1)
    }
}
