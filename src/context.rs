use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use crate::{coff::ImageFileMachine, syncpool::SyncBumpPool};

/// Structure which holds "global-state" used throughout the linker.
///
/// The fields inside this structure are meant to be passed through to various
/// functions for different uses. The majority of the fields in this structure
/// should either be thread-safe or only need to be mutable in limited contexts.
pub struct LinkContext<'a> {
    pub config: LinkConfig,
    pub errored: AtomicBool,
    pub bump_pool: &'a SyncBumpPool,
    pub stats: LinkStats,
}

impl<'a> LinkContext<'a> {
    /// Creates a new [`LinkContext`] with everything set to the defaults.
    pub fn new(config: LinkConfig, bump_pool: &'a SyncBumpPool) -> Self {
        Self {
            config,
            errored: false.into(),
            bump_pool,
            stats: Default::default(),
        }
    }

    /// Checks if an error log record was emitted and exits if one was seen.
    /// This uses an [`Ordering::Relaxed`] load of the atomic flag for checking
    /// errors.
    pub fn check_errored(&self) {
        if self.errored.load(Ordering::Relaxed) {
            std::process::exit(1);
        }
    }
}

impl<'a> log::Log for &LinkContext<'a> {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        log::logger().enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if record.level() == log::Level::Error {
            self.errored.store(true, Ordering::Release);
        }
        log::logger().log(record);
    }

    fn flush(&self) {
        log::logger().flush();
    }
}

/// Global configuration options.
///
/// Most of these fields are set through command line options.
#[derive(Debug)]
pub struct LinkConfig {
    /// Target architecture
    pub architecture: ImageFileMachine,

    /// Demangle symbols
    pub demangle: bool,

    /// Whether section garbage collection is being performed.
    pub do_gc: bool,

    /// Print sections discarded during GC sections
    pub print_gc_sections: bool,

    /// Error limit value
    pub error_limit: usize,

    /// Strip debug sections and symbols
    pub strip_debug: bool,

    /// Library search paths
    pub search_paths: Vec<PathBuf>,
}

impl std::default::Default for LinkConfig {
    fn default() -> Self {
        Self {
            architecture: ImageFileMachine::Unknown,
            demangle: false,
            do_gc: false,
            print_gc_sections: false,
            error_limit: 0,
            strip_debug: false,
            search_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct LinkStats {
    pub input_files: AtomicU32,
    pub input_coffs: AtomicU32,
    pub input_archives: AtomicU32,
    pub input_archive_members: AtomicU32,
    pub parsed_coffs: AtomicU32,
    pub parsed_coff_sections: AtomicUsize,
    pub parsed_coff_symbols: AtomicUsize,
}

impl LinkStats {
    pub fn print_yaml(&self) {
        println!(
            r#"stats:
  input_files: {input_files}
  input_coffs: {input_coffs}
  input_archives: {input_archives}
  input_archive_members: {input_archive_members}
  parsed_coffs: {parsed_coffs}
  parsed_coff_sections: {parsed_coff_sections}
  parsed_coff_symbols: {parsed_coff_symbols}"#,
            input_files = self.input_files.load(Ordering::Relaxed),
            input_coffs = self.input_coffs.load(Ordering::Relaxed),
            input_archives = self.input_archives.load(Ordering::Relaxed),
            input_archive_members = self.input_archive_members.load(Ordering::Relaxed),
            parsed_coffs = self.parsed_coffs.load(Ordering::Relaxed),
            parsed_coff_sections = self.parsed_coff_sections.load(Ordering::Relaxed),
            parsed_coff_symbols = self.parsed_coff_symbols.load(Ordering::Relaxed),
        );
    }
}

#[derive(Debug, Default)]
pub struct ReadStats {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetArchitecture {
    Amd64,
    I386,
}

impl TargetArchitecture {
    pub const fn into_machine(self) -> ImageFileMachine {
        match self {
            Self::Amd64 => ImageFileMachine::Amd64,
            Self::I386 => ImageFileMachine::I386,
        }
    }
}

impl TryFrom<ImageFileMachine> for TargetArchitecture {
    type Error = TryFromMachineError;

    fn try_from(value: ImageFileMachine) -> Result<Self, Self::Error> {
        Ok(match value {
            ImageFileMachine::Amd64 => Self::Amd64,
            ImageFileMachine::I386 => Self::I386,
            o => return Err(TryFromMachineError(o)),
        })
    }
}

#[derive(Debug)]
pub struct TryFromMachineError(ImageFileMachine);

impl std::fmt::Display for TryFromMachineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown or unsupported COFF machine value '{}'", self.0)
    }
}

impl std::error::Error for TryFromMachineError {}
