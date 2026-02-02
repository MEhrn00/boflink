use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::{cli::CliOptions, coff::ImageFileMachine, symbols::SymbolMap, syncpool::SyncBumpPool};

/// Structure which holds "global-state" used throughout the linker.
///
/// The fields inside this structure are meant to be passed through to various
/// functions for different uses. The majority of the fields in this structure
/// should either be thread-safe or only need to be mutable in limited contexts.
pub struct LinkContext<'a> {
    pub options: &'a CliOptions,
    pub errored: AtomicBool,
    pub bump_pool: &'a SyncBumpPool,
    pub symbol_map: SymbolMap<'a>,
    pub stats: LinkStats,
}

impl<'a> LinkContext<'a> {
    /// Creates a new [`LinkContext`] with everything set to the defaults.
    pub fn new(options: &'a CliOptions, bump_pool: &'a SyncBumpPool) -> Self {
        Self {
            options,
            errored: false.into(),
            bump_pool,
            symbol_map: SymbolMap::with_slot_count(
                options.threads.map(|num| num.get()).unwrap_or(1),
            ),
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

#[derive(Debug, Default)]
pub struct LinkStats {
    pub input_files: AtomicU32,
    pub input_coffs: AtomicU32,
    pub input_archives: AtomicU32,
    pub input_archive_members: AtomicU32,
    pub parsed_coffs: AtomicU32,
    pub parsed_coff_sections: AtomicUsize,
    pub parsed_coff_symbols: AtomicUsize,
    pub global_symbols: AtomicUsize,
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
  parsed_coff_symbols: {parsed_coff_symbols}
  global_symbols: {global_symbols}"#,
            input_files = self.input_files.load(Ordering::Relaxed),
            input_coffs = self.input_coffs.load(Ordering::Relaxed),
            input_archives = self.input_archives.load(Ordering::Relaxed),
            input_archive_members = self.input_archive_members.load(Ordering::Relaxed),
            parsed_coffs = self.parsed_coffs.load(Ordering::Relaxed),
            parsed_coff_sections = self.parsed_coff_sections.load(Ordering::Relaxed),
            parsed_coff_symbols = self.parsed_coff_symbols.load(Ordering::Relaxed),
            global_symbols = self.global_symbols.load(Ordering::Relaxed),
        );
    }
}

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
