use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::{cli::CliOptions, symbols::SymbolMap, syncpool::SyncBumpPool};

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
    pub global_symbols: AtomicUsize,
    pub arena_memory: usize,
}

impl LinkStats {
    pub fn print_yaml(&self) {
        println!(
            r#"stats:
  input_files: {input_files}
  input_coffs: {input_coffs}
  input_archives: {input_archives}
  input_archive_members: {input_archive_members}
  global_symbols: {global_symbols}
  arena_memory: {arena_memory} bytes"#,
            input_files = self.input_files.load(Ordering::Relaxed),
            input_coffs = self.input_coffs.load(Ordering::Relaxed),
            input_archives = self.input_archives.load(Ordering::Relaxed),
            input_archive_members = self.input_archive_members.load(Ordering::Relaxed),
            global_symbols = self.global_symbols.load(Ordering::Relaxed),
            arena_memory = self.arena_memory,
        );
    }
}
