use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::{arena::ArenaPool, cli::CliOptions, symbols::SymbolMap};

/// Context structure which holds miscellaneous the program context used
/// throughout the entire program.
///
/// This is designed as a replacement for using static global variables in areas
/// where it would be useful.
/// Global variables are generally a bad idea unless absolutely necessary as a
/// last resort. This structure helps solve a lot of those issues while also
/// "simulating" having them.
pub struct LinkContext<'a> {
    /// The raw command line options passed to the program
    pub options: &'a CliOptions,
    pub symbol_map: SymbolMap<'a>,

    /// Flag indicating if the program has encountered an error.
    ///
    /// This structure implements the [`log::Log`] trait. This flag will get
    /// set if any error records have passed through this logger.
    errored: AtomicBool,

    pub string_pool: &'a ArenaPool<u8>,
    pub stats: LinkStats,
}

impl<'a> LinkContext<'a> {
    pub fn new(options: &'a CliOptions, string_pool: &'a ArenaPool<u8>) -> Self {
        // This should already be set to reflect the active thread count but
        // fall back to 1 if it is not.
        let active_threads = options.threads.map(|num| num.get()).unwrap_or(1);

        Self {
            options,
            string_pool,
            errored: AtomicBool::new(false),
            symbol_map: SymbolMap::with_slot_count(active_threads),
            stats: Default::default(),
        }
    }

    /// Function which checks if an error message was logged using this logger
    /// and exits the program if it has.
    ///
    /// This can be used for doing a simple check after a multi-threaded linker
    /// pass to see if any threads encountered an error. It is generally helpful
    /// to log all errors that occur during a pass for the user instead of
    /// short-circuiting and terminating on the first one.
    ///
    /// This method takes `self` as `&mut self` to ensure that only a single
    /// thread is performing this check.
    pub fn exclusive_check_errored(&mut self) {
        if *self.errored.get_mut() {
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
}

impl LinkStats {
    pub fn print_yaml(&mut self) {
        self.write_yaml(std::io::stdout().lock()).unwrap();
    }

    /// Writes the current link states to the specified writer.
    ///
    /// This method takes `self` as `&mut self` to ensure that only a single
    /// thread is accessing the link stats during printing.
    pub fn write_yaml(&mut self, mut w: impl std::io::Write) -> std::io::Result<()> {
        write!(
            w,
            r#"stats:
  input_files: {input_files}
  input_coffs: {input_coffs}
  input_archives: {input_archives}
  input_archive_members: {input_archive_members}
  global_symbols: {global_symbols}
"#,
            input_files = self.input_files.load(Ordering::Relaxed),
            input_coffs = self.input_coffs.load(Ordering::Relaxed),
            input_archives = self.input_archives.load(Ordering::Relaxed),
            input_archive_members = self.input_archive_members.load(Ordering::Relaxed),
            global_symbols = self.global_symbols.load(Ordering::Relaxed),
        )
    }
}
