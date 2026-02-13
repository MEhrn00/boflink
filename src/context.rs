use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::{arena::ArenaPool, cli::CliOptions, outputs::OutputSection, symbols::SymbolMap};

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
    pub section_pool: &'a ArenaPool<OutputSection<'a>>,
    pub stats: LinkStats,
}

impl<'a> LinkContext<'a> {
    pub fn new(
        options: &'a CliOptions,
        string_pool: &'a ArenaPool<u8>,
        section_pool: &'a ArenaPool<OutputSection<'a>>,
    ) -> Self {
        // This should already be set to reflect the active thread count but
        // fall back to 1 if it is not.
        let active_threads = options.threads.map(|num| num.get()).unwrap_or(1);

        Self {
            options,
            string_pool,
            section_pool,
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
    pub read: ReadStats,
    pub parse: ParseStats,
    pub globals: AtomicUsize,
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
  read:
    files: {read_files}
    coffs: {read_coffs}
    archives: {read_archives}
  parse:
    coffs: {parse_coffs}
    input_sections: {parse_input_sections}
    input_symbols: {parse_input_symbols}
    local_symbols: {parse_local_symbols}
    comdats: {parse_comdats}
  globals: {globals}
"#,
            read_files = *self.read.files.get_mut(),
            read_coffs = *self.read.coffs.get_mut(),
            read_archives = *self.read.archives.get_mut(),
            parse_coffs = *self.parse.coffs.get_mut(),
            parse_input_sections = *self.parse.input_sections.get_mut(),
            parse_input_symbols = *self.parse.input_symbols.get_mut(),
            parse_local_symbols = *self.parse.local_symbols.get_mut(),
            parse_comdats = *self.parse.comdats.get_mut(),
            globals = *self.globals.get_mut(),
        )
    }
}

#[derive(Debug, Default)]
pub struct ReadStats {
    pub files: AtomicU32,
    pub coffs: AtomicU32,
    pub archives: AtomicU32,
}

#[derive(Debug, Default)]
pub struct ParseStats {
    pub coffs: AtomicU32,
    pub input_sections: AtomicUsize,
    pub input_symbols: AtomicUsize,
    pub local_symbols: AtomicU32,
    pub comdats: AtomicUsize,
}
