use std::sync::atomic::{AtomicU32, AtomicUsize};

use boflink_arena::{BumpPool, TypedArenaPool};
use bstr::BStr;
use memmap2::Mmap;

use crate::{
    cli::CliOptions,
    coff::ImageFileMachine,
    logging::Logger,
    object::ObjectFile,
    symbols::{ManglingScheme, SymbolDemangler},
};

/// Context structure which holds miscellaneous the program context used
/// throughout the entire program.
///
/// This is designed as a replacement for using static global variables in areas
/// where it would be useful.
/// Global variables are generally a bad idea unless absolutely necessary as a
/// last resort. This structure helps solve a lot of those issues while also
/// "simulating" having them.
pub struct LinkContext<'a> {
    pub logger: Logger,
    pub options: &'a CliOptions,
    pub bump_pool: &'a BumpPool,
    pub mapping_pool: &'a TypedArenaPool<Mmap>,
    pub obj_pool: &'a TypedArenaPool<ObjectFile<'a>>,
    pub stats: LinkStats,
}

impl<'a> LinkContext<'a> {
    #[inline]
    pub fn new(
        logger: Logger,
        options: &'a CliOptions,
        bump_pool: &'a BumpPool,
        mapping_pool: &'a TypedArenaPool<Mmap>,
        obj_pool: &'a TypedArenaPool<ObjectFile<'a>>,
    ) -> Self {
        Self {
            logger,
            options,
            bump_pool,
            mapping_pool,
            obj_pool,
            stats: Default::default(),
        }
    }

    #[inline]
    pub fn exit_on_error(&self) {
        if self.logger.contains_error() {
            std::process::exit(1);
        }
    }

    #[inline]
    pub fn demangle<'s>(&self, name: &'s BStr, machine: ImageFileMachine) -> ContextDemangler<'s> {
        if self.options.demangle {
            ContextDemangler::Demangle(SymbolDemangler::new(name, ManglingScheme::machine(machine)))
        } else {
            ContextDemangler::Plain(name)
        }
    }
}

impl<'a> log::Log for &LinkContext<'a> {
    #[inline]
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.logger.enabled(metadata)
    }

    #[inline]
    fn log(&self, record: &log::Record) {
        self.logger.log(record);
    }

    #[inline]
    fn flush(&self) {
        self.logger.flush();
    }
}

impl<'a> log::Log for &mut LinkContext<'a> {
    #[inline]
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.logger.enabled(metadata)
    }

    #[inline]
    fn log(&self, record: &log::Record) {
        self.logger.log(record);
    }

    #[inline]
    fn flush(&self) {
        self.logger.flush();
    }
}

/// Symbol demangler that conditionally demangles a symbol
#[derive(Debug)]
pub enum ContextDemangler<'a> {
    Demangle(SymbolDemangler<'a>),
    Plain(&'a BStr),
}

impl<'a> std::fmt::Display for ContextDemangler<'a> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Demangle(demangler) => demangler.fmt(f),
            Self::Plain(name) => name.fmt(f),
        }
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
    pub sections: AtomicUsize,
    pub symbols: AtomicUsize,
    pub input_sections: AtomicUsize,
    pub input_symbols: AtomicUsize,
}

#[derive(Debug, Default)]
pub struct LinkStats {
    pub read: ReadStats,
    pub parse: ParseStats,
    pub globals: AtomicUsize,
}

impl LinkStats {
    #[inline]
    pub fn print_yaml(&mut self) {
        self.write_yaml(std::io::stdout().lock()).unwrap();
    }

    /// Writes the current link states to the specified writer.
    ///
    /// This method takes `self` as `&mut self` to ensure that only a single
    /// thread is accessing the link stats during printing.
    pub fn write_yaml(&mut self, mut w: impl std::io::Write) -> std::io::Result<()> {
        let read_files = *self.read.files.get_mut();
        let read_coffs = *self.read.coffs.get_mut();
        let read_archives = *self.read.archives.get_mut();
        let parse_coffs = *self.parse.coffs.get_mut();
        let parse_sections = *self.parse.sections.get_mut();
        let parse_symbols = *self.parse.symbols.get_mut();
        let parse_input_sections = *self.parse.input_sections.get_mut();
        let parse_input_symbols = *self.parse.input_symbols.get_mut();
        let globals = *self.globals.get_mut();

        write!(
            w,
            r#"stats:
  read:
    files: {read_files}
    coffs: {read_coffs}
    archives: {read_archives}
  parse:
    coffs: {parse_coffs}
    sections: {parse_sections}
    symbols: {parse_symbols}
    input_sections: {parse_input_sections}
    input_symbols: {parse_input_symbols}
  globals: {globals}
"#
        )
    }
}
