use std::path::PathBuf;

use boflink::linker::LinkerTargetArch;
use clap::{Parser, ValueEnum};
use clap_verbosity_flag::{InfoLevel, Verbosity};

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct CliArgs {
    /// Set the output file name
    #[arg(
        short,
        long,
        default_value = "a.bof",
        value_name = "file",
        value_hint = clap::ValueHint::FilePath
    )]
    pub output: PathBuf,

    /// Files to link
    #[arg(
        value_name = "files",
        value_hint = clap::ValueHint::FilePath
    )]
    pub files: Vec<PathBuf>,

    /// Add the specified library to search for symbols
    #[arg(id = "library", short, long, value_name = "libname")]
    pub libraries: Vec<String>,

    /// Add the directory to the library search path
    #[arg(
        id = "library-path",
        short = 'L',
        long,
        value_name = "directory",
        value_hint = clap::ValueHint::DirPath
    )]
    pub library_paths: Vec<PathBuf>,

    /// Set the sysroot path
    #[arg(
        long,
        value_name = "directory",
        value_hint = clap::ValueHint::DirPath
    )]
    pub sysroot: Option<PathBuf>,

    /// Set the target machine emulation
    #[arg(short, long, value_name = "emulation")]
    pub machine: Option<TargetEmulation>,

    /// Name of the entrypoint
    #[arg(short, long, value_name = "entry", default_value = "go")]
    pub entry: String,

    /// Dump the link graph to the specified file
    #[arg(long, value_name = "file", value_hint = clap::ValueHint::FilePath)]
    pub dump_link_graph: Option<PathBuf>,

    /// Custom API to use instead of the Beacon API
    #[arg(long, value_name = "library", visible_alias = "api")]
    pub custom_api: Option<String>,

    /// Initialize the .bss section and merge it with the .data section
    #[arg(long)]
    pub merge_bss: bool,

    /// Enable garbage collection of unused sections
    #[arg(long)]
    pub gc_sections: bool,

    /// Ensure that the specified symbols are kept during '--gc-sections'
    ///
    /// Can be specified multiple times.
    /// Accepts a comma separated list of symbols
    #[arg(long, value_name = "symbol", value_delimiter = ',')]
    pub keep_symbol: Vec<String>,

    /// Print sections discarded during '--gc-sections'
    #[arg(long)]
    pub print_gc_sections: bool,

    /// Print colored output
    #[arg(long, value_name = "color", default_value_t = ColorOption::Auto)]
    pub color: ColorOption,

    #[command(flatten)]
    pub verbose: Verbosity<InfoLevel>,

    /// Print timing information
    #[arg(long)]
    pub print_timing: bool,

    #[command(flatten)]
    pub ignored: IgnoredCliArgs,
}

#[derive(Parser, Debug)]
pub struct IgnoredCliArgs {
    /// Ignored for compatibility with GCC
    #[arg(long, value_name = "file", hide = true)]
    pub out_implib: Option<String>,

    /// Ignored for compatibility with GCC
    #[arg(long, value_name = "number", default_value = "0", hide = true)]
    pub major_image_version: u8,

    /// Ignored for compatibility with GCC
    #[arg(long, value_name = "number", default_value = "0", hide = true)]
    pub minor_image_version: u8,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetEmulation {
    #[value(name = "i386pep")]
    I386Pep,

    #[value(name = "i386pe")]
    I386Pe,
}

impl From<TargetEmulation> for LinkerTargetArch {
    fn from(value: TargetEmulation) -> Self {
        match value {
            TargetEmulation::I386Pep => LinkerTargetArch::Amd64,
            TargetEmulation::I386Pe => LinkerTargetArch::I386,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpGraphState {
    #[value(name = "linked")]
    Linked,

    #[value(name = "merged")]
    Merged,
}

impl std::fmt::Display for DumpGraphState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(v) = self.to_possible_value() {
            write!(f, "{}", v.get_name())?
        }

        Ok(())
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorOption {
    #[value(name = "never")]
    Never,

    #[value(name = "auto")]
    Auto,

    #[value(name = "always")]
    Always,

    #[value(name = "ansi")]
    AlwaysAnsi,
}

impl std::fmt::Display for ColorOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(v) = self.to_possible_value() {
            write!(f, "{}", v.get_name())?;
        }

        Ok(())
    }
}

impl From<ColorOption> for termcolor::ColorChoice {
    fn from(val: ColorOption) -> Self {
        match val {
            ColorOption::Never => termcolor::ColorChoice::Never,
            ColorOption::Auto => termcolor::ColorChoice::Auto,
            ColorOption::Always => termcolor::ColorChoice::Always,
            ColorOption::AlwaysAnsi => termcolor::ColorChoice::AlwaysAnsi,
        }
    }
}

/// Parses the command line arguments into the [`CliArgs`].
pub fn parse_arguments() -> anyhow::Result<CliArgs> {
    let args = CliArgs::parse_from(argfile::expand_args_from(
        std::env::args_os().filter(|arg| arg != "-Bdynamic"),
        argfile::parse_fromfile,
        argfile::PREFIX,
    )?);

    crate::logging::setup_logger(&args)?;

    Ok(args)
}
