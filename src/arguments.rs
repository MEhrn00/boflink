use std::{collections::BTreeMap, ffi::OsString, path::PathBuf};

use boflink::linker::LinkerTargetArch;
use clap::{ArgAction, ArgMatches, CommandFactory, FromArgMatches, Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    about,
    version = format!("version {} ({})", clap::crate_version!(), env!("GIT_SHORT_HASH")),
)]
pub struct CliArgs {
    #[command(flatten)]
    pub inputs: CliInputArgs,

    #[command(flatten)]
    pub options: CliOptionArgs,

    #[command(flatten)]
    pub long_ignored: IgnoredLongCliArgs,

    #[command(flatten)]
    pub ignored: IgnoredCliArgs,
}

#[derive(Parser, Debug)]
pub struct CliOptionArgs {
    /// Set the output file name
    #[arg(
        short,
        long,
        default_value = "a.bof",
        value_name = "file",
        value_hint = clap::ValueHint::FilePath
    )]
    pub output: PathBuf,

    /// Add the directory to the library search path
    #[arg(
        short = 'L',
        long = "library-path",
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

    /// Do not merge grouped sections
    #[arg(long, long = "no-merge-groups", action = ArgAction::SetFalse)]
    pub merge_groups: bool,

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

    /// Report unresolved symbols as warnings
    #[arg(long)]
    pub warn_unresolved_symbols: bool,

    /// Unresolved <symbol> will not cause an error or warning
    #[arg(long, value_name = "symbol", value_delimiter = ',')]
    pub ignore_unresolved_symbol: Vec<String>,

    /// Query x86_64-w64-mingw32-gcc for its list of library search paths
    #[arg(long, conflicts_with_all = ["mingw32", "ucrt64", "ucrt32"])]
    pub mingw64: bool,

    /// Query i686-w64-mingw32-gcc for its list of library search paths
    #[arg(long, conflicts_with_all = ["ucrt64", "ucrt32"])]
    pub mingw32: bool,

    /// Query x86_64-w64-mingw32ucrt-gcc for its list of library search paths
    #[arg(long, conflicts_with = "ucrt32")]
    pub ucrt64: bool,

    /// Query i686-w64-mingw32ucrt-gcc for its list of library search paths
    #[arg(long)]
    pub ucrt32: bool,

    /// Print colored output
    #[arg(long, value_name = "color", default_value_t = ColorOption::Auto)]
    pub color: ColorOption,

    /// Increasing logging verbosity
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Print timing information
    #[arg(long)]
    pub print_timing: bool,
}

#[derive(Parser, Debug)]
#[command(args_override_self = true)]
pub struct CliInputArgs {
    /// Files to link
    #[arg(
        value_name = "files",
        value_hint = clap::ValueHint::FilePath
    )]
    pub files: Vec<PathBuf>,

    /// Add the specified library to search for symbols
    #[arg(short, long = "libraries", value_name = "libname")]
    pub libraries: Vec<String>,

    /// Include all objects from following archives
    #[arg(
        long,
        value_parser = clap::value_parser!(bool),
        action = ArgAction::Append,
        num_args = 0,
        default_missing_value = "false",
        default_value = "false",
    )]
    pub whole_archive: bool,

    /// Turn off --whole-archive
    #[arg(
        long,
        value_parser = clap::value_parser!(bool),
        action = ArgAction::Append,
        num_args = 0,
        default_missing_value = "false",
        default_value = "false",
    )]
    pub no_whole_archive: bool,
}

impl CliInputArgs {
    fn from_matches(matches: &ArgMatches) -> Vec<ParsedCliInput> {
        let mut values = BTreeMap::new();
        for id in matches.ids() {
            if matches.try_get_many::<clap::Id>(id.as_str()).is_ok() {
                continue;
            }

            ParsedCliInput::extract(matches, id, &mut values);
        }

        values.into_values().collect::<Vec<_>>()
    }
}

#[derive(Parser, Debug)]
pub struct IgnoredCliArgs {
    /// Ignored for compatibility with GCC
    #[arg(long, value_name = "file")]
    pub out_implib: Option<String>,

    /// Ignored for compatibility with GCC
    #[arg(
        long,
        value_name = "number",
        default_value = "0",
        hide_default_value = true
    )]
    pub major_image_version: u8,

    /// Ignored for compatibility with GCC
    #[arg(
        long,
        value_name = "number",
        default_value = "0",
        hide_default_value = true
    )]
    pub minor_image_version: u8,
}

#[derive(Parser, Debug)]
pub struct IgnoredLongCliArgs {
    /// Ignored for compatibility with GCC
    #[arg(long = "Bdynamic", aliases = ["dy", "call_shared"])]
    pub dynamic: bool,
}

#[derive(Parser, Debug)]
#[command()]
pub struct ParsedCliArgs {
    #[arg(skip)]
    pub inputs: Vec<ParsedCliInput>,

    #[command(flatten)]
    pub options: CliOptionArgs,
}

#[derive(Debug, Clone)]
pub enum ParsedCliInput {
    WholeArchiveStart,
    File(PathBuf),
    Library(String),
    WholeArchiveEnd,
}

impl ParsedCliInput {
    fn extract(matches: &ArgMatches, id: &clap::Id, output: &mut BTreeMap<usize, Self>) {
        match id.as_str() {
            "files" => {
                if let Some(values) = matches.get_many::<PathBuf>(id.as_str()) {
                    for (value, index) in values.zip(
                        matches
                            .indices_of(id.as_str())
                            .expect("id came from matches"),
                    ) {
                        output.insert(index, ParsedCliInput::File(value.clone()));
                    }
                }
            }
            "libraries" => {
                if let Some(values) = matches.get_many::<String>(id.as_str()) {
                    for (value, index) in values.zip(
                        matches
                            .indices_of(id.as_str())
                            .expect("id came from matches"),
                    ) {
                        output.insert(index, ParsedCliInput::Library(value.clone()));
                    }
                }
            }
            "whole_archive" => {
                if let Some(indicies) = matches.indices_of(id.as_str()) {
                    for idx in indicies {
                        output.insert(idx, ParsedCliInput::WholeArchiveStart);
                    }
                }
            }
            "no_whole_archive" => {
                if let Some(indicies) = matches.indices_of(id.as_str()) {
                    for idx in indicies {
                        output.insert(idx, ParsedCliInput::WholeArchiveEnd);
                    }
                }
            }
            _ => (),
        }
    }
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
pub fn parse_arguments() -> anyhow::Result<ParsedCliArgs> {
    let mut legacy_flags = Vec::new();

    let legacy_command = IgnoredLongCliArgs::command();
    for arg in legacy_command.get_arguments() {
        if let Some(long_arg) = arg.get_long() {
            legacy_flags.push(long_arg);
        }

        if let Some(long_aliases) = arg.get_all_aliases() {
            legacy_flags.extend(long_aliases);
        }
    }

    let commandline = argfile::expand_args_from(
        std::env::args_os(),
        argfile::parse_fromfile,
        argfile::PREFIX,
    )?;

    if commandline.iter().any(|v| {
        v.to_str()
            .is_some_and(|v| v.starts_with("-v") || v == "--verbose")
    }) {
        if let Some(version) = CliArgs::command().get_version() {
            println!("boflink {version}");
        }

        let commandline_str = commandline
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>();
        println!("boflink command line: {}", commandline_str.join(" "));
    }

    let matches = CliArgs::command().get_matches_from(commandline.into_iter().map(|arg| {
        let arg_str = match arg.to_str() {
            Some(arg_str) => arg_str,
            None => return arg,
        };

        if arg_str.chars().next().is_some_and(|c| c == '-')
            && arg_str.chars().nth(1).is_some_and(|c| c != '-')
        {
            if let Some(unprefixed) = arg_str.strip_prefix('-') {
                if legacy_flags.contains(&unprefixed) {
                    let mut remapped = OsString::from("-");
                    remapped.push(&arg);
                    return remapped;
                }
            }
        }

        arg
    }));

    let options = CliOptionArgs::from_arg_matches(&matches)?;
    crate::logging::setup_logger(&options)?;

    Ok(ParsedCliArgs {
        inputs: CliInputArgs::from_matches(&matches),
        options: CliOptionArgs::from_arg_matches(&matches)?,
    })
}
