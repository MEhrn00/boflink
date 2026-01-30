use std::{
    collections::{HashSet, VecDeque},
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, bail};
use object::pe::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386};
use os_str_bytes::OsStrBytesExt;

use crate::{fsutils, linker::LinkerTargetArch, logging::ColorOption};

const CARGO_PKG_NAME: &str = env!("CARGO_PKG_NAME");
const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const CARGO_PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const CARGO_PKG_REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
const GIT_SHORT_HASH: Option<&str> = option_env!("GIT_SHORT_HASH");

fn fmt_help(out: impl FnOnce(std::fmt::Arguments), print_ignored: bool) {
    const HELP_USAGE: &str = "[options] files...";
    const HELP_ARGUMENTS: &str = r#"
  files...                   Files to link
"#;

    const HELP_OPTIONS: &str = r#"
  --Bdynamic                 Link against shared libraries (default) [aliases: --dy, --call_shared]
  --Bstatic                  Do not link against shared libraries [aliases: --static, --dn, --non_shared]
  --color-diagnostics[=<color>]
                             Use colors in diagnostic messages [default: auto] [possible values: auto, always, never]
  --color[=<color>]          Deprecated alias for '--color-diagnostics'
  --custom-api=<libname>     Custom API to use for the Beacon API [aliases: --api]
  --define-common            Define common symbols (default) [aliases: -d, --dc, --dp]
    --no-define-common
  --demangle                 Demangle symbols in log messages (default)
    --no-demangle
  --dump-link-graph=<file>   Write the link graph to <file>
  -e <symbol>, --entry=<symbol>
                             Name of the entrypoint symbol [default: go]
  --error-limit=<number>     Number of errors to print before exiting [default: 20]
  --force-group-allocation   Combine grouped sections (default)
    --no-force-group-allocation
  --gc-sections              Garbage collect unused sections
    --no-gc-sections
  --ignore-unresolved-symbol=<symbol>
                             Unresolved <symbol> will not cause an error or warning
  --keep-symbol=<symbol>     Alias for --require-defined
  -L <dir>, --library-path=<dir>
                             Add <dir> to the list of library search paths
  -l <libname>, --library=<libname>
                             Search for the library <libname>
  -m <emulation>             Set the target emulation [possible values: i386pep, i386pe]
  --merge-bss                Initialize the .bss section and merge it with the .data section
    --no-merge-bss
  --merge-groups             Alias for --force-group-allocation
    --no-merge-groups
  --mingw=<executable>       Include MinGW GCC link libraries and search paths from <executable>
  --mingw64                  Alias for --mingw=x86_64-w64-mingw32-gcc
  --mingw32                  Alias for --mingw=i686-w64-mingw32-gcc
  --ucrt64                   Alias for --mingw=x86_64-w64-mingw32ucrt-gcc
  --ucrt32                   Alias for --mingw=i686-w64-mingw32ucrt-gcc
  -o <file>, --output=<file>
                             Path to write the output file [default: a.bof]
  --pop-state                Restore the previous state of positional significant arguments
  --print-gc-sections        Print sections discarded during '--gc-sections'
  --print-timing             Print timing information
  --push-state               Save the current state of positional significant arguments
  --require-defined=<symbol>
                             Ensure <symbol> is defined in the final output
  --sysroot=<dir>            Set the sysroot path
  -u <symbol>, --undefined=<symbol>
                             Start with an undefined reference to <symbol>
  --warn-unresolved-symbols  Report unresolved symbols as warnings
    --no-warn-unresolved-symbols
  --whole-archive            Include all objects from following archives
    --no-whole-archive
  -v, --verbose...           Increase logging verbosity
  -h, --help[=ignored]       Print help and exit
  -V, --version              Print version and exit
"#;

    const HELP_IGNORED_OPTIONS: &str = r#"
  --dynamicbase              Ignored for Cargo compatibility
    --disable-dynamicbase
  --enable-auto-image-base   Ignored for Cargo compatibility
    --disable-auto-image-base
  -flto                      Ignored for GCC LTO option compatibility
    -fno-lto
  --high-entropy-va          Ignored for Cargo compatibility
  --major-image-version=<number>
                             Ignored for CMake compatibility
  --minor-image-version=<number>
                             Ignored for CMake compatibility
  --nxcompat                 Ignored for Cargo compatibility
  --out-implib=<file>        Ignored for CMake compatibility
  -plugin <plugin>           Ignored for GCC plugin compatibility
  -plugin-opt=<arg>          Ignored for GCC plugin compatibility
"#;

    let argv0 = std::env::args_os().next();

    let prog = argv0
        .as_ref()
        .map(|arg| arg.to_string_lossy())
        .unwrap_or_else(|| CARGO_PKG_NAME.into());

    let help_pre = format_args!(
        "{CARGO_PKG_DESCRIPTION}\n\
        Usage: {prog} {HELP_USAGE}\n\n\
        Arguments:\n\
        {arguments}\n\n\
        Options:\n\
        {options}",
        arguments = HELP_ARGUMENTS.trim_matches('\n'),
        options = HELP_OPTIONS.trim_matches('\n'),
    );

    let footer = format_args!("Issues can be reported on Github: {CARGO_PKG_REPOSITORY}/issues");

    if print_ignored {
        out(format_args!(
            "{help_pre}\n\n\
            Ignored Options:\n\
            {ignored}\n\n\
            {footer}",
            ignored = HELP_IGNORED_OPTIONS.trim_matches('\n'),
        ));
    } else {
        out(format_args!("{help_pre}\n\n{footer}"));
    }
}

fn short_opt(name: char) -> impl for<'a> FnOnce(&'a OsStr) -> bool {
    move |arg| {
        arg.strip_prefix("-").is_some_and(|arg| {
            arg.len() == 1
                && *arg
                    .as_encoded_bytes()
                    .first()
                    .unwrap_or_else(|| unreachable!())
                    == name as u8
        })
    }
}

fn short_val<P>(name: char) -> impl for<'a> FnOnce(&'a OsStr, P) -> Option<anyhow::Result<OsString>>
where
    P: Iterator,
    <P as Iterator>::Item: Into<OsString>,
{
    move |arg, mut it| {
        if short_opt(name)(arg) {
            Some(
                it.next()
                    .map(Into::into)
                    .with_context(|| report_missing_value(arg)),
            )
        } else {
            None
        }
    }
}

fn long_opt(name: &str) -> impl for<'a> FnOnce(&'a OsStr) -> bool {
    move |arg| arg.strip_prefix("--").is_some_and(|arg| arg == name)
}

fn long_bool(name: &str) -> impl for<'a> FnOnce(&'a OsStr) -> Option<bool> {
    move |arg| {
        arg.strip_prefix("--").and_then(|arg| {
            if arg == name {
                Some(true)
            } else if arg.strip_prefix("no-").is_some_and(|arg| arg == name) {
                Some(false)
            } else {
                None
            }
        })
    }
}

fn long_val<P>(name: &str) -> impl for<'a> FnOnce(&'a OsStr, P) -> Option<anyhow::Result<OsString>>
where
    P: Iterator,
    <P as Iterator>::Item: Into<OsString>,
{
    move |arg, mut it| {
        if long_opt(name)(arg) {
            return Some(
                it.next()
                    .map(Into::into)
                    .with_context(|| report_missing_value(arg)),
            );
        } else if let Some((flag, val)) = arg.strip_prefix("--").and_then(|arg| arg.split_once("="))
        {
            if name == flag {
                return Some(Ok(val.to_owned()));
            }
        }

        None
    }
}

fn legacy_opt(name: &str) -> impl for<'a> FnOnce(&'a OsStr) -> bool {
    move |arg| arg.strip_prefix("-").is_some_and(|arg| arg == name)
}

fn legacy_val<P>(
    name: &str,
) -> impl for<'a> FnOnce(&'a OsStr, P) -> Option<anyhow::Result<OsString>>
where
    P: Iterator,
    <P as Iterator>::Item: Into<OsString>,
{
    move |arg, mut it| {
        if legacy_opt(name)(arg) {
            return Some(
                it.next()
                    .map(Into::into)
                    .with_context(|| report_missing_value(arg)),
            );
        } else if let Some((flag, val)) = arg.strip_prefix('-').and_then(|arg| arg.split_once("="))
        {
            if name == flag {
                return Some(Ok(val.to_owned()));
            }
        }

        None
    }
}

fn anyval<P>(
    s1: &str,
    s2: &str,
) -> impl for<'a> FnOnce(&'a OsStr, P) -> Option<anyhow::Result<OsString>>
where
    P: Iterator,
    <P as Iterator>::Item: Into<OsString>,
{
    move |arg, mut it| {
        let mut argval = |s: &str| {
            if s.len() == 1
                && let Some(v) = short_val(s.chars().next().unwrap())(arg, it.by_ref())
            {
                return Some(v);
            } else if let Some(v) = long_val(s)(arg, it.by_ref()) {
                return Some(v);
            } else if let Some(legacy_arg) = s.strip_prefix('-')
                && !legacy_arg.starts_with('-')
                && let Some(v) = legacy_val(legacy_arg)(arg, it.by_ref())
            {
                return Some(v);
            }
            None
        };

        if !s1.is_empty()
            && let Some(v) = argval(s1)
        {
            Some(v)
        } else if !s2.is_empty()
            && let Some(v) = argval(s2)
        {
            Some(v)
        } else {
            None
        }
    }
}

fn anyopt(short_: char, long_: &str) -> impl for<'a> FnOnce(&'a OsStr) -> bool {
    move |arg| short_opt(short_)(arg) || long_opt(long_)(arg)
}

fn report_missing_value(arg: impl AsRef<OsStr>) -> String {
    format!(
        "missing argument value for '{}'",
        arg.as_ref().to_string_lossy()
    )
}

#[derive(Debug, Default)]
pub struct CliArgs {
    pub inputs: Vec<InputArg>,
    pub options: CliOptions,
    state: InputArgContext,
    stack: Vec<InputArgContext>,
}

impl CliArgs {
    pub fn try_update_from<I, T>(&mut self, mut arg_iter: I) -> anyhow::Result<()>
    where
        I: Iterator<Item = T>,
        T: Into<OsString>,
    {
        while let Some(arg) = arg_iter.next()
            && !self.options.help
            && !self.options.version
        {
            let arg = arg.into();

            if self.try_update_inputs_from(&arg, arg_iter.by_ref())?
                || self.options.try_update_from(&arg, arg_iter.by_ref())?
                || self.try_update_from_mingw_arg(&arg, arg_iter.by_ref())?
            {
            } else {
                bail!("unknown argument: {}", arg.to_string_lossy());
            }
        }

        Ok(())
    }

    fn try_update_inputs_from<I>(&mut self, arg: &OsStr, mut it: I) -> anyhow::Result<bool>
    where
        I: Iterator,
        <I as Iterator>::Item: Into<OsString>,
    {
        let legacy_opt = |s| legacy_opt(s)(arg);
        let long_opt = |s| long_opt(s)(arg);
        let long_or_legacy = |s| long_opt(s) || legacy_opt(s);
        let mut anyval = |s1, s2| anyval(s1, s2)(arg, it.by_ref());

        if !arg.starts_with("-") {
            self.inputs.push(InputArg {
                variant: InputArgVariant::File(arg.into()),
                context: self.state,
            });
        } else if let Some(name) = arg.strip_prefix("-l")
            && !name.is_empty()
        {
            self.inputs.push(InputArg {
                variant: InputArgVariant::Library(name.to_owned()),
                context: self.state,
            });
        } else if long_opt("push-state") {
            self.stack.push(self.state);
        } else if long_opt("pop-state") {
            self.state = self
                .stack
                .pop()
                .context("--pop-state missing previous --push-state")?;
        } else if long_or_legacy("Bstatic")
            || long_or_legacy("static")
            || long_or_legacy("dn")
            || long_or_legacy("non_shared")
        {
            self.state.in_static = true;
        } else if long_or_legacy("Bdynamic")
            || long_or_legacy("dy")
            || long_or_legacy("call_shared")
        {
            self.state.in_static = false;
        } else if long_opt("start-lib") {
            self.state.in_lib = true;
        } else if long_opt("end-lib") {
            self.state.in_lib = false;
        } else if long_opt("whole-archive") {
            self.state.in_whole_archive = true;
        } else if long_opt("no-whole-archive") {
            self.state.in_whole_archive = false;
        } else if let Some(v) = anyval("l", "library") {
            self.inputs.push(InputArg {
                variant: InputArgVariant::Library(v?),
                context: self.state,
            });
        } else {
            return Ok(false);
        }

        Ok(true)
    }

    fn try_update_from_mingw_arg<I>(&mut self, arg: &OsStr, mut it: I) -> anyhow::Result<bool>
    where
        I: Iterator,
        <I as Iterator>::Item: Into<OsString>,
    {
        let mut anyval = |s1, s2| anyval(s1, s2)(arg, it.by_ref());
        let long_opt = |s| long_opt(s)(arg);

        if let Some(v) = anyval("mingw", "") {
            let gcc = v?;
            let args =
                query_gcc(&gcc).with_context(|| format!("--mingw={}", gcc.to_string_lossy()))?;
            self.try_update_from(args.into_iter()).with_context(|| {
                format!("handling '--mingw={}' argument", gcc.to_string_lossy())
            })?;
        } else if long_opt("mingw64") {
            let args = query_gcc("x86_64-w64-mingw32-gcc").context("--mingw64")?;
            self.try_update_from(args.into_iter())
                .context("handling '--mingw64' argument")?;
        } else if long_opt("mingw32") {
            let args = query_gcc("i686-w64-mingw32-gcc").context("--mingw32")?;
            self.try_update_from(args.into_iter())
                .context("handling '--mingw32' argument")?;
        } else if long_opt("ucrt64") {
            let args = query_gcc("x86_64-w64-mingw32ucrt-gcc").context("--ucrt64")?;
            self.try_update_from(args.into_iter())
                .context("handling '--ucrt64' argument")?;
        } else if long_opt("ucrt32") {
            let args = query_gcc("i686-w64-mingw32ucrt-gcc").context("--ucrt32")?;
            self.try_update_from(args.into_iter())
                .context("handling '--ucrt32' argument")?;
        } else {
            return Ok(false);
        }

        Ok(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InputArg {
    pub variant: InputArgVariant,
    pub context: InputArgContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InputArgVariant {
    File(PathBuf),
    Library(OsString),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InputArgContext {
    pub in_static: bool,
    pub in_whole_archive: bool,
    pub in_lib: bool,
}

#[derive(Debug)]
pub struct CliOptions {
    pub auto_image_base: bool,
    pub color_diagnostics: ColorOption,
    pub color_used: bool,
    pub custom_api: Option<OsString>,
    pub define_common: bool,
    pub demangle: bool,
    pub dump_link_graph: Option<PathBuf>,
    pub dynamicbase: bool,
    pub entry: String,
    pub error_limit: usize,
    pub force_group_allocation: bool,
    pub flto: bool,
    pub gc_sections: bool,
    pub high_entropy_va: bool,
    pub ignore_unresolved_symbol: Vec<String>,
    pub library_path: Vec<PathBuf>,
    pub machine: Option<Emulation>,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub merge_bss: bool,
    pub nxcompat: bool,
    pub output: PathBuf,
    pub out_implib: Option<PathBuf>,
    pub plugin: Option<PathBuf>,
    pub plugin_opt: Vec<OsString>,
    pub print_gc_sections: bool,
    pub print_timing: bool,
    pub require_defined: Vec<String>,
    pub sysroot: Option<PathBuf>,
    pub undefined: Vec<String>,
    pub warn_unresolved_symbols: bool,
    pub verbose: usize,
    pub help: bool,
    pub help_ignored: bool,
    pub version: bool,
}

impl std::default::Default for CliOptions {
    fn default() -> Self {
        Self {
            auto_image_base: false,
            color_diagnostics: ColorOption::Auto,
            color_used: false,
            custom_api: None,
            define_common: true,
            demangle: true,
            dump_link_graph: None,
            dynamicbase: false,
            entry: "go".into(),
            error_limit: 20,
            force_group_allocation: true,
            flto: false,
            gc_sections: false,
            high_entropy_va: false,
            ignore_unresolved_symbol: Vec::new(),
            library_path: Vec::new(),
            machine: None,
            major_image_version: 0,
            minor_image_version: 0,
            merge_bss: false,
            nxcompat: false,
            output: "a.bof".into(),
            out_implib: None,
            plugin: None,
            plugin_opt: Vec::new(),
            print_gc_sections: false,
            print_timing: false,
            require_defined: Vec::new(),
            sysroot: None,
            undefined: Vec::new(),
            warn_unresolved_symbols: true,
            verbose: 0,
            help: false,
            help_ignored: false,
            version: false,
        }
    }
}

impl CliOptions {
    fn try_update_from<I>(&mut self, arg: &OsStr, mut it: I) -> anyhow::Result<bool>
    where
        I: Iterator,
        <I as Iterator>::Item: Into<OsString>,
    {
        let long_bool = |s| long_bool(s)(arg);
        let long_opt = |s| long_opt(s)(arg);
        let short_opt = |c| short_opt(c)(arg);
        let anyopt = |c, s| anyopt(c, s)(arg);
        let mut anyval = |s1, s2| anyval(s1, s2)(arg, it.by_ref());

        if long_opt("enable-auto-image-base") {
            self.auto_image_base = true;
        } else if long_opt("disable-auto-image-base") {
            self.auto_image_base = false;
        } else if long_opt("color-diagnostics") {
            self.color_diagnostics = ColorOption::Auto;
        } else if let Some(v) = arg.strip_prefix("--color-diagnostics=") {
            self.color_diagnostics = ColorOption::parse(v, true).with_context(|| {
                format!(
                    "unknown '--color-diagnostics' value: {}",
                    v.to_string_lossy()
                )
            })?;
        } else if let Some(v) = anyval("color", "") {
            let v = v?;
            self.color_diagnostics = ColorOption::parse(&v, true).with_context(|| {
                format!(
                    "unknown '--color-diagnostics' value: {}",
                    v.to_string_lossy()
                )
            })?;
            self.color_used = true;
        } else if let Some(v) = anyval("custom-api", "api") {
            self.custom_api = Some(v?);
        } else if let Some(v) = long_bool("define-common") {
            self.define_common = v;
        } else if let Some(v) = long_bool("demangle") {
            self.demangle = v;
        } else if let Some(v) = anyval("dump-link-graph", "") {
            self.dump_link_graph = Some(v?.into());
        } else if long_opt("dynamicbase") {
            self.dynamicbase = true;
        } else if long_opt("disable-dynamicbase") {
            self.dynamicbase = false;
        } else if let Some(v) = anyval("e", "entry") {
            self.entry = v?.to_string_lossy().to_string();
        } else if let Some(v) = anyval("error-limit", "") {
            self.error_limit = v?
                .to_string_lossy()
                .parse()
                .ok()
                .context("--error-limit value must be a number")?;
        } else if let Some(v) = long_bool("force-group-allocation") {
            self.force_group_allocation = v;
        } else if arg == "-flto" {
            self.flto = true;
        } else if arg == "-fno-lto" {
            self.flto = false;
        } else if let Some(v) = long_bool("gc-sections") {
            self.gc_sections = v;
        } else if long_opt("high-entropy-va") {
            self.high_entropy_va = true;
        } else if let Some(v) = anyval("ignore-unresolved-symbol", "") {
            self.ignore_unresolved_symbol
                .extend(v?.to_string_lossy().split(',').map(|s| s.to_owned()));
        } else if let Some(dir) = arg.strip_prefix("-L")
            && !dir.is_empty()
        {
            self.library_path
                .push(fsutils::lexically_normalize_path(Path::new(dir)));
        } else if let Some(dir) = anyval("L", "library-path") {
            let v = dir?;
            self.library_path
                .push(fsutils::lexically_normalize_path(Path::new(&v)));
        } else if let Some(v) = anyval("m", "") {
            let v = v?;
            self.machine = Some(Emulation::parse(&v).with_context(|| {
                format!("unknown emulation '-m' value: {}", v.to_string_lossy())
            })?);
        } else if let Some(v) = anyval("major-image-version", "") {
            self.major_image_version = v?
                .to_str()
                .and_then(|s| s.parse::<u16>().ok())
                .with_context(|| {
                    format!(
                        "--major-image-version must be an integer between {}-{}",
                        u16::MIN,
                        u16::MAX
                    )
                })?;
        } else if let Some(v) = anyval("minor-image-version", "") {
            self.minor_image_version = v?
                .to_str()
                .and_then(|s| s.parse::<u16>().ok())
                .with_context(|| {
                    format!(
                        "--minor-image-version must be an integer between {}-{}",
                        u16::MIN,
                        u16::MAX
                    )
                })?;
        } else if let Some(v) = long_bool("merge-bss") {
            self.merge_bss = v;
        } else if let Some(v) = long_bool("merge-groups") {
            self.force_group_allocation = v;
        } else if long_opt("nxcompat") {
            self.nxcompat = true;
        } else if let Some(v) = anyval("o", "output") {
            self.output = v?.into();
        } else if let Some(v) = anyval("out-implib", "") {
            self.out_implib = Some(v?.into());
        } else if let Some(v) = anyval("plugin", "-plugin") {
            self.plugin = Some(v?.into());
        } else if let Some(v) = anyval("plugin-opt", "-plugin-opt") {
            self.plugin_opt.push(v?);
        } else if long_opt("print-gc-sections") {
            self.print_gc_sections = true;
        } else if long_opt("print-timing") {
            self.print_timing = true;
        } else if let Some(v) = anyval("require-defined", "keep-symbol") {
            self.require_defined
                .extend(v?.to_string_lossy().split(',').map(|s| s.to_owned()));
        } else if let Some(v) = anyval("sysroot", "") {
            self.sysroot = Some(v?.into());
        } else if let Some(v) = anyval("u", "undefined") {
            self.undefined
                .extend(v?.to_string_lossy().split(',').map(String::from));
        } else if let Some(v) = long_bool("warn-unresolved-symbols") {
            self.warn_unresolved_symbols = v;
        } else if short_opt('v') {
            self.verbose = self.verbose.saturating_add(1);
        } else if let Some(vs) = arg.strip_prefix("-v")
            && vs.to_string_lossy().chars().all(|v| v == 'v')
        {
            self.verbose = self.verbose.saturating_add(vs.len()).saturating_add(1);
        } else if let Some(flag) = arg.strip_prefix("--help=")
            && flag.eq_ignore_ascii_case("ignored")
        {
            self.help = true;
            self.help_ignored = true;
        } else if anyopt('h', "help") {
            self.help = true;
        } else if anyopt('V', "version") {
            self.version = true;
        } else {
            return Ok(false);
        }

        Ok(true)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Emulation {
    I386Pep,
    I386Pe,
}

impl Emulation {
    fn parse(s: &OsStr) -> Option<Self> {
        if s.eq_ignore_ascii_case("i386pep") {
            Some(Emulation::I386Pep)
        } else if s.eq_ignore_ascii_case("i386pe") {
            Some(Emulation::I386Pe)
        } else {
            None
        }
    }

    pub fn into_machine(self) -> u16 {
        match self {
            Self::I386Pep => IMAGE_FILE_MACHINE_AMD64,
            Self::I386Pe => IMAGE_FILE_MACHINE_I386,
        }
    }

    pub fn into_architecture(self) -> object::Architecture {
        match self {
            Self::I386Pep => object::Architecture::X86_64,
            Self::I386Pe => object::Architecture::I386,
        }
    }
}

impl From<Emulation> for LinkerTargetArch {
    fn from(value: Emulation) -> Self {
        match value {
            Emulation::I386Pep => Self::Amd64,
            Emulation::I386Pe => Self::I386,
        }
    }
}

pub fn print_help(print_ignored: bool) {
    fmt_help(
        |fmt| {
            println!("{fmt}");
        },
        print_ignored,
    );
}

fn fmt_version(out: impl FnOnce(std::fmt::Arguments)) {
    if let Some(githash) = GIT_SHORT_HASH {
        out(format_args!(
            "{CARGO_PKG_NAME} version {CARGO_PKG_VERSION} ({githash})"
        ));
    } else {
        out(format_args!("{CARGO_PKG_NAME} version {CARGO_PKG_VERSION}"));
    }
}

pub fn print_version() {
    fmt_version(|fmt| {
        println!("{fmt}");
    });
}

pub fn log_cmdline(args: &[OsString]) {
    fmt_version(|fmt| {
        log::info!("{fmt}");
    });

    let args = args.iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>();
    log::info!("command line: {}", args.join(" "));
}

pub fn expand_response_files(cmdline: impl Iterator<Item = OsString>) -> Vec<OsString> {
    let mut expanded = Vec::new();

    let mut args =
        VecDeque::from_iter(cmdline.map(|arg| argfile::Argument::parse(arg, argfile::PREFIX)));

    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut stack = Vec::new();
    while !args.is_empty() || !stack.is_empty() {
        let Some(arg) = args.pop_front() else {
            args = stack.pop().unwrap_or_else(|| unreachable!());
            continue;
        };

        match arg {
            argfile::Argument::PassThrough(arg) => {
                expanded.push(arg);
            }
            argfile::Argument::Path(path) => {
                if visited.contains(&path) {
                    continue;
                }

                visited.insert(path.clone());
                let Ok(content) = std::fs::read_to_string(&path) else {
                    args.push_front(argfile::Argument::PassThrough(
                        format!("@{}", path.to_string_lossy()).into(),
                    ));
                    continue;
                };

                stack.push(std::mem::take(&mut args));
                args.extend(argfile::parse_fromfile(&content, argfile::PREFIX).into_iter());
            }
        }
    }

    expanded
}

fn query_gcc(gcc: impl AsRef<OsStr>) -> anyhow::Result<Vec<OsString>> {
    let mut args = Vec::new();

    let output = Command::new(gcc.as_ref())
        .args(["-###", "-nostartfiles", "-fno-lto", "a.o"])
        .output()
        .with_context(|| {
            format!(
                "failed running '{} -### -nostartfiles -fno-lto a.o'",
                gcc.as_ref().to_string_lossy()
            )
        })?;

    let stderr = String::from_utf8_lossy(&output.stderr);

    for line in stderr.lines() {
        if let Some(cmdline) = line.strip_prefix(' ') {
            args.extend(parse_gcc_cmdline(cmdline));
        }
    }

    Ok(args)
}

fn parse_gcc_cmdline(cmdline: &str) -> Vec<OsString> {
    shell_split(cmdline)
        .into_iter()
        .filter_map(|arg| {
            if arg.starts_with("-l") || arg.starts_with("-L") {
                Some(arg.into())
            } else {
                None
            }
        })
        .collect()
}

fn shell_split(cmdline: &str) -> Vec<String> {
    let mut tokens = Vec::new();

    let mut chars = cmdline.chars();
    let mut state = SplitState::Space;
    let mut token = String::new();
    while let Some(ch) = chars.next() {
        match state {
            SplitState::Space => {
                if ch.is_whitespace() {
                } else if ch == '\\' {
                    if let Some(ch) = chars.next() {
                        token.push(ch);
                    }
                    state = SplitState::None;
                } else if ch == '"' || ch == '\'' {
                    state = SplitState::Quote(ch);
                } else {
                    token.push(ch);
                    state = SplitState::None;
                }
            }
            SplitState::None => {
                if ch.is_whitespace() {
                    tokens.push(std::mem::take(&mut token));
                    state = SplitState::Space;
                } else if ch == '\\' {
                    if let Some(ch) = chars.next() {
                        token.push(ch);
                    }
                } else if ch == '"' || ch == '\'' {
                    state = SplitState::Quote(ch);
                } else {
                    token.push(ch);
                }
            }
            SplitState::Quote(q) => {
                if ch == '\\' {
                    if let Some(ch) = chars.next() {
                        token.push(ch);
                    }
                } else if ch == q {
                    state = SplitState::None;
                } else {
                    token.push(ch);
                }
            }
        }
    }

    if !token.is_empty() {
        tokens.push(token);
    }

    tokens
}

enum SplitState {
    None,
    Space,
    Quote(char),
}

#[cfg(test)]
mod tests {
    #[test]
    fn shell_split() {
        let cmdline = "/usr/libexec/gcc/x86_64-w64-mingw32/15.2.1/collect2 -fno-lto \"--sysroot=/usr/x86_64-w64-mingw32/sys-root\" -m i386pep -Bdynamic -L/usr/lib/gcc/x86_64-w64-mingw32/15.2.1 -L/usr/lib/gcc/x86_64-w64-mingw32/15.2.1/../../../../x86_64-w64-mingw32/lib/../lib -L/usr/x86_64-w64-mingw32/sys-root/mingw/lib/../lib -L/usr/lib/gcc/x86_64-w64-mingw32/15.2.1/../../../../x86_64-w64-mingw32/lib -L/usr/x86_64-w64-mingw32/sys-root/mingw/lib a.o \"-lstdc++\" -lmingw32 -lgcc_s -lgcc -lmingwex -lmsvcrt -lkernel32 -lpthread -ladvapi32 -lshell32 -luser32 -lkernel32 -lmingw32 -lgcc_s -lgcc -lmingwex -lmsvcrt -lkernel32";
        println!("{:?}", super::shell_split(cmdline));
    }
}
