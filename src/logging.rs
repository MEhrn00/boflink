use std::{
    ffi::OsStr,
    fmt::Debug,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use clap::ValueEnum;

const CARGO_PKG_NAME: &str = env!("CARGO_PKG_NAME");

/// Log level message strings.
///
/// The log crate sets these to all uppercase letters which is great for doing
/// more general purpose logging in bulk but lowercase letters look nicer in
/// a console window.
/// https://github.com/rust-lang/log/blob/43f2c2837f93be1c6ff9ce672a940d28152b09cf/src/lib.rs#L460
const LEVEL_NAMES: [&str; 6] = ["", "error:", "warning:", "info:", "debug:", "trace:"];

const LEVEL_COLORS: [&str; 6] = [
    "",
    "\x1b[0;1;31m",
    "\x1b[0;1;33m",
    "\x1b[0;1;32m",
    "\x1b[0;1;37m",
    "\x1b[0;1;34m",
];

const ANSI_RESET: &str = "\x1b[0m";

/// Separator to use for multiline log messages
const NEWLINE_SEPARATOR: &str = "\n>>> ";

/// The main cli logger implementation
#[derive(Debug)]
pub struct Logger {
    /// If ANSI colors should be emitted
    use_colors: bool,

    /// Maximum log level
    max_level: log::Level,

    /// Number of errors that have been emitted by the logger
    error_count: AtomicUsize,

    /// Maximum number of errors to emit before exiting
    max_errors: usize,

    /// String to prepend to the log message
    ///
    /// This is used for adding an extra newline separator between multiline
    /// log messages.
    prepend: Mutex<&'static str>,
}

impl Logger {
    /// Creates a new logger with the specified options
    pub fn new(max_level: log::Level, colors: ColorOption, max_errors: usize) -> Self {
        Self {
            use_colors: should_use_colors(colors),
            max_level,
            error_count: AtomicUsize::new(0),
            max_errors: if max_errors == 0 {
                usize::MAX
            } else {
                max_errors
            },
            prepend: Mutex::new(""),
        }
    }
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let level_name = LEVEL_NAMES[record.level() as usize];

        let tag = if self.use_colors {
            format_args!(
                "{}{level_name}{ANSI_RESET}",
                LEVEL_COLORS[record.level() as usize]
            )
        } else {
            format_args!("{level_name}")
        };

        let msg = record.args().to_string();
        let msg_len = msg.len();
        let msg = msg.replace('\n', NEWLINE_SEPARATOR);
        let is_multiline = msg.len() != msg_len;

        {
            let mut prepend = self
                .prepend
                .lock()
                .expect("logger internal mutex is poisoned");
            eprintln!("{prepend}{CARGO_PKG_NAME}: {tag} {msg}");
            if is_multiline {
                *prepend = "\n";
            }
        }

        if record.metadata().level() == log::Level::Error
            && self.error_count.fetch_add(1, Ordering::Relaxed) + 1 >= self.max_errors
        {
            let prepend = self
                .prepend
                .lock()
                .expect("logger internal mutex is poisoned");
            eprintln!("{prepend}{CARGO_PKG_NAME}: {tag} too many errors emitted, exiting");
            std::process::exit(1);
        }
    }

    fn flush(&self) {}
}

/// Color options for the logger
#[derive(ValueEnum, Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColorOption {
    /// Automatically use colors depending on the environment
    #[value(name = "auto")]
    #[default]
    Auto,

    /// Always use colors
    #[value(name = "always")]
    Always,

    /// Never use colors
    #[value(name = "never")]
    Never,
}

impl std::fmt::Display for ColorOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(v) = self.to_possible_value() {
            write!(f, "{}", v.get_name())?;
        }

        Ok(())
    }
}

impl ColorOption {
    /// Attempts to parse the specified string value into a ColorOption.
    pub fn _parse(value: impl AsRef<OsStr>, ignore_case: bool) -> Option<ColorOption> {
        let optmap = [
            ("auto", ColorOption::Auto),
            ("always", ColorOption::Always),
            ("never", ColorOption::Never),
        ];

        let value = value.as_ref();

        if ignore_case
            && let Some(val) = optmap
                .iter()
                .find_map(|(name, val)| value.eq_ignore_ascii_case(name).then_some(*val))
        {
            Some(val)
        } else if !ignore_case
            && let Some(val) = optmap
                .iter()
                .find_map(|(name, val)| (*name == value).then_some(*val))
        {
            Some(val)
        } else {
            None
        }
    }
}

pub fn init(
    max_level: log::Level,
    colors: ColorOption,
    max_errors: usize,
) -> Result<(), log::SetLoggerError> {
    log::set_boxed_logger(Box::new(Logger::new(max_level, colors, max_errors)))
        .map(|()| log::set_max_level(max_level.to_level_filter()))
}

/// Returns `true` if colors should be used in log messages given the specified
/// color option and environment variable values.
fn should_use_colors(color: ColorOption) -> bool {
    match color {
        ColorOption::Always => true,
        ColorOption::Never => false,
        ColorOption::Auto => {
            if have_nocolor_env() {
                false
            } else if have_clicolor_force() {
                true
            } else if clicolor().is_none_or(|v| v) {
                stderr_supports_ansi_colors()
            } else {
                false
            }
        }
    }
}

/// Returns `true` if the `NO_COLOR` environment variable is set to a non-empty
/// value that is not 0.
///
/// Used for following https://no-color.org/.
fn have_nocolor_env() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty() && v != "0")
}

/// Returns `true` if the `CLICOLOR_FORCE` environment variable is set to a
/// non-empty value that is not 0.
///
/// Used for following https://bixense.com/clicolors/
fn have_clicolor_force() -> bool {
    std::env::var_os("CLICOLOR_FORCE").is_some_and(|v| !v.is_empty() && v != "0")
}

/// Gets the `CLICOLOR` environment variable value.
///
/// - Returns `None` if not present.
/// - Returns `Some(true)` if present and set to a non-empty value other than 0.
/// - Returns `Some(false)` if present and set to 0 or is empty.
///
/// Used for following https://bixense.com/clicolors/
fn clicolor() -> Option<bool> {
    let clicolor = std::env::var_os("CLICOLOR")?;
    Some(!clicolor.is_empty() && clicolor != "0")
}

/// Returns `true` if stderr supports ANSI colors.
fn stderr_supports_ansi_colors() -> bool {
    #[cfg(windows)]
    {
        use std::io::IsTerminal;

        std::io::stderr().is_terminal()
            && windows::enable_vterm_processing(&std::io::stderr()).is_ok()
    }

    #[cfg(not(windows))]
    {
        use std::io::IsTerminal;

        std::io::stderr().is_terminal()
    }
}

#[cfg(windows)]
mod windows {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::{
        Foundation::HANDLE,
        System::Console::{
            CONSOLE_MODE, ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
            GetConsoleMode, SetConsoleMode,
        },
    };

    pub fn enable_vterm_processing(handle: &impl AsRawHandle) -> std::io::Result<()> {
        let mut mode = CONSOLE_MODE::default();

        unsafe {
            GetConsoleMode(HANDLE(handle.as_raw_handle()), &mut mode)
                .map_err(std::io::Error::from)?;
        }

        let vterm_flags = ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT;
        if (mode & vterm_flags) != vterm_flags {
            mode |= vterm_flags;

            unsafe {
                SetConsoleMode(HANDLE(handle.as_raw_handle()), mode)
                    .map_err(std::io::Error::from)?;
            }
        }

        Ok(())
    }
}
