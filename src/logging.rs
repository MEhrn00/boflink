use std::{
    io::Write,
    sync::{
        Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
};

use anstream::ColorChoice;
use anstyle::Reset;

static LOGGER: Logger = Logger::new();

const NEWLINE_SEPARATOR: &str = "\n>>> ";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
enum Level {
    Error = log::Level::Error as usize,
    Warn = log::Level::Warn as usize,
    Info = log::Level::Info as usize,
    Debug = log::Level::Debug as usize,
    Trace = log::Level::Trace as usize,
}

impl From<log::Level> for Level {
    fn from(value: log::Level) -> Self {
        match value {
            log::Level::Error => Self::Error,
            log::Level::Warn => Self::Warn,
            log::Level::Info => Self::Info,
            log::Level::Debug => Self::Debug,
            log::Level::Trace => Self::Trace,
        }
    }
}

impl Level {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warning",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    const fn color(&self) -> anstyle::AnsiColor {
        match self {
            Self::Error => anstyle::AnsiColor::Red,
            Self::Warn => anstyle::AnsiColor::Yellow,
            Self::Info => anstyle::AnsiColor::Green,
            Self::Debug => anstyle::AnsiColor::White,
            Self::Trace => anstyle::AnsiColor::Blue,
        }
    }

    const fn style(&self) -> anstyle::Style {
        anstyle::Style::new()
            .fg_color(Some(anstyle::Color::Ansi(self.color())))
            .bold()
    }
}

/// Main logger implementation
pub struct Logger {
    flags: AtomicLoggerFlags,
    error_limit: AtomicUsize,
    error_count: AtomicUsize,
    prepend: Mutex<&'static str>,
}

impl Logger {
    pub const fn new() -> Self {
        Self {
            flags: AtomicLoggerFlags::new(),
            error_limit: AtomicUsize::new(usize::MAX),
            error_count: AtomicUsize::new(0),
            prepend: Mutex::new(""),
        }
    }

    pub fn set_colors(&self, colors: ColorChoice) {
        let enabled = if force_color()
            || colors == ColorChoice::Always
            || colors == ColorChoice::AlwaysAnsi
        {
            true
        } else if colors == ColorChoice::Never || anstyle_query::no_color() {
            false
        } else {
            #[cfg(not(windows))]
            {
                use std::io::IsTerminal;
                std::io::stdout().is_terminal() && std::io::stderr().is_terminal()
            }

            #[cfg(windows)]
            {
                anstyle_query::windows::enable_ansi_colors().unwrap_or_default()
            }
        };

        self.flags
            .set(LoggerFlags::COLORS, enabled, Ordering::Relaxed);
    }

    pub fn set_error_limit(&self, error_limit: usize) {
        self.error_limit.store(error_limit, Ordering::Relaxed);
    }

    pub fn has_error(&self) -> bool {
        self.error_count.load(Ordering::SeqCst) > 0
    }
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let level = Level::from(record.level());
        let msg = record.args().to_string();
        let msg_len = msg.len();
        let msg = msg.replace('\n', NEWLINE_SEPARATOR);
        let is_multiline = msg.len() != msg_len;
        let progname = crate::CARGO_PKG_NAME;
        {
            let mut prepend = self.prepend.lock().expect("logger mutex poisoned");
            if self.flags.contains(LoggerFlags::COLORS, Ordering::Relaxed) {
                writeln!(
                    std::io::stderr().lock(),
                    "{prepend}{progname}: {level_style}{level_name}:{reset} {msg}",
                    level_style = level.style(),
                    level_name = level.as_str(),
                    reset = Reset.render()
                )
                .unwrap();
            } else {
                writeln!(
                    std::io::stderr().lock(),
                    "{prepend}{progname}: {level_name}: {msg}",
                    level_name = level.as_str(),
                )
                .unwrap();
            }
            if is_multiline {
                *prepend = "\n";
            }
        }

        if record.level() == log::Level::Error
            && self.error_count.fetch_add(1, Ordering::SeqCst) + 1
                >= self.error_limit.load(Ordering::Relaxed)
            && !self
                .flags
                .insert(LoggerFlags::EXITING, Ordering::SeqCst)
                .contains(LoggerFlags::EXITING)
        {
            log::error!(logger: self, "too many errors emitted. Exiting.");
            std::process::exit(1);
        }
    }

    fn flush(&self) {}
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    struct LoggerFlags: u8 {
        const EXITING = 1;
        const COLORS = 1 << 1;
    }
}

struct AtomicLoggerFlags(AtomicU8);

impl AtomicLoggerFlags {
    const fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    fn load(&self, order: Ordering) -> LoggerFlags {
        LoggerFlags::from_bits_retain(self.0.load(order))
    }

    fn contains(&self, other: LoggerFlags, order: Ordering) -> bool {
        self.load(order).contains(other)
    }

    fn insert(&self, other: LoggerFlags, order: Ordering) -> LoggerFlags {
        LoggerFlags::from_bits_retain(self.0.fetch_or(other.bits(), order))
    }

    fn remove(&self, other: LoggerFlags, order: Ordering) -> LoggerFlags {
        LoggerFlags::from_bits_retain(self.0.fetch_and(!other.bits(), order))
    }

    fn set(&self, other: LoggerFlags, value: bool, order: Ordering) -> LoggerFlags {
        if value {
            self.insert(other, order)
        } else {
            self.remove(other, order)
        }
    }
}

pub fn set_max_level(level: log::LevelFilter) {
    log::set_max_level(level);
}

pub fn max_level() -> log::LevelFilter {
    log::max_level()
}

pub fn logger() -> &'static Logger {
    &LOGGER
}

pub fn init() -> Result<(), log::SetLoggerError> {
    log::set_logger(&LOGGER).map(|()| set_max_level(log::LevelFilter::Info))
}

fn force_color() -> bool {
    !std::env::var_os("FORCE_COLOR")
        .unwrap_or_default()
        .is_empty()
}
