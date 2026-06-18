use std::{ffi::OsStr, io::Write, sync::Mutex};

use anstream::AutoStream;
use anstyle::{AnsiColor, Style};

pub use anstream::ColorChoice;

/// Log level message strings.
///
/// The log crate sets these to all uppercase letters which is great for doing
/// more general purpose logging in bulk but lowercase letters look nicer in
/// a console window.
/// https://github.com/rust-lang/log/blob/43f2c2837f93be1c6ff9ce672a940d28152b09cf/src/lib.rs#L460
const LEVEL_NAMES: [&str; 6] = ["", "error:", "warning:", "info:", "debug:", "trace:"];

const LEVEL_COLORS: [Option<AnsiColor>; 6] = [
    None,
    Some(AnsiColor::Red),
    Some(AnsiColor::Yellow),
    Some(AnsiColor::Green),
    Some(AnsiColor::White),
    Some(AnsiColor::Blue),
];

/// Separator to use for multiline log messages
const NEWLINE_SEPARATOR: &str = "\n>>> ";

/// Main logger implementation
#[derive(Debug)]
struct Logger {
    progname: String,
    colors: ColorChoice,
    max_level: log::Level,
    prepend: Mutex<&'static str>,
}

impl Logger {
    #[inline]
    pub fn new(progname: impl Into<String>, colors: ColorChoice, max_level: log::Level) -> Self {
        Self {
            progname: progname.into(),
            colors: AutoStream::new(std::io::stderr(), colors).current_choice(),
            max_level,
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
        let level_style = LEVEL_COLORS[record.level() as usize]
            .map(|color| Style::new().fg_color(Some(color.into())).bold())
            .unwrap_or_default();

        let msg = record.args().to_string();
        let msg_len = msg.len();
        let msg = msg.replace('\n', NEWLINE_SEPARATOR);
        let is_multiline = msg.len() != msg_len;

        {
            let mut prepend = self
                .prepend
                .lock()
                .expect("logger internal mutex is poisoned");
            let mut stream = AutoStream::new(std::io::stderr(), self.colors).lock();
            writeln!(
                stream,
                "{}: {level_style}{level_name}:{reset} {msg}",
                self.progname,
                reset = Style::new().render_reset()
            )
            .unwrap();
            if is_multiline {
                *prepend = "\n";
            }
        }
    }

    fn flush(&self) {}
}

/// Parses a string value into a [`ColorChoice`].
pub fn parse_color_choice(value: impl AsRef<OsStr>, ignore_case: bool) -> Option<ColorChoice> {
    let optmap = [
        ("auto", ColorChoice::Auto),
        ("always", ColorChoice::Always),
        ("never", ColorChoice::Never),
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

/// Creates a new [`Logger`] and initializes it
pub fn init_logger(
    progname: impl Into<String>,
    colors: ColorChoice,
    max_level: log::Level,
) -> Result<(), log::SetLoggerError> {
    log::set_boxed_logger(Box::new(Logger::new(progname, colors, max_level))).inspect(|_| {
        log::set_max_level(max_level.to_level_filter());
    })
}
