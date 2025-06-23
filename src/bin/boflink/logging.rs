use std::io::{IsTerminal, Write};

use log::Level;
use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};

use crate::arguments::{CliOptionArgs, ColorOption};

struct CliLogger {
    stdout: BufferWriter,
    stderr: BufferWriter,
}

impl log::Log for CliLogger {
    #[inline]
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if record.args().as_str().is_some_and(|args| args.is_empty()) {
            return;
        }

        let writer = if record.level() <= Level::Warn {
            &self.stderr
        } else {
            &self.stdout
        };

        let mut buffer = writer.buffer();
        write!(buffer, "{}: ", env!("CARGO_BIN_NAME")).unwrap();

        match record.level() {
            Level::Error => {
                let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true));
                write!(buffer, "error:").unwrap();
            }
            Level::Warn => {
                let _ =
                    buffer.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)).set_bold(true));
                write!(buffer, "warn:").unwrap();
            }
            Level::Info => {
                let _ =
                    buffer.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_bold(true));
                write!(buffer, "info:").unwrap();
            }
            Level::Debug => {
                let _ =
                    buffer.set_color(ColorSpec::new().set_fg(Some(Color::White)).set_bold(true));
                write!(buffer, "debug:").unwrap();
            }
            Level::Trace => {
                let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Blue)).set_bold(true));
                write!(buffer, "trace:").unwrap();
            }
        }

        buffer.reset().unwrap();
        writeln!(buffer, " {}", record.args()).unwrap();

        writer.print(&buffer).unwrap();
    }

    fn flush(&self) {}
}

/// Sets up logging for the cli
pub fn setup_logger(options: &CliOptionArgs) -> anyhow::Result<()> {
    let color_choice = if options.color == ColorOption::Auto
        && std::env::var("TERM")
            .ok()
            .is_none_or(|term| !term.eq_ignore_ascii_case("dumb"))
        && std::env::var_os("NO_COLOR").is_none()
    {
        options.color.into()
    } else {
        ColorChoice::Never
    };

    log::set_boxed_logger(Box::from(CliLogger {
        stdout: BufferWriter::stdout(
            if color_choice != ColorChoice::Never && std::io::stdout().is_terminal() {
                color_choice
            } else {
                ColorChoice::Never
            },
        ),
        stderr: BufferWriter::stderr(
            if color_choice != ColorChoice::Never && std::io::stderr().is_terminal() {
                color_choice
            } else {
                ColorChoice::Never
            },
        ),
    }))
    .map(|()| {
        if options.verbose >= 2 {
            log::set_max_level(log::LevelFilter::Trace);
        } else if options.verbose >= 1 {
            log::set_max_level(log::LevelFilter::Debug);
        } else {
            log::set_max_level(log::LevelFilter::Info);
        }
    })?;

    Ok(())
}
