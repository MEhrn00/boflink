//! Timing utilities.

use std::time::Duration;

use log::RecordBuilder;

/// Scoped timer instance for tracking execution time.
///
/// The timer starts when this is struct is created and ends when it goes out
/// of scope or when [`ScopedTimer::stop()`] is called.
pub struct ScopedTimer {
    caller: &'static std::panic::Location<'static>,
    callback: Option<Box<dyn FnMut(Emitter, Duration)>>,
    start: std::time::Instant,
}

impl ScopedTimer {
    /// Creates a new [`ScopedTimer`] which will execute `f` when stopped.
    ///
    /// The callback function is passed an [`Emitter`] object used for logging
    /// a [`log::trace!`] record and the recorded [`std::time::Duration`].
    ///
    /// If the thread that handles dropping this timer panics, the callback
    /// function will not be executed.
    #[track_caller]
    pub fn with_callback(f: impl FnMut(Emitter, Duration) + 'static) -> ScopedTimer {
        Self {
            caller: std::panic::Location::caller(),
            callback: Some(Box::new(f)),
            start: std::time::Instant::now(),
        }
    }

    /// Creates a new [`ScopedTimer`] that prints out `<msg> tool <time>` in
    /// a [`log::trace!`] record.
    #[track_caller]
    pub fn msg(msg: impl std::fmt::Display + 'static) -> ScopedTimer {
        Self {
            caller: std::panic::Location::caller(),
            callback: Some(Box::new(move |emitter, d| {
                emitter.emit(format_args!("{msg} took {}", d.display()));
            })),
            start: std::time::Instant::now(),
        }
    }

    /// Stops the timer and executes the passed in callback function.
    pub fn stop(mut self) {
        let elapsed = std::time::Instant::now() - self.start;
        if let Some(mut callback) = self.callback.take() {
            callback(
                Emitter {
                    caller: self.caller,
                },
                elapsed,
            )
        }
    }
}

impl Drop for ScopedTimer {
    fn drop(&mut self) {
        if !std::thread::panicking()
            && let Some(mut callback) = self.callback.take()
        {
            let elapsed = std::time::Instant::now() - self.start;
            callback(
                Emitter {
                    caller: self.caller,
                },
                elapsed,
            )
        }
    }
}

/// Emitter for formatting [`log::trace!`] records in timer messages.
pub struct Emitter {
    caller: &'static std::panic::Location<'static>,
}

impl Emitter {
    /// Emits a [`log::trace!`] record using the formatted message.
    ///
    /// This is used to avoid an extra heap allocation when logging the time
    /// message.
    pub fn emit(self, args: std::fmt::Arguments) {
        let record = RecordBuilder::new()
            .args(args)
            .level(log::Level::Trace)
            .target("boflink::timing")
            .file(Some(self.caller.file()))
            .line(Some(self.caller.line()))
            .build();

        log::logger().log(&record);
    }
}

/// Extension trait for [`std::time::Duration`].
pub trait DurationExt {
    fn display(&self) -> DurationDisplay<'_>;
}

impl DurationExt for std::time::Duration {
    fn display(&self) -> DurationDisplay<'_> {
        DurationDisplay { inner: self }
    }
}

/// [`std::fmt::Display`] implementation for a [`std::time::Duration`].
///
/// This will automatically compute significance level such that the time is
/// less than 1000th of a unit and will display the unit suffix.
///
/// The time is internally converted to a `f64` and allows specifying precision
/// in the format specifier.
#[derive(Debug)]
pub struct DurationDisplay<'a> {
    inner: &'a Duration,
}

impl std::fmt::Display for DurationDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.inner < &Duration::from_nanos_u128(1_000) {
            write!(f, "{}ns", self.inner.as_nanos())?;
            return Ok(());
        }

        let (convert, suffix) = if self.inner < &Duration::from_micros(1_000) {
            (Duration::from_micros(1), "µs")
        } else if self.inner < &Duration::from_millis(1_000) {
            (Duration::from_millis(1), "ms")
        } else {
            (Duration::from_secs(1), "s")
        };

        if let Some(precision) = f.precision() {
            write!(
                f,
                "{:.*}{suffix}",
                precision,
                self.inner.div_duration_f64(convert)
            )
        } else {
            write!(f, "{}{suffix}", self.inner.div_duration_f64(convert))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::DurationExt;

    #[test]
    fn duration_formatting() {
        let tests = [
            (Duration::from_secs(1), None, "1s"),
            (Duration::from_secs(1), Some(3), "1.000s"),
            (Duration::from_nanos_u128(100), None, "100ns"),
            (Duration::from_millis(100), Some(2), "100.00ms"),
            (Duration::new(1, 1_000_000), None, "1.001s"),
        ];

        for (duration, precision, expected) in tests {
            let formatted = if let Some(precision) = precision {
                format!("{:.precision$}", duration.display())
            } else {
                format!("{}", duration.display())
            };
            assert_eq!(
                formatted, expected,
                "duration = {duration:?}, precision = {precision:?}"
            );
        }
    }
}
