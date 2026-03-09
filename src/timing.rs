//! Timing utilities.

use std::time::Duration;

use log::RecordBuilder;

use crate::stdext::time::DurationExt;

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
    #[allow(unused)]
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
    #[allow(unused)]
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
