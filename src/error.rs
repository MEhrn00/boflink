//! Error handling module.
//!
//! This is essentially a more trimmed down version of [anyhow](https://github.com/dtolnay/anyhow).
//! Anyhow is great and could realistically be used instead of this.
//!
//! Internally, anyhow represents errors using a raw vtable with the error chain.
//! The advantage here is that the original error value is kept as is when propagating
//! out and constructing/chaining errors is very low-cost without any large heap
//! allocations. Anyhow also includes backtrace information if not present in an error.
//!
//! Performance is not really important for errors in this program because they
//! do not get handled in a way for the program to continue. All errors encountered
//! are assumed to be fatal so they are logged in an error message and the program
//! will eventually terminate. Backtrace information is also unused so there is
//! no need to capture it.

use private::Sealed;

/// Result type for the program
pub type Result<T> = std::result::Result<T, Error>;

/// Generic program error type.
///
/// Internally, this is a pointer to a stack of accumulated error messages.
/// The downside with this is that constructing an error requires 2 heap allocations:
/// 1 for the error message and another for the error stack. The is fine for the
/// program because of the module note on error handling performance.
///
/// The error holds a pointer to the error stack instead of the stack itself
/// for size optimizations. Returning a `Result<()>` is only the size of a pointer
/// (8 bytes) but storing the error stack itself in the error would make it
/// 24 bytes.
///
/// Error messages in the stack are displayed in LIFO order delimited by a `:`.
/// New messages can be pushed on the stack using the [`ErrorContext`] trait.
///
/// The result is that using an error handling pattern like this.
/// ```rs
/// read_symbol_name_at_index(123)
///     .context("symbol at index 123")
///     .context("file.o")?;
/// ```
/// Will display a message similar to this when logged
/// ```txt
/// boflink: error: file.o: symbol at index 123: symbol name is not valid
/// ```
#[allow(clippy::box_collection, reason = "reduces size of Result enums")]
#[derive(Debug)]
#[repr(transparent)]
pub struct Error(Box<Vec<String>>);

impl Error {
    pub fn msg(s: impl std::fmt::Display) -> Error {
        Self(Box::new(vec![s.to_string()]))
    }
}

#[macro_export]
macro_rules! bail {
    ($msg:literal $(,)?) => {
        return Err($crate::make_error!($msg))
    };
    ($fmt:expr, $(,)?) => {
        return Err($crate::make_error!($expr))
    };
    ($fmt:expr, $($args:tt)*) => {
        return Err($crate::make_error!($fmt, $($args)*))
    };
}

#[macro_export]
macro_rules! make_error {
    ($msg:literal $(,)?) => {
        $crate::error::Error::msg(format!($msg))
    };
    ($fmt:expr, $(,)?) => {
        $crate::error::Error::msg(format!($fmt))
    };
    ($fmt:expr, $($args:tt)*) => {
        $crate::error::Error::msg(format!($fmt, $($args)*))
    };
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut it = self.0.iter().rev();
        let Some(e) = it.next() else {
            return Ok(());
        };

        f.write_str(e)?;
        it.try_for_each(|e| {
            f.write_str(": ")?;
            f.write_str(e)
        })
    }
}

impl<E: std::error::Error> From<E> for Error {
    fn from(value: E) -> Self {
        Self::msg(value)
    }
}

pub trait ErrorContext<T>: Sealed {
    fn context(self, context: impl std::fmt::Display) -> std::result::Result<T, Error>;
    fn with_context<C: std::fmt::Display>(
        self,
        f: impl FnOnce() -> C,
    ) -> std::result::Result<T, Error>;
}

impl<T, E: Into<Error>> Sealed for std::result::Result<T, E> {}

impl<T, E: Into<Error>> ErrorContext<T> for std::result::Result<T, E> {
    fn context(self, context: impl std::fmt::Display) -> std::result::Result<T, Error> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => {
                let mut e: Error = e.into();
                e.0.push(context.to_string());
                Err(e)
            }
        }
    }

    fn with_context<C: std::fmt::Display>(
        self,
        f: impl FnOnce() -> C,
    ) -> std::result::Result<T, Error> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => {
                let mut e: Error = e.into();
                e.0.push(f().to_string());
                Err(e)
            }
        }
    }
}

impl<T> Sealed for Option<T> {}

impl<T> ErrorContext<T> for Option<T> {
    fn context(self, context: impl std::fmt::Display) -> std::result::Result<T, Error> {
        match self {
            Some(v) => Ok(v),
            None => Err(Error::msg(context)),
        }
    }

    fn with_context<C: std::fmt::Display>(
        self,
        f: impl FnOnce() -> C,
    ) -> std::result::Result<T, Error> {
        match self {
            Some(v) => Ok(v),
            None => Err(Error::msg(f().to_string())),
        }
    }
}

mod private {
    pub trait Sealed {}
}
