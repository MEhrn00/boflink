use private::Sealed;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(Box<ErrorInner>);

#[derive(Debug)]
#[repr(transparent)]
struct ErrorInner(Vec<String>);

impl Error {
    pub fn msg(s: impl std::fmt::Display) -> Error {
        Self(Box::new(ErrorInner(vec![s.to_string()])))
    }
}

#[macro_export]
macro_rules! bail {
    ($msg:literal $(,)?) => {
        return Err($crate::error!($msg))
    };
    ($fmt:expr, $(,)?) => {
        return Err($crate::error!($expr))
    };
    ($fmt:expr, $($args:tt)*) => {
        return Err($crate::error!($fmt, $($args)*))
    };
}

#[macro_export]
macro_rules! error {
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
        let mut it = self.0.0.iter().rev();
        let Some(e) = it.next() else {
            return Ok(());
        };

        f.write_str(&e)?;
        it.try_for_each(|e| {
            f.write_str(": ")?;
            f.write_str(&e)
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
                e.0.0.push(context.to_string());
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
                e.0.0.push(f().to_string());
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
