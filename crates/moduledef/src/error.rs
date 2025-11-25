use nom_locate::LocatedSpan;
use thiserror::Error;

/// Error type for parsing errors.
#[derive(Debug, Clone, Error)]
pub struct Error {
    /// Line in the file where the error occured.
    line: u32,

    /// Column of the error.
    column: usize,

    /// Text fragment where the error occured
    fragment: String,

    /// Error kind.
    kind: ErrorKind,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Error)]
enum ErrorKind {
    #[error("nom error: {}", .0.description())]
    Nom(nom::error::ErrorKind),
}

impl Error {
    /// Returns the line number where the error occured.
    #[inline]
    pub fn line_number(&self) -> u32 {
        self.line
    }

    /// Returns the column number where the error occured.
    #[inline]
    pub fn column_number(&self) -> usize {
        self.column
    }

    /// Returns the text fragment where the error occured.
    #[inline]
    pub fn fragment(&self) -> &String {
        &self.fragment
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "at {line_number}:{column}: {msg}\n\
            {line_number: >5} | {fragment}\n\
            {pad: >5} | {caret:>column$}\n\
            ",
            msg = self.kind,
            line_number = self.line,
            fragment = self.fragment,
            pad = ' ',
            caret = '^',
            column = self.column,
        )
    }
}

pub(crate) fn convert_error<X: Clone>(e: nom::error::Error<LocatedSpan<&str, X>>) -> Error {
    Error {
        line: e.input.location_line(),
        column: e.input.get_utf8_column(),
        fragment: std::str::from_utf8(e.input.get_line_beginning())
            .unwrap()
            .to_string(),
        kind: ErrorKind::Nom(e.code),
    }
}

#[cfg(test)]
mod tests {
    use nom::{FindSubstring, Input};
    use nom_locate::LocatedSpan;

    #[test]
    fn fragment_line() {
        let data = r#"
Hello World
This is some text in a multiline statement
test
foo
"#;

        let input = LocatedSpan::new(data);
        let offset = input.find_substring("text").unwrap();
        let other = input.take_from(offset);
        dbg!(std::str::from_utf8(other.get_line_beginning()).unwrap());
    }
}
