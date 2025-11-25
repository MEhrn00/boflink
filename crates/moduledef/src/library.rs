//! see: https://learn.microsoft.com/en-us/cpp/build/reference/library?view=msvc-170

use std::num::ParseIntError;

use nom::{
    IResult, Parser,
    bytes::complete::tag,
    combinator::opt,
    error::{FromExternalError, ParseError},
};
use nom_locate::LocatedSpan;

use crate::{
    base::{BaseStatement, parse_base_statement},
    parsers::{lex, parse_string_arg, statement},
};

/// A `LIBRARY` statement in a module definition file.
///
/// See: https://learn.microsoft.com/en-us/cpp/build/reference/library?view=msvc-170
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LibraryStatement<'a> {
    library: &'a str,
    base: Option<u64>,
}

impl<'a> LibraryStatement<'a> {
    /// Returns the value of the `[library]` argument in the library statement.
    #[inline]
    pub fn library(&self) -> &'a str {
        self.library
    }

    /// Returns the value of the base address if it exists.
    #[inline]
    pub fn base_address(&self) -> Option<u64> {
        self.base
    }
}

/// Parses the keyword `LIBRARY`
pub fn parse_library_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("LIBRARY")(input)
}

/// Parses `LIBRARY [library][BASE=address]`
pub fn parse_library_statement<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, LibraryStatement<'a>, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>
        + FromExternalError<LocatedSpan<&'a str, X>, ParseIntError>,
{
    statement(parse_library_keyword, parse_library_args)
        .map(|(name, base)| LibraryStatement {
            library: name,
            base: base.map(|b| b.address),
        })
        .parse(input)
}

fn parse_library_args<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, (&'a str, Option<BaseStatement>), E>
where
    E: ParseError<LocatedSpan<&'a str, X>>
        + FromExternalError<LocatedSpan<&'a str, X>, ParseIntError>,
{
    (lex(parse_string_arg), opt(lex(parse_base_statement))).parse(input)
}

#[cfg(test)]
mod tests {
    use nom::Finish;
    use nom_locate::LocatedSpan;

    use crate::library::{LibraryStatement, parse_library_statement};

    #[test]
    fn plainname() {
        let data = "LIBRARY foo";

        let (_, stmt) = parse_library_statement::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            LibraryStatement {
                library: "foo",
                base: None,
            }
        );
    }

    #[test]
    fn quoted_name() {
        let data = "LIBRARY \"foo\"";

        let (_, stmt) = parse_library_statement::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            LibraryStatement {
                library: "foo",
                base: None,
            }
        );
    }

    #[test]
    fn with_base() {
        let data = "LIBRARY foo BASE=123";

        let (_, stmt) = parse_library_statement::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            LibraryStatement {
                library: "foo",
                base: Some(123),
            }
        );
    }
}
