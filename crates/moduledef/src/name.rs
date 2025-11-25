//! see: https://learn.microsoft.com/en-us/cpp/build/reference/name-c-cpp?view=msvc-170
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

/// A `NAME` statement in a module definition file.
///
/// See: https://learn.microsoft.com/en-us/cpp/build/reference/name-c-cpp?view=msvc-170
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameStatement<'a> {
    application: &'a str,
    base: Option<u64>,
}

impl<'a> NameStatement<'a> {
    /// Returns the value of the `[application]` argument in the name statement.
    #[inline]
    pub fn application(&self) -> &'a str {
        self.application
    }

    /// Returns the value of the base address if it exists.
    #[inline]
    pub fn base_address(&self) -> Option<u64> {
        self.base
    }
}

/// Parses the keyword `NAME`
pub fn parse_name_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("NAME")(input)
}

/// Parses `NAME [application][BASE=address]`
pub fn parse_name_statement<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, NameStatement<'a>, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>
        + FromExternalError<LocatedSpan<&'a str, X>, ParseIntError>,
{
    statement(parse_name_keyword, parse_name_statement_args)
        .map(|(application, base)| NameStatement {
            application,
            base: base.map(|b| b.address),
        })
        .parse(input)
}

/// Parses `[application][BASE=address]` as a tuple pair
fn parse_name_statement_args<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, (&'a str, Option<BaseStatement>), E>
where
    E: ParseError<LocatedSpan<&'a str, X>>
        + FromExternalError<LocatedSpan<&'a str, X>, ParseIntError>,
{
    (lex(parse_string_arg), opt(parse_base_statement)).parse(input)
}
