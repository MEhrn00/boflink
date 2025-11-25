use nom::{IResult, Parser, bytes::complete::tag, error::ParseError};
use nom_locate::LocatedSpan;

use crate::parsers::{parse_string_arg, statement_assign};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct StubStatement<'a> {
    pub filename: &'a str,
}

/// Parses `STUB`
pub fn parse_stub_keyword<I, E>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
    E: ParseError<I>,
{
    tag("STUB")(input)
}

/// Parses `STUB:filename`
pub fn parse_stub_statement<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, StubStatement<'a>, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>,
{
    statement_assign(parse_stub_keyword, parse_string_arg)
        .map(|filename| StubStatement { filename })
        .parse(input)
}
