use std::num::ParseIntError;

use nom::{
    IResult, Parser,
    bytes::complete::tag,
    character::complete::char,
    combinator::opt,
    error::{FromExternalError, ParseError},
    sequence::preceded,
};

use crate::parsers::{parse_u16_number, statement};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VersionStatement {
    pub major: u16,
    pub minor: Option<u16>,
}

impl std::default::Default for VersionStatement {
    fn default() -> Self {
        Self {
            major: 0,
            minor: Some(0),
        }
    }
}

/// Parses the keyword `VERSION`
pub fn parse_version_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("VERSION")(input)
}

pub fn parse_version_statement<I, E>(input: I) -> IResult<I, VersionStatement, E>
where
    for<'a> I: nom::Input + nom::Offset + AsRef<str> + nom::Compare<&'a str>,
    <I as nom::Input>::Item: nom::AsChar,
    E: ParseError<I> + FromExternalError<I, ParseIntError>,
{
    statement(parse_version_keyword, parse_version_args)
        .map(|(major, minor)| VersionStatement { major, minor })
        .parse(input)
}

fn parse_version_args<I, E>(input: I) -> IResult<I, (u16, Option<u16>), E>
where
    for<'a> I: nom::Input + nom::Offset + AsRef<str> + nom::Compare<&'a str>,
    <I as nom::Input>::Item: nom::AsChar,
    E: ParseError<I> + FromExternalError<I, ParseIntError>,
{
    (parse_u16_number, opt(preceded(char('.'), parse_u16_number))).parse(input)
}
