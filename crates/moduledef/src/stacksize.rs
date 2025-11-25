use std::num::ParseIntError;

use nom::{
    IResult, Parser,
    bytes::complete::tag,
    character::complete::char,
    combinator::opt,
    error::{FromExternalError, ParseError},
    sequence::preceded,
};

use crate::parsers::{parse_u64_number, statement};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StacksizeStatement {
    pub reserve: u64,
    pub commit: Option<u64>,
}

/// Parses the keyword `STACKSIZE`
pub fn parse_stacksize_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("STACKSIZE")(input)
}

pub fn parse_stacksize_statement<I, E>(input: I) -> IResult<I, StacksizeStatement, E>
where
    for<'a> I: nom::Input + nom::Offset + AsRef<str> + nom::Compare<&'a str>,
    <I as nom::Input>::Item: nom::AsChar,
    E: ParseError<I> + FromExternalError<I, ParseIntError>,
{
    statement(parse_stacksize_keyword, parse_stacksize_arguments)
        .map(|(reserve, commit)| StacksizeStatement { reserve, commit })
        .parse(input)
}

/// Parses `reserve[,commit]`
fn parse_stacksize_arguments<I, E>(input: I) -> IResult<I, (u64, Option<u64>), E>
where
    for<'a> I: nom::Input + nom::Offset + AsRef<str> + nom::Compare<&'a str>,
    <I as nom::Input>::Item: nom::AsChar,
    E: ParseError<I> + FromExternalError<I, ParseIntError>,
{
    (parse_u64_number, opt(preceded(char(','), parse_u64_number))).parse(input)
}
