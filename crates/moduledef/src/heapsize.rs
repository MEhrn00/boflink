//! see: https://learn.microsoft.com/en-us/cpp/build/reference/heapsize?view=msvc-170
use std::num::ParseIntError;

use nom::{
    IResult, Parser,
    bytes::complete::tag,
    character::complete::char,
    combinator::{cut, opt},
    error::{FromExternalError, ParseError},
    sequence::preceded,
};

use crate::parsers::{parse_u64_number, statement_assign};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeapsizeStatement {
    pub reserve: u64,
    pub commit: Option<u64>,
}

pub fn parse_heapsize_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("HEAPSIZE")(input)
}

pub fn parse_heapsize_statement<I, E>(input: I) -> IResult<I, HeapsizeStatement, E>
where
    for<'a> I: nom::Input + nom::Offset + AsRef<str> + nom::Compare<&'a str>,
    <I as nom::Input>::Item: nom::AsChar,
    E: ParseError<I> + FromExternalError<I, ParseIntError>,
{
    statement_assign(parse_heapsize_keyword, parse_heapsize_arguments)
        .map(|(reserve, commit)| HeapsizeStatement { reserve, commit })
        .parse(input)
}

fn parse_heapsize_arguments<I, E>(input: I) -> IResult<I, (u64, Option<u64>), E>
where
    for<'a> I: nom::Input + nom::Offset + AsRef<str> + nom::Compare<&'a str>,
    <I as nom::Input>::Item: nom::AsChar,
    E: ParseError<I> + FromExternalError<I, ParseIntError>,
{
    parse_u64_number
        .and(opt(preceded(char(','), cut(parse_u64_number))))
        .parse(input)
}

#[cfg(test)]
mod tests {
    use nom::Finish;

    use crate::heapsize::{HeapsizeStatement, parse_heapsize_statement};

    #[test]
    fn reserve_only() {
        let data = "HEAPSIZE=1";

        let (_, stmt) = parse_heapsize_statement::<_, nom::error::Error<_>>(data)
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            HeapsizeStatement {
                reserve: 1,
                commit: None,
            }
        );
    }

    #[test]
    fn commit() {
        let data = "HEAPSIZE=1,1";

        let (_, stmt) = parse_heapsize_statement::<_, nom::error::Error<_>>(data)
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            HeapsizeStatement {
                reserve: 1,
                commit: Some(1),
            }
        );
    }
}
