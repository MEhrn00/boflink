use std::num::ParseIntError;

use nom::{
    IResult, Parser,
    bytes::complete::tag,
    combinator::cut,
    error::{FromExternalError, ParseError},
};

use crate::parsers::{parse_u64_number, statement_assign};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BaseStatement {
    pub address: u64,
}

/// Parses the keyword `BASE`
pub fn parse_base_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("BASE")(input)
}

/// Parses `BASE=address`
pub fn parse_base_statement<I, E>(input: I) -> IResult<I, BaseStatement, E>
where
    for<'a> I: nom::Input + nom::Offset + AsRef<str> + nom::Compare<&'a str>,
    <I as nom::Input>::Item: nom::AsChar,
    E: ParseError<I> + FromExternalError<I, ParseIntError>,
{
    statement_assign(parse_base_keyword, cut(parse_u64_number))
        .map(|address| BaseStatement { address })
        .parse(input)
}

#[cfg(test)]
mod tests {
    use nom::Finish;

    use crate::base::{BaseStatement, parse_base_statement};

    #[test]
    fn decimal() {
        let data = "BASE=123";

        let (_, stmt) = parse_base_statement::<_, nom::error::Error<_>>(data)
            .finish()
            .expect("Could not parse data");

        assert_eq!(stmt, BaseStatement { address: 123 });
    }

    #[test]
    fn hexadecimal() {
        let data = "BASE=0x123";

        let (_, stmt) = parse_base_statement::<_, nom::error::Error<_>>(data)
            .finish()
            .expect("Could not parse data");

        assert_eq!(stmt, BaseStatement { address: 0x123 });
    }

    #[test]
    fn space_separated() {
        let tests = [
            ("BASE= 123", 123),
            ("BASE =123", 123),
            ("BASE = 123", 123),
            ("BASE      =     123", 123),
        ];

        for (data, expected) in tests {
            let (_, stmt) = parse_base_statement::<_, nom::error::Error<_>>(data)
                .finish()
                .unwrap_or_else(|_| panic!("Could not parse {data}"));

            assert_eq!(stmt, BaseStatement { address: expected });
        }
    }
}
