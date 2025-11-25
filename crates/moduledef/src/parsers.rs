use std::num::ParseIntError;

use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{is_not, tag, take_while1},
    character::complete::{
        char, hex_digit1, line_ending, multispace0, multispace1, not_line_ending, satisfy,
    },
    combinator::{cut, recognize, verify},
    error::{ErrorKind, FromExternalError, ParseError},
    multi::{many0, many0_count, many1},
    sequence::{delimited, preceded, separated_pair, terminated},
};
use nom_locate::LocatedSpan;

use crate::keyword::is_keyword;

/// Combinator for removing preceeding and trailing whitespace tokens when
/// applying the specified parser
pub fn lex<I, O, E: ParseError<I>, P>(parser: P) -> impl Parser<I, Output = O, Error = E>
where
    I: nom::Input,
    <I as nom::Input>::Item: nom::AsChar,
    P: Parser<I, Output = O, Error = E>,
{
    delimited(multispace0, parser, multispace0)
}

/// Combinator which removes preceeding line comments and any preceeding/trailing
/// whitespace
pub fn lexc<'a, O, E, P, X: Clone>(
    parser: P,
) -> impl Parser<LocatedSpan<&'a str, X>, Output = O, Error = E>
where
    E: ParseError<LocatedSpan<&'a str, X>>,
    P: Parser<LocatedSpan<&'a str, X>, Output = O, Error = E>,
{
    preceded(
        many0_count(alt((
            terminated(recognize(parse_comment), line_ending),
            multispace1,
        ))),
        lex(parser),
    )
}

/// Combinator for parsing an assignment expression. Takes in a parser for the
/// key and a parser for the value.
///
/// An assignment expression is in the form of `<key>=<value>` or `<key>:<value>`.
/// This will return the parsed key/value pair.
pub fn assign<I, E: ParseError<I>, O1, O2, P1, P2>(
    key_parser: P1,
    value_parser: P2,
) -> impl Parser<I, Output = (O1, O2), Error = E>
where
    I: nom::Input,
    <I as nom::Input>::Item: nom::AsChar,
    P1: Parser<I, Output = O1, Error = E>,
    P2: Parser<I, Output = O2, Error = E>,
{
    separated_pair(
        key_parser,
        lex(char('=').or(char(':'))),
        terminated(value_parser, multispace0),
    )
}

/// Combinator for parsing a statement. Takes a keyword parser and argument
/// parser
pub fn statement<I, O1, O2, E: ParseError<I>, P1, P2>(
    stmt_parser: P1,
    args_parser: P2,
) -> impl Parser<I, Output = O2, Error = E>
where
    I: nom::Input,
    <I as nom::Input>::Item: nom::AsChar,
    P1: Parser<I, Output = O1, Error = E>,
    P2: Parser<I, Output = O2, Error = E>,
{
    preceded(stmt_parser.and(cut(multispace1)), cut(lex(args_parser)))
}

/// Combinator for parsing an 'assignment' statement.
///
/// This is a statement where the keyword and arguments are separated by a ':'
/// or '=' character instead of normal whitepace. This can also be used to parse
/// assignment statements in arguments if the key is not needed.
pub fn statement_assign<I, E: ParseError<I>, O1, O2, P1, P2>(
    key_parser: P1,
    value_parser: P2,
) -> impl Parser<I, Output = O2, Error = E>
where
    I: nom::Input,
    <I as nom::Input>::Item: nom::AsChar,
    P1: Parser<I, Output = O1, Error = E>,
    P2: Parser<I, Output = O2, Error = E>,
{
    assign(key_parser, value_parser).map(|(_, value)| value)
}

/// Returns `true` if the input stream is at the start of a line.
fn is_start_of_line<T: nom::AsBytes, X: Clone>(input: LocatedSpan<T, X>) -> bool {
    input.get_column() == 1
}

/// Combinator which only applies the parser if the input is at the start of a
/// line.
///
/// Returns `Fail` if the input is not at the start of a line
fn start_of_line<'a, O, E, P, X: Clone>(
    mut parser: P,
) -> impl Parser<LocatedSpan<&'a str, X>, Output = O, Error = E>
where
    E: ParseError<LocatedSpan<&'a str, X>>,
    P: Parser<LocatedSpan<&'a str, X>, Output = O, Error = E>,
{
    move |input: LocatedSpan<&'a str, X>| {
        if is_start_of_line(input.clone()) {
            parser.parse(input).map_err(nom::Err::convert)
        } else {
            Err(nom::Err::Error(E::from_error_kind(input, ErrorKind::Fail)))
        }
    }
}

/// Parses a comment prefix character
///
/// ```ebnf
/// comment_prefix = ";" ;
/// ```
fn parse_comment_prefix<I: nom::Input, E: ParseError<I>>(input: I) -> IResult<I, char, E>
where
    <I as nom::Input>::Item: nom::AsChar,
{
    char(';')(input)
}

/// Returns `true` if the character is a comment character
fn is_comment_prefix(ch: impl nom::AsChar) -> bool {
    ch.as_char() == ';'
}

/// Parses a comment line.
///
/// Returns `Fail` if the input is not at the start of a line.
///
/// ```ebnf
/// all characters = ? all visible characters ? ;
/// newline = "\n" | "\r\n" ;
/// comment_prefix = ";" ;
/// comment = comment_char , { all characters } , newline ;
/// ```
fn parse_comment<'a, E: ParseError<LocatedSpan<&'a str, X>>, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, &'a str, E> {
    start_of_line(preceded(parse_comment_prefix, not_line_ending))
        .map(|parsed| *parsed)
        .parse(input)
}

/// Parses an unprefixed hex number into a u64
///
/// The hex number can contain optional '_' characters to help group large
/// numbers.
/// ```text
/// FFFFFFFF
/// FF_FF_FF_FF
/// ```
fn parse_u64hex<I, E: ParseError<I> + FromExternalError<I, ParseIntError>>(
    input: I,
) -> IResult<I, u64, E>
where
    I: nom::Input + nom::Offset + AsRef<str>,
    <I as nom::Input>::Item: nom::AsChar,
{
    recognize(many1(terminated(hex_digit1, many0(char('_')))))
        .map_res(|parsed: I| {
            let s = parsed.as_ref();
            if s.contains('_') {
                u64::from_str_radix(&s.replace('_', ""), 16)
            } else {
                u64::from_str_radix(s, 16)
            }
        })
        .parse(input)
}

/// Parses a prefixed hex number into a u64
///
/// The hex number can contain optional '_' characters.
/// ```text
/// 0xFFFFFFFF
/// 0xFF_FF_FF_FF
/// ```
fn parse_u64hex_prefixed<I, E: ParseError<I> + FromExternalError<I, ParseIntError>>(
    input: I,
) -> IResult<I, u64, E>
where
    for<'a> I: nom::Input + nom::Offset + AsRef<str> + nom::Compare<&'a str>,
    <I as nom::Input>::Item: nom::AsChar,
{
    preceded(tag("0x").or(tag("0X")), parse_u64hex).parse(input)
}

/// Parses a numeric argument into a u64.
///
/// Follows the rules for module definition file numeric arguments.
/// > Numeric arguments are specified in base 10 or hexadecimal.
///
/// See: https://learn.microsoft.com/en-us/cpp/build/reference/rules-for-module-definition-statements?view=msvc-170
pub fn parse_u64_number<I, E: ParseError<I> + FromExternalError<I, ParseIntError>>(
    input: I,
) -> IResult<I, u64, E>
where
    for<'a> I: nom::Input + nom::Offset + AsRef<str> + nom::Compare<&'a str>,
    <I as nom::Input>::Item: nom::AsChar,
{
    parse_u64hex_prefixed
        .or(nom::character::complete::u64)
        .parse(input)
}

/// Parses an unprefixed hex number into a u16.
fn parse_u16hex<I, E: ParseError<I> + FromExternalError<I, ParseIntError>>(
    input: I,
) -> IResult<I, u16, E>
where
    I: nom::Input + nom::Offset + AsRef<str>,
    <I as nom::Input>::Item: nom::AsChar,
{
    recognize(many1(terminated(hex_digit1, many0(char('_')))))
        .map_res(|parsed: I| {
            let s = parsed.as_ref();
            if s.contains('_') {
                u16::from_str_radix(&s.replace('_', ""), 16)
            } else {
                u16::from_str_radix(s, 16)
            }
        })
        .parse(input)
}

/// Parses an `0x` prefixed hex number into a u16
pub fn parse_u16hex_prefixed<I, E: ParseError<I> + FromExternalError<I, ParseIntError>>(
    input: I,
) -> IResult<I, u16, E>
where
    for<'a> I: nom::Input + nom::Offset + AsRef<str> + nom::Compare<&'a str>,
    <I as nom::Input>::Item: nom::AsChar,
{
    preceded(tag("0x").or(tag("0X")), parse_u16hex).parse(input)
}

/// Parses a numeric argument into a u16.
///
/// Follows the rules for module definition file numeric arguments.
/// > Numeric arguments are specified in base 10 or hexadecimal.
///
/// See: https://learn.microsoft.com/en-us/cpp/build/reference/rules-for-module-definition-statements?view=msvc-170
pub fn parse_u16_number<I, E: ParseError<I> + FromExternalError<I, ParseIntError>>(
    input: I,
) -> IResult<I, u16, E>
where
    for<'a> I: nom::Input + nom::Offset + AsRef<str> + nom::Compare<&'a str>,
    <I as nom::Input>::Item: nom::AsChar,
{
    parse_u16hex_prefixed
        .or(nom::character::complete::u16)
        .parse(input)
}

/// Parses an identifier that is not a reserved keyword.
pub fn parse_user_identifier<'a, E: ParseError<LocatedSpan<&'a str, X>>, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, &'a str, E> {
    verify(parse_identifier, |parsed: &str| !is_keyword(parsed)).parse(input)
}

/// Parses an identifier string.
pub fn parse_identifier<'a, E: ParseError<LocatedSpan<&'a str, X>>, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, &'a str, E> {
    let (remaining, parsed) = take_while1(|ch: char| !is_identifier_sep(ch))
        .map(|v: LocatedSpan<&'a str, X>| *v)
        .parse(input)?;

    // Ensure that the parser did not short-circuit at an invalid comment prefix
    if !is_start_of_line(remaining.clone()) && !remaining.clone().is_empty() {
        satisfy(|c| !is_comment_prefix(c))(remaining.clone())?;
    }

    Ok((remaining, parsed))
}

/// Returns `true` if the specified character is a separator for an identifier.
fn is_identifier_sep(ch: char) -> bool {
    ch.is_ascii_whitespace() || ch == ';' || ch == ':' || ch == '=' || ch == ',' || ch == '.'
}

/// Parses a quoted string
pub fn parse_quoted_string<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, &'a str, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>,
{
    delimited(tag("\""), is_not("\"\r\n"), tag("\""))
        .map(|v: LocatedSpan<&'a str, X>| *v)
        .parse(input)
}

/// Parses a module definition file string argument.
///
/// This is either a string literal or a user identifier.
pub fn parse_string_arg<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, &'a str, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>,
{
    parse_quoted_string.or(parse_user_identifier).parse(input)
}

#[cfg(test)]
mod tests {
    use nom::{Finish, Parser, bytes::complete::tag};
    use nom_locate::LocatedSpan;

    use crate::parsers::{lex, lexc, parse_comment};

    #[test]
    fn comment_single_line() {
        let data = "; Comment";

        let (_, res) = parse_comment::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");
        assert_eq!(res, " Comment");
    }

    #[test]
    fn lex_single_token() {
        let data = "   token  ";

        let (_, res) = lex::<_, _, nom::error::Error<_>, _>(tag("token"))
            .parse(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(*res, "token");
    }

    #[test]
    fn lexc_multiple_lines() {
        let data = r#";
; This is some header
; with
; comments
;

start
"#;

        let (_, res) = lexc::<_, nom::error::Error<_>, _, _>(tag("start"))
            .parse(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(*res, "start");
    }

    #[test]
    fn lexc_invalid_comment() {
        let data = r#";
;
text;
;
;

token
"#;

        let _ = lexc::<_, nom::error::Error<_>, _, _>(tag("token"))
            .parse(LocatedSpan::new(data))
            .finish()
            .expect_err("Expected error but found Result::Ok");
    }
}
