use std::marker::PhantomData;

#[derive(Debug)]
pub struct ParseError<'a> {
    #[allow(unused)]
    data: &'a str,

    #[allow(unused)]
    kind: ParseErrorKind,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseErrorKind {
    Or,
    Token,
    EndOfData,
}

pub type ParseResult<'a, O> = Result<(O, &'a str), ParseError<'a>>;

pub trait Parser<'a> {
    type Output;

    fn parse(self, data: &'a str) -> ParseResult<'a, Self::Output>;

    #[inline]
    fn or<P>(self, other: P) -> Or<'a, Self::Output, Self, P>
    where
        Self: Sized,
        P: Parser<'a, Output = Self::Output>,
    {
        Or {
            first: self,
            second: other,
            _m: PhantomData,
            _o: PhantomData,
        }
    }

    #[inline]
    fn then<P>(self, other: P) -> Then<'a, Self::Output, P::Output, Self, P>
    where
        Self: Sized,
        P: Parser<'a>,
    {
        Then {
            first: self,
            second: other,
            _o: PhantomData,
            _m: PhantomData,
        }
    }

    #[inline]
    fn preceeds<P>(self, parser: P) -> Preceeds<'a, P::Output, Self, P>
    where
        Self: Sized,
        P: Parser<'a>,
    {
        Preceeds {
            first: self,
            parser,
            _o: PhantomData,
            _m: PhantomData,
        }
    }

    #[inline]
    fn surrounded_by<P>(self, value: P) -> SurroundedBy<'a, Self, P>
    where
        Self: Sized,
        P: Parser<'a> + Clone,
    {
        SurroundedBy {
            surround: value,
            parser: self,
            _m: PhantomData,
        }
    }

    #[inline]
    fn terminated_by<P>(self, value: P) -> TerminatedBy<'a, Self, P>
    where
        Self: Sized,
        P: Parser<'a>,
    {
        TerminatedBy {
            terminator: value,
            parser: self,
            _m: PhantomData,
        }
    }
}

impl<'a, T, O> Parser<'a> for T
where
    T: FnMut(&'a str) -> ParseResult<'a, O>,
{
    type Output = O;

    #[inline]
    fn parse(mut self, data: &'a str) -> Result<(Self::Output, &'a str), ParseError<'a>> {
        self(data)
    }
}

#[inline]
pub fn token<'a>(tok: &str) -> impl Parser<'a, Output = &'a str> + Clone {
    move |data: &'a str| {
        let subdata = data.get(0..tok.len()).ok_or(ParseError {
            data,
            kind: ParseErrorKind::EndOfData,
        })?;

        if subdata == tok {
            Ok((subdata, &data[tok.len()..]))
        } else {
            Err(ParseError {
                data,
                kind: ParseErrorKind::Token,
            })
        }
    }
}

#[inline]
pub fn not_token<'a>(tok: &str) -> impl Parser<'a, Output = &'a str> + Clone {
    move |data: &'a str| {
        let subdata = data.get(0..tok.len()).ok_or(ParseError {
            data,
            kind: ParseErrorKind::EndOfData,
        })?;

        if subdata != tok {
            Ok((subdata, &data[tok.len()..]))
        } else {
            Err(ParseError {
                data,
                kind: ParseErrorKind::Token,
            })
        }
    }
}

#[inline]
pub fn many0<'a>(
    parser: impl Parser<'a, Output = &'a str> + Clone,
) -> impl Parser<'a, Output = &'a str> + Clone {
    move |data| {
        let mut offset = 0;
        let mut parse_data = data;

        while let Ok((parsed, remaining)) = parser.clone().parse(parse_data) {
            offset += parsed.len();
            parse_data = remaining;
        }

        Ok((&data[..offset], &data[offset..]))
    }
}

#[inline]
pub fn many1<'a>(
    parser: impl Parser<'a, Output = &'a str> + Clone,
) -> impl Parser<'a, Output = &'a str> + Clone {
    move |data| {
        let mut offset = 0;
        let mut parse_data = data;

        let (parsed, remaining) = parser.clone().parse(parse_data)?;
        offset += parsed.len();
        parse_data = remaining;

        while let Ok((parsed, remaining)) = parser.clone().parse(parse_data) {
            offset += parsed.len();
            parse_data = remaining;
        }

        Ok((&data[..offset], &data[offset..]))
    }
}

pub struct Or<'a, O, F: Parser<'a, Output = O>, S: Parser<'a, Output = O>> {
    first: F,
    second: S,
    _o: PhantomData<O>,
    _m: PhantomData<&'a str>,
}

impl<'a, F: Parser<'a, Output = &'a str>, S: Parser<'a, Output = &'a str>> Parser<'a>
    for Or<'a, &'a str, F, S>
{
    type Output = &'a str;

    fn parse(self, data: &'a str) -> Result<(Self::Output, &'a str), ParseError<'a>> {
        if let Ok((parsed, remaining)) = self.first.parse(data) {
            Ok((parsed, remaining))
        } else if let Ok((parsed, remaining)) = self.second.parse(data) {
            Ok((parsed, remaining))
        } else {
            Err(ParseError {
                data,
                kind: ParseErrorKind::Or,
            })
        }
    }
}

pub struct Then<'a, O1, O2, F: Parser<'a, Output = O1>, S: Parser<'a, Output = O2>> {
    first: F,
    second: S,
    _o: PhantomData<(O1, O2)>,
    _m: PhantomData<&'a str>,
}

impl<'a, O1, O2, F: Parser<'a, Output = O1>, S: Parser<'a, Output = O2>> Parser<'a>
    for Then<'a, O1, O2, F, S>
{
    type Output = (O1, O2);

    fn parse(self, data: &'a str) -> Result<(Self::Output, &'a str), ParseError<'a>> {
        let (p1, remaining) = self.first.parse(data)?;
        let (p2, remaining) = self.second.parse(remaining)?;
        Ok(((p1, p2), remaining))
    }
}

pub struct Preceeds<'a, O, F: Parser<'a>, S: Parser<'a, Output = O>> {
    first: F,
    parser: S,
    _o: PhantomData<O>,
    _m: PhantomData<&'a str>,
}

impl<'a, O, F: Parser<'a>, S: Parser<'a, Output = O>> Parser<'a> for Preceeds<'a, O, F, S> {
    type Output = O;

    fn parse(self, data: &'a str) -> Result<(Self::Output, &'a str), ParseError<'a>> {
        let (_, remaining) = self.first.parse(data)?;
        self.parser.parse(remaining)
    }
}

pub struct SurroundedBy<'a, P: Parser<'a>, S: Parser<'a> + Clone> {
    surround: S,
    parser: P,
    _m: PhantomData<&'a str>,
}

impl<'a, P: Parser<'a>, S: Parser<'a> + Clone> Parser<'a> for SurroundedBy<'a, P, S> {
    type Output = P::Output;

    fn parse(self, data: &'a str) -> Result<(Self::Output, &'a str), ParseError<'a>> {
        let (_, remaining) = self.surround.clone().parse(data)?;
        let (parsed, remaining) = self.parser.parse(remaining)?;
        let (_, remaining) = self.surround.parse(remaining)?;
        Ok((parsed, remaining))
    }
}

pub struct TerminatedBy<'a, P: Parser<'a>, T: Parser<'a>> {
    terminator: T,
    parser: P,
    _m: PhantomData<&'a str>,
}

impl<'a, P: Parser<'a>, T: Parser<'a>> Parser<'a> for TerminatedBy<'a, P, T> {
    type Output = P::Output;

    fn parse(self, data: &'a str) -> Result<(Self::Output, &'a str), ParseError<'a>> {
        let (parsed, remaining) = self.parser.parse(data)?;
        let (_, remaining) = self.terminator.parse(remaining)?;
        Ok((parsed, remaining))
    }
}

#[cfg(test)]
mod tests {
    use super::{Parser, many0, many1, not_token, token};

    #[test]
    fn token_parser() {
        let (parsed, remaining) = token("hello").parse("hello, world").unwrap();
        assert_eq!(parsed, "hello");
        assert_eq!(remaining, ", world");
    }

    #[test]
    fn not_token_parser() {
        let (parsed, remaining) = not_token("a").parse("b").unwrap();
        assert_eq!(parsed, "b");
        assert_eq!(remaining, "");
    }

    #[test]
    fn many0_combinator() {
        let (parsed, remaining) = many0(token("1")).parse("111000").unwrap();
        assert_eq!(parsed, "111");
        assert_eq!(remaining, "000");

        let (parsed, remaining) = many0(token("0")).parse("111").unwrap();
        assert_eq!(parsed, "");
        assert_eq!(remaining, "111");
    }

    #[test]
    fn many1_combinator() {
        let (parsed, remaining) = many1(token("1")).parse("111000").unwrap();
        assert_eq!(parsed, "111");
        assert_eq!(remaining, "000");

        let result = many1(token("0")).parse("111");
        assert!(result.is_err(), "Expected error: {result:?}");
    }

    #[test]
    fn or_combinator() {
        let (parsed, remaining) = token("1").or(token("2")).parse("2").unwrap();
        assert_eq!(parsed, "2");
        assert!(remaining.is_empty());
    }

    #[test]
    fn then_combinator() {
        let (parsed, remaining) = token("1").then(token("2")).parse("12").unwrap();
        assert_eq!(parsed.0, "1");
        assert_eq!(parsed.1, "2");
        assert!(remaining.is_empty());
    }

    #[test]
    fn preceeds_combinator() {
        let (parsed, remaining) = token("0").preceeds(token("1")).parse("01").unwrap();
        assert_eq!(parsed, "1");
        assert_eq!(remaining, "");
    }
}
