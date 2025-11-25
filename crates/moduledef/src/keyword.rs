use nom::{
    IResult, Parser, branch::alt, bytes::complete::tag, combinator::value, error::ParseError,
};

use crate::{
    base::parse_base_keyword,
    exports::{
        parse_data_keyword, parse_exports_keyword, parse_noname_keyword, parse_private_keyword,
    },
    heapsize::parse_heapsize_keyword,
    library::parse_library_keyword,
    name::parse_name_keyword,
    sections::{
        parse_execute_keyword, parse_read_keyword, parse_sections_keyword, parse_segments_keyword,
        parse_shared_keyword, parse_write_keyword,
    },
    stacksize::parse_stacksize_keyword,
    stub::parse_stub_keyword,
    version::parse_version_keyword,
};

/// Module definition file keywords.
#[derive(Debug, Clone, Copy)]
pub enum Keyword {
    Base,
    Constant,
    Data,
    Execute,
    Exports,
    Heapsize,
    Library,
    Name,
    NoName,
    Private,
    Read,
    Sections,
    Segments,
    Shared,
    Stacksize,
    Stub,
    Version,
    Write,
}

impl Keyword {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Base => "BASE",
            Self::Constant => "CONSTANT",
            Self::Data => "DATA",
            Self::Exports => "EXPORTS",
            Self::Execute => "EXECUTE",
            Self::Heapsize => "HEAPSIZE",
            Self::Library => "LIBRARY",
            Self::Name => "NAME",
            Self::NoName => "NONAME",
            Self::Private => "PRIVATE",
            Self::Read => "READ",
            Self::Sections => "SECTIONS",
            Self::Segments => "SEGMENTS",
            Self::Shared => "SHARED",
            Self::Stacksize => "STACKSIZE",
            Self::Stub => "STUB",
            Self::Version => "VERSION",
            Self::Write => "WRITE",
        }
    }
}

impl std::fmt::Display for Keyword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Parses a keyword.
pub fn parse_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, Keyword, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    alt((
        value(Keyword::Base, parse_base_keyword),
        value(Keyword::Constant, parse_constant_keyword),
        value(Keyword::Data, parse_data_keyword),
        value(Keyword::Exports, parse_exports_keyword),
        value(Keyword::Execute, parse_execute_keyword),
        value(Keyword::Heapsize, parse_heapsize_keyword),
        value(Keyword::Library, parse_library_keyword),
        value(Keyword::Name, parse_name_keyword),
        value(Keyword::NoName, parse_noname_keyword),
        value(Keyword::Private, parse_private_keyword),
        value(Keyword::Read, parse_read_keyword),
        value(Keyword::Sections, parse_sections_keyword),
        value(Keyword::Segments, parse_segments_keyword),
        value(Keyword::Shared, parse_shared_keyword),
        value(Keyword::Stacksize, parse_stacksize_keyword),
        value(Keyword::Stub, parse_stub_keyword),
        value(Keyword::Version, parse_version_keyword),
        value(Keyword::Write, parse_write_keyword),
    ))
    .parse(input)
}

/// Returns `true` if the specified string is a keyword.
pub fn is_keyword(s: impl AsRef<str>) -> bool {
    parse_keyword::<_, ()>(s.as_ref()).is_ok()
}

fn parse_constant_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("CONSTANT")(input)
}
