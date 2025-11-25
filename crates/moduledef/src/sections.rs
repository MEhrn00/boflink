use bitflags::bitflags;
use nom::{
    IResult, Parser, branch::alt, bytes::complete::tag, combinator::value, error::ParseError,
    multi::fold_many0,
};
use nom_locate::LocatedSpan;

use crate::parsers::{lex, lexc, parse_string_arg, statement};

pub fn parse_sections_statement_first<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, SectionsDefinition<'a>, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>,
{
    statement(
        parse_sections_keyword.or(parse_segments_keyword),
        lexc(parse_sections_definition),
    )
    .parse(input)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SectionsDefinition<'a> {
    section_name: &'a str,
    specifier: SectionDefinitionFlags,
}

impl<'a> SectionsDefinition<'a> {
    #[inline]
    pub fn section_name(&self) -> &'a str {
        self.section_name
    }

    #[inline]
    pub fn specifier(&self) -> SectionDefinitionFlags {
        self.specifier
    }

    #[inline]
    pub fn has_execute_modifier(&self) -> bool {
        self.specifier.contains(SectionDefinitionFlags::EXECUTE)
    }

    #[inline]
    pub fn has_read_modifier(&self) -> bool {
        self.specifier.contains(SectionDefinitionFlags::READ)
    }

    #[inline]
    pub fn has_shared_modifier(&self) -> bool {
        self.specifier.contains(SectionDefinitionFlags::SHARED)
    }

    #[inline]
    pub fn has_write_modifier(&self) -> bool {
        self.specifier.contains(SectionDefinitionFlags::WRITE)
    }
}

pub fn parse_sections_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("SECTIONS")(input)
}

pub fn parse_segments_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("SEGMENTS")(input)
}

pub fn parse_sections_definition<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, SectionsDefinition<'a>, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>,
{
    (lex(parse_string_arg), parse_sections_definition_specifier)
        .map(|(section_name, specifier)| SectionsDefinition {
            section_name,
            specifier,
        })
        .parse(input)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SectionDefinitionFlags(u8);

bitflags! {
    impl SectionDefinitionFlags: u8 {
        const EXECUTE = 1;
        const READ = 1 << 1;
        const WRITE = 1 << 2;
        const SHARED = 1 << 3;
    }
}

fn parse_sections_definition_specifier<I, E: ParseError<I>>(
    input: I,
) -> IResult<I, SectionDefinitionFlags, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    fold_many0(
        alt((
            value(SectionDefinitionFlags::EXECUTE, parse_execute_keyword),
            value(SectionDefinitionFlags::READ, parse_read_keyword),
            value(SectionDefinitionFlags::WRITE, parse_write_keyword),
            value(SectionDefinitionFlags::SHARED, parse_shared_keyword),
        )),
        SectionDefinitionFlags::default,
        |mut acc, parsed| {
            acc |= parsed;
            acc
        },
    )
    .parse(input)
}

pub fn parse_execute_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("EXECUTE")(input)
}

pub fn parse_read_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("READ")(input)
}

pub fn parse_shared_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("SHARED")(input)
}

pub fn parse_write_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("WRITE")(input)
}
