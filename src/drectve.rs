use nom::{
    AsChar, Finish, Offset, Parser,
    branch::alt,
    bytes::{
        complete::{escaped, is_not, take_until1, take_while},
        tag,
    },
    character::complete::{char as nomchar, one_of, space0},
    combinator::verify,
    error::context,
    sequence::{delimited, preceded, separated_pair, terminated},
};
use object::{Object, ObjectSection, coff::CoffFile, pe::IMAGE_SCN_LNK_INFO};

#[derive(Debug, thiserror::Error)]
pub enum DirectiveParserError {
    #[error("could not parse .drectve section data as a string: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("{0}")]
    Object(#[from] object::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("could not parse .drectve section")]
pub struct DirectiveParseError;

pub struct DirectiveParser<'a> {
    offset: usize,
    data: &'a str,
}

impl<'a> DirectiveParser<'a> {
    #[allow(unused)]
    pub fn new(data: &'a str) -> DirectiveParser<'a> {
        Self::with_offset(0, data)
    }

    pub fn with_offset(offset: usize, data: &'a str) -> DirectiveParser<'a> {
        let whitespace_count = data
            .chars()
            .enumerate()
            .find(|(_, c)| *c != ' ')
            .map(|(offset, _)| offset)
            .unwrap_or_default();

        Self {
            offset: offset + whitespace_count,
            data: &data[whitespace_count..],
        }
    }

    pub fn parse_next(&mut self) -> Option<Result<(&'a str, &'a str), DirectiveParseError>> {
        if self.data.is_empty() {
            return None;
        }

        let mut parser = terminated(
            separated_pair(cmdline_flag, nomchar(':'), flag_value),
            space0,
        );

        match parser.parse(self.data).finish() {
            Ok((remaining, (flag, value))) => {
                self.offset += self.data.offset(remaining);
                self.data = remaining;
                Some(Ok((flag, value)))
            }
            Err(_) => Some(Err(DirectiveParseError)),
        }
    }
}

fn not_space1(input: &str) -> nom::IResult<&str, &str> {
    verify(take_while(|c| !AsChar::is_space(c)), |s: &str| {
        !s.is_empty()
    })
    .parse(input)
}

fn cmdline_flag(input: &str) -> nom::IResult<&str, &str> {
    preceded(
        context("command line flag prefix (\"/\" or \"-\")", one_of("/-")),
        context("command line flag", take_until1(":")),
    )
    .parse(input)
}

fn quoted_value(input: &str) -> nom::IResult<&str, &str> {
    delimited(tag("\""), is_not("\""), tag("\"")).parse(input)
}

fn escaped_value(input: &str) -> nom::IResult<&str, &str> {
    escaped(not_space1, '\\', one_of(r#"\" "#)).parse(input)
}

fn flag_value(input: &str) -> nom::IResult<&str, &str> {
    context(
        "command line flag value",
        alt((quoted_value, escaped_value)),
    )
    .parse(input)
}

impl<'a> Iterator for DirectiveParser<'a> {
    type Item = Result<(&'a str, &'a str), DirectiveParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.parse_next()
    }
}

/// Parses the .drectve section inside the COFF.
///
/// Returns `Ok(None)` if the COFF does not contain a .drectve section.
pub fn parse_linker_directives<'a>(
    coff: &CoffFile<'a>,
) -> Result<Option<DirectiveParser<'a>>, DirectiveParserError> {
    let drectve_section = match coff.section_by_name(".drectve") {
        Some(section) => {
            if section
                .coff_section()
                .characteristics
                .get(object::LittleEndian)
                & IMAGE_SCN_LNK_INFO
                == 0
            {
                return Ok(None);
            }

            section
        }
        None => return Ok(None),
    };

    let section_data = drectve_section.data()?;

    let mut offset = 0;
    let section_data = if section_data
        .get(..3)
        .is_some_and(|prefix| prefix == [0xef, 0xbb, 0xbf])
    {
        offset = 3;
        section_data.get(3..).unwrap_or_default()
    } else {
        section_data
    };

    Ok(Some(DirectiveParser::with_offset(
        offset,
        std::str::from_utf8(section_data)?,
    )))
}

/// Parses the .drectve section of the COFF returning an iterator over all
/// "/DEFAULTLIB" values.
pub fn parse_defaultlibs<'a>(coff: &CoffFile<'a>) -> Option<impl Iterator<Item = &'a str>> {
    let parser = parse_linker_directives(coff).ok().flatten()?;

    Some(
        parser
            .flatten()
            .filter(|(flag, _)| flag.eq_ignore_ascii_case("DEFAULTLIB"))
            .map(|(_, value)| value),
    )
}

/// Parses the .drectve section "/DEFAULTLIB" values but normalizes the result.
pub fn parse_defaultlibs_normalized<'a>(
    coff: &CoffFile<'a>,
) -> Option<impl Iterator<Item = &'a str>> {
    parse_defaultlibs(coff).map(|libraries| {
        libraries.map(|library| {
            if let Some((prefix, suffix)) = library.rsplit_once(".") {
                if suffix.eq_ignore_ascii_case("lib") {
                    return prefix;
                }
            }

            library
        })
    })
}

/// Parses the .drectve section "/ALTERNATENAME" flags and returns the result
/// as a pair of (<symbol>, <alias>).
#[allow(unused)]
pub fn parse_alternatenames<'a>(
    coff: &CoffFile<'a>,
) -> Option<impl Iterator<Item = (&'a str, &'a str)>> {
    let parser = parse_linker_directives(coff).ok().flatten()?;

    Some(
        parser
            .flatten()
            .filter(|(flag, _)| flag.eq_ignore_ascii_case("ALTERNATENAME"))
            .filter_map(|(_, value)| value.split_once('=')),
    )
}

#[cfg(test)]
mod tests {
    use super::DirectiveParser;

    #[test]
    fn quoted_defaultlibs() {
        const INPUT: &str =
            "  /DEFAULTLIB:\"uuid.lib\" /DEFAULTLIB:\"advapi32.lib\" /DEFAULTLIB:\"OLDNAMES\" ";

        const LIBRARIES: [&str; 3] = ["uuid.lib", "advapi32.lib", "OLDNAMES"];

        let parser = DirectiveParser::new(INPUT);

        for (parse_result, expected) in parser.zip(LIBRARIES) {
            let (flag, library) = parse_result.expect("could not parse data");
            assert_eq!(flag, "DEFAULTLIB");
            assert_eq!(library, expected,);
        }
    }

    #[test]
    fn unquoted_defaultlibs() {
        const INPUT: &str = "  /DEFAULTLIB:uuid.lib /DEFAULTLIB:advapi32.lib /DEFAULTLIB:OLDNAMES ";

        const LIBRARIES: [&str; 3] = ["uuid.lib", "advapi32.lib", "OLDNAMES"];

        let parser = DirectiveParser::new(INPUT);

        for (parse_result, expected) in parser.zip(LIBRARIES) {
            let (flag, library) = parse_result.expect("could not parse data");
            assert_eq!(flag, "DEFAULTLIB");
            assert_eq!(library, expected,);
        }
    }

    #[test]
    fn mixed_defautlibs() {
        const INPUT: &str =
            "  /DEFAULTLIB:uuid.lib /DEFAULTLIB:\"advapi32.lib\" /DEFAULTLIB:OLDNAMES ";

        const LIBRARIES: [&str; 3] = ["uuid.lib", "advapi32.lib", "OLDNAMES"];

        let parser = DirectiveParser::new(INPUT);

        for (parse_result, expected) in parser.zip(LIBRARIES) {
            let (flag, library) = parse_result.expect("could not parse data");
            assert_eq!(flag, "DEFAULTLIB");
            assert_eq!(library, expected,);
        }
    }

    #[test]
    fn defaultlibs_no_trailing_whitespace() {
        const INPUT: &str = "  /DEFAULTLIB:uuid.lib";

        const LIBRARIES: [&str; 1] = ["uuid.lib"];

        let parser = DirectiveParser::new(INPUT);

        for (parse_result, expected) in parser.zip(LIBRARIES) {
            let (flag, library) = parse_result.expect("could not parse data");
            assert_eq!(flag, "DEFAULTLIB");
            assert_eq!(library, expected,);
        }
    }

    #[test]
    fn alternatenames() {
        const INPUT: &str = "  /ALTERNATENAME:foo=bar /alternatename:foo=bar";

        const NAMES: [(&str, &str); 2] = [("foo", "bar"), ("foo", "bar")];

        let parser = DirectiveParser::new(INPUT);

        for (parse_result, expected) in parser.zip(NAMES) {
            let (_, value) = parse_result.expect("could not parse data");
            let alternatename = value
                .split_once('=')
                .expect("alternatename value missing a '='");
            assert_eq!(alternatename, expected);
        }
    }
}
