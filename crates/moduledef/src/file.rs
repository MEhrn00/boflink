use std::num::ParseIntError;

use nom::{
    Finish, IResult, Parser,
    branch::alt,
    error::{FromExternalError, ParseError},
};
use nom_locate::LocatedSpan;

use crate::{
    error::Error,
    exports::{ExportsDefinition, parse_exports_definition, parse_exports_statement_first},
    heapsize::{HeapsizeStatement, parse_heapsize_statement},
    library::{LibraryStatement, parse_library_statement},
    name::{NameStatement, parse_name_statement},
    parsers::lexc,
    sections::{SectionsDefinition, parse_sections_definition, parse_sections_statement_first},
    stacksize::{StacksizeStatement, parse_stacksize_statement},
    stub::{StubStatement, parse_stub_statement},
    version::{VersionStatement, parse_version_statement},
};

#[derive(Debug, Copy, Clone, Default)]
enum InputSpanContext {
    #[default]
    Root,

    Exports,
    Sections,
    Invalid,
}

type InputSpan<'a> = LocatedSpan<&'a str, InputSpanContext>;

/// A module definition file.
#[derive(Debug, Clone, Copy)]
pub struct ModuleFile<'a> {
    /// The file header statement `LIBRARY | NAME` if it exists.
    header: Option<ModuleFileHeader<'a>>,

    /// The current parse input position.
    input: InputSpan<'a>,
}

impl<'a> ModuleFile<'a> {
    /// Parses a module definition file.
    pub fn parse(data: &'a str) -> Result<ModuleFile<'a>, Error> {
        let input = InputSpan::new_extra(data, InputSpanContext::Root);
        let (remaining, header) = lexc(parse_module_file_header::<nom::error::Error<_>, _>)
            .parse(input)
            .finish()
            .map_err(crate::error::convert_error)?;

        Ok(Self {
            header: Some(header),
            input: remaining,
        })
    }

    /// Returns the header statement from the file if it exists.
    #[inline]
    pub fn header(&self) -> Option<ModuleFileHeader<'a>> {
        self.header
    }

    /// Returns the name of the module if it exists.
    ///
    /// This is either the `[library]` argument value if the module definition
    /// file starts with a `LIBRARY` statement or the `[application]`
    /// argument value if the module definition file starts with a `NAME`
    /// statement.
    #[inline]
    pub fn module_name(&self) -> Option<&'a str> {
        self.header.map(|header| match header {
            ModuleFileHeader::Name(stmt) => stmt.application(),
            ModuleFileHeader::Library(stmt) => stmt.library(),
        })
    }

    /// Returns the `[library]` name value from the `LIBRARY` statement if
    /// it exists.
    #[inline]
    pub fn library_name(&self) -> Option<&'a str> {
        self.header.and_then(|header| {
            if let ModuleFileHeader::Library(stmt) = header {
                Some(stmt.library())
            } else {
                None
            }
        })
    }

    /// Returns the module file base address if it exists.
    ///
    /// This is the value of the `[BASE=address]` argument from either a
    /// `LIBRARY` statement or a `NAME` statement if it exists.
    #[inline]
    pub fn base_address(&self) -> Option<u64> {
        self.header.and_then(|header| match header {
            ModuleFileHeader::Name(stmt) => stmt.base_address(),
            ModuleFileHeader::Library(stmt) => stmt.base_address(),
        })
    }

    /// Returns an iterator over the module definition file statements.
    #[inline]
    pub fn statements(&self) -> ModuleFileStatementsIter<'a> {
        ModuleFileStatementsIter { input: self.input }
    }

    /// Returns an iterator over the export definitions
    #[inline]
    pub fn exports(&self) -> ModuleFileExportsIter<'a> {
        ModuleFileExportsIter {
            statements: self.statements(),
        }
    }
}

/// The header statement of a module definition file.
///
/// One of these statements must be the first statements in the file if they
/// are used.
/// See: https://learn.microsoft.com/en-us/cpp/build/reference/rules-for-module-definition-statements?view=msvc-170
#[derive(Debug, Clone, Copy)]
pub enum ModuleFileHeader<'a> {
    Library(LibraryStatement<'a>),
    Name(NameStatement<'a>),
}

/// Parses either a LIBRARY statement or a NAME statement at the beginning of the file.
fn parse_module_file_header<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, ModuleFileHeader<'a>, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>
        + FromExternalError<LocatedSpan<&'a str, X>, ParseIntError>,
{
    lexc(alt((
        parse_library_statement.map(ModuleFileHeader::Library),
        parse_name_statement.map(ModuleFileHeader::Name),
    )))
    .parse(input)
}

/// Iterator over the statements in a module definition file.
#[derive(Debug, Clone, Copy)]
pub struct ModuleFileStatementsIter<'a> {
    /// Current parse input.
    input: InputSpan<'a>,
}

impl<'a> Iterator for ModuleFileStatementsIter<'a> {
    type Item = Result<ModuleStatement<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.input.is_empty() {
            return None;
        }

        Some(
            match self.input.extra {
                InputSpanContext::Root => lexc(alt((
                    parse_switch_exports,
                    parse_switch_sections,
                    parse_heapsize_statement.map(ModuleStatement::Heapsize),
                    parse_stacksize_statement.map(ModuleStatement::Stacksize),
                    parse_stub_statement.map(ModuleStatement::Stub),
                    parse_version_statement.map(ModuleStatement::Version),
                )))
                .parse(self.input),
                InputSpanContext::Exports => lexc(alt((
                    parse_exports_definition.map(ModuleStatement::ExportsDefinition),
                    parse_switch_root,
                    parse_switch_sections,
                )))
                .parse(self.input),
                InputSpanContext::Sections => lexc(alt((
                    parse_sections_definition.map(ModuleStatement::SectionsDefinition),
                    parse_switch_exports,
                    parse_switch_root,
                )))
                .parse(self.input),
                InputSpanContext::Invalid => {
                    return None;
                }
            }
            .finish()
            .map(|(remaining, parsed)| {
                self.input = remaining;
                parsed
            })
            .map_err(|x: nom::error::Error<InputSpan<'a>>| {
                self.input.extra = InputSpanContext::Invalid;
                crate::error::convert_error(x)
            }),
        )
    }
}

/// A parsed module definition file statement.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ModuleStatement<'a> {
    /// Definition for an EXPORTS statement.
    ExportsDefinition(ExportsDefinition<'a>),

    SectionsDefinition(SectionsDefinition<'a>),

    /// HEAPSIZE statement
    Heapsize(HeapsizeStatement),

    /// STACKSIZE statement
    Stacksize(StacksizeStatement),

    /// STUB statement
    Stub(StubStatement<'a>),

    /// VERSION statement
    Version(VersionStatement),
}

/// Iterator over the export definitions in a module definition file.
#[derive(Debug, Clone, Copy)]
pub struct ModuleFileExportsIter<'a> {
    /// Statements iterator.
    statements: ModuleFileStatementsIter<'a>,
}

impl<'a> Iterator for ModuleFileExportsIter<'a> {
    type Item = Result<ExportsDefinition<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.statements.next()? {
                Ok(ModuleStatement::ExportsDefinition(definition)) => {
                    return Some(Ok(definition));
                }
                Ok(_) => (),
                Err(e) => {
                    return Some(Err(e));
                }
            }
        }
    }
}

fn parse_root_statement<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, ModuleStatement<'a>, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>
        + FromExternalError<LocatedSpan<&'a str, X>, ParseIntError>,
{
    alt((
        parse_heapsize_statement.map(ModuleStatement::Heapsize),
        parse_stacksize_statement.map(ModuleStatement::Stacksize),
        parse_stub_statement.map(ModuleStatement::Stub),
        parse_version_statement.map(ModuleStatement::Version),
    ))
    .parse(input)
}

fn parse_switch_root<'a, E>(input: InputSpan<'a>) -> IResult<InputSpan<'a>, ModuleStatement<'a>, E>
where
    E: ParseError<InputSpan<'a>> + FromExternalError<InputSpan<'a>, ParseIntError>,
{
    switch_context(parse_root_statement, InputSpanContext::Root).parse(input)
}

fn parse_switch_exports<'a, E>(
    input: InputSpan<'a>,
) -> IResult<InputSpan<'a>, ModuleStatement<'a>, E>
where
    E: ParseError<InputSpan<'a>> + FromExternalError<InputSpan<'a>, ParseIntError>,
{
    switch_context(
        parse_exports_statement_first.map(ModuleStatement::ExportsDefinition),
        InputSpanContext::Exports,
    )
    .parse(input)
}

fn parse_switch_sections<'a, E>(
    input: InputSpan<'a>,
) -> IResult<InputSpan<'a>, ModuleStatement<'a>, E>
where
    E: ParseError<InputSpan<'a>> + FromExternalError<InputSpan<'a>, ParseIntError>,
{
    switch_context(
        parse_sections_statement_first.map(ModuleStatement::SectionsDefinition),
        InputSpanContext::Sections,
    )
    .parse(input)
}

fn switch_context<'a, O, E, P>(
    mut parser: P,
    new_context: InputSpanContext,
) -> impl Parser<InputSpan<'a>, Output = O, Error = E>
where
    P: Parser<InputSpan<'a>, Output = O, Error = E>,
    E: ParseError<InputSpan<'a>>,
{
    move |input: InputSpan<'a>| -> IResult<InputSpan<'a>, O, E> {
        let (mut remaining, parsed) = parser.parse(input)?;
        remaining.extra = new_context;
        Ok((remaining, parsed))
    }
}

#[cfg(test)]
mod tests {
    use crate::file::ModuleFile;

    #[test]
    fn library_header() {
        let data = "LIBRARY foo";
        let modfile = ModuleFile::parse(data).expect("Could not parse module file");
        assert_eq!(modfile.module_name(), Some("foo"));
    }

    #[test]
    fn library_header_comments() {
        let data = ";\n\
            ; Comment\n\
            ;\n\
            LIBRARY foo";

        let modfile = ModuleFile::parse(data).expect("Could not parse module file");
        assert_eq!(modfile.module_name(), Some("foo"));
    }
}
