//! see: https://learn.microsoft.com/en-us/cpp/build/reference/exports?view=msvc-170
use std::num::ParseIntError;

use nom::{
    IResult, Parser,
    bytes::complete::tag,
    character::complete::{char, multispace0},
    combinator::{cut, opt},
    error::{FromExternalError, ParseError},
    sequence::{preceded, separated_pair, terminated},
};
use nom_locate::LocatedSpan;

use crate::parsers::{lex, lexc, parse_string_arg, parse_u16_number, statement};

/// All of the definitions for an `EXPORTS` statement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg(test)]
struct ExportsStatement<'a> {
    definitions: Vec<ExportsDefinition<'a>>,
}

/// Parses an `EXPORTS` statement.
#[cfg(test)]
fn parse_exports_statement<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, ExportsStatement<'a>, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>
        + FromExternalError<LocatedSpan<&'a str, X>, ParseIntError>,
{
    use nom::{character::complete::multispace1, multi::many0};

    preceded(
        parse_exports_keyword.and(multispace1),
        many0(lexc(parse_exports_definition)).map(|definitions| ExportsStatement { definitions }),
    )
    .parse(input)
}

/// Parses the keyword `EXPORTS`
pub fn parse_exports_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("EXPORTS")(input)
}

/// Parses an `EXPORTS` statement and returns the first definition
pub fn parse_exports_statement_first<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, ExportsDefinition<'a>, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>
        + FromExternalError<LocatedSpan<&'a str, X>, ParseIntError>,
{
    statement(parse_exports_keyword, lexc(parse_exports_definition)).parse(input)
}

/// A definition entry for an `EXPORTS` statement.
///
/// See: https://learn.microsoft.com/en-us/cpp/build/reference/exports?view=msvc-170
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExportsDefinition<'a> {
    entryname: &'a str,
    entryname_alias: Option<EntrynameAlias<'a>>,
    ordinal: Option<DefinitionOrdinal>,
    attribute: Option<DefinitionAttribute>,
}

impl<'a> ExportsDefinition<'a> {
    /// Returns the `entryname` value of the definition.
    #[inline]
    pub fn entryname(&self) -> &'a str {
        self.entryname
    }

    /// Returns the `entryname` alias if it is present.
    ///
    /// This is the information that is right of the entryname `=` sign.
    #[inline]
    pub fn entryname_alias(&self) -> Option<EntrynameAlias<'a>> {
        self.entryname_alias
    }

    /// Returns the definition ordinal information if it is present.
    #[inline]
    pub fn ordinal(&self) -> Option<DefinitionOrdinal> {
        self.ordinal
    }

    /// Returns the set definition attribute if it is present.
    #[inline]
    pub fn attribute(&self) -> Option<DefinitionAttribute> {
        self.attribute
    }

    /// Returns the `internal_name` value of the definition if it exists.
    #[inline]
    pub fn internal_name(&self) -> Option<&'a str> {
        self.entryname_alias.and_then(|alias| match alias {
            EntrynameAlias::InternalName(name) => Some(name),
            _ => None,
        })
    }

    /// Returns the `other_module.exported_name` value pair of the definition
    /// if it exists.
    #[inline]
    pub fn other_module(&self) -> Option<(&'a str, ExportedName<'a>)> {
        self.entryname_alias.and_then(|alias| match alias {
            EntrynameAlias::External {
                other_module,
                exported_name,
            } => Some((other_module, exported_name)),
            _ => None,
        })
    }

    /// Returns the `ordinal` value of the definition if it exists.
    #[inline]
    pub fn ordinal_value(&self) -> Option<u16> {
        self.ordinal.map(|ordinal| ordinal.value)
    }

    /// Returns `true` if the `NONAME` attribute for the definition ordinal is present.
    #[inline]
    pub fn ordinal_noname(&self) -> bool {
        self.ordinal.map(|ordinal| ordinal.noname).unwrap_or(false)
    }

    /// Returns `true` if the `PRIVATE` attribute is present.
    #[inline]
    pub fn has_private_attribute(&self) -> bool {
        self.attribute
            .map(|attribute| attribute == DefinitionAttribute::Private)
            .unwrap_or(false)
    }

    /// Returns `true` if the `DATA` attribute is present.
    #[inline]
    pub fn has_data_attribute(&self) -> bool {
        self.attribute
            .map(|attribute| attribute == DefinitionAttribute::Data)
            .unwrap_or(false)
    }
}

/// Parses the definition arguments for an `EXPORTS` statement.
///
/// entryname[= internal_name|other_module.exported_name] [@ordinal [NONAME] ] [ [PRIVATE] | [DATA] ]
pub fn parse_exports_definition<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, ExportsDefinition<'a>, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>
        + FromExternalError<LocatedSpan<&'a str, X>, ParseIntError>,
{
    (
        lex(parse_string_arg),
        opt(preceded(
            char('=').and(multispace0),
            cut(lex(parse_definition_entryname_alias)),
        )),
        opt(preceded(char('@'), cut(parse_definition_ordinal))),
        opt(lex(parse_definition_attribute)),
    )
        .map(
            |(entryname, entryname_alias, ordinal, attribute)| ExportsDefinition {
                entryname,
                entryname_alias,
                ordinal,
                attribute,
            },
        )
        .parse(input)
}

/// Alias for the `entryname` parameter in an exports definition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntrynameAlias<'a> {
    /// The `internal_name` value
    InternalName(&'a str),

    /// Export that references another module.
    External {
        /// The `other_module`
        other_module: &'a str,

        /// The `exported_name`
        exported_name: ExportedName<'a>,
    },
}

/// Parses either `internal_name` or `other_module.exported_name`
fn parse_definition_entryname_alias<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, EntrynameAlias<'a>, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>,
{
    let parse_internal_name = parse_string_arg.map(EntrynameAlias::InternalName);

    let parse_external_alias = separated_pair(parse_string_arg, char('.'), parse_exported_name)
        .map(|(other_module, exported_name)| EntrynameAlias::External {
            other_module,
            exported_name,
        });

    parse_external_alias.or(parse_internal_name).parse(input)
}

/// An `exported_name` value from the `other_module.exported_name` argument in
/// an `EXPORTS` definition statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportedName<'a> {
    Name(&'a str),
    Ordinal(u16),
}

/// Parses an exported name from an external export.
fn parse_exported_name<'a, E, X: Clone>(
    input: LocatedSpan<&'a str, X>,
) -> IResult<LocatedSpan<&'a str, X>, ExportedName<'a>, E>
where
    E: ParseError<LocatedSpan<&'a str, X>>,
{
    preceded(char('#'), nom::character::complete::u16)
        .map(ExportedName::Ordinal)
        .or(parse_string_arg.map(ExportedName::Name))
        .parse(input)
}

/// Ordinal value for an export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DefinitionOrdinal {
    /// The ordinal value.
    value: u16,

    /// NONAME option for the export.
    noname: bool,
}

impl DefinitionOrdinal {
    /// The ordinal value
    #[inline]
    pub fn value(&self) -> u16 {
        self.value
    }

    /// If the `NONAME` flag is present for the ordinal
    #[inline]
    pub fn noname(&self) -> bool {
        self.noname
    }
}

impl std::default::Default for DefinitionOrdinal {
    fn default() -> Self {
        Self {
            value: 1,
            noname: false,
        }
    }
}

/// Parses the definition ordinal argument
fn parse_definition_ordinal<I, E>(input: I) -> IResult<I, DefinitionOrdinal, E>
where
    for<'a> I: nom::Input + nom::Offset + AsRef<str> + nom::Compare<&'a str>,
    <I as nom::Input>::Item: nom::AsChar,
    E: ParseError<I> + FromExternalError<I, ParseIntError>,
{
    separated_pair(
        parse_u16_number,
        multispace0,
        terminated(noname_flag, multispace0),
    )
    .map(|(value, noname)| DefinitionOrdinal { value, noname })
    .parse(input)
}

/// Prases the keyword `NONAME`
pub fn parse_noname_keyword<I, E>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
    E: ParseError<I>,
{
    tag("NONAME")(input)
}

/// Recognizes the `NONAME` flag and returns true if it is present or `false`
/// if it is not present.
fn noname_flag<I, E>(input: I) -> IResult<I, bool, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
    E: ParseError<I>,
{
    opt(parse_noname_keyword)
        .map(|noname| noname.is_some())
        .parse(input)
}

/// Export definition attribute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefinitionAttribute {
    /// Export is private
    Private,

    /// Export is a data export
    Data,
}

/// Parses `PRIVATE | DATA`
fn parse_definition_attribute<I, E: ParseError<I>>(input: I) -> IResult<I, DefinitionAttribute, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    private_attribute.or(data_attribute).parse(input)
}

/// Parses the keyword `PRIVATE`
pub fn parse_private_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("PRIVATE")(input)
}

/// Parses `PRIVATE` from an export definition argument
fn private_attribute<I, E: ParseError<I>>(input: I) -> IResult<I, DefinitionAttribute, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    parse_private_keyword
        .map(|_| DefinitionAttribute::Private)
        .parse(input)
}

/// Parses the keyword `DATA`
pub fn parse_data_keyword<I, E: ParseError<I>>(input: I) -> IResult<I, I, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    tag("DATA")(input)
}

/// Parses `DATA` form an export definition argument
fn data_attribute<I, E: ParseError<I>>(input: I) -> IResult<I, DefinitionAttribute, E>
where
    for<'a> I: nom::Input + nom::Compare<&'a str>,
{
    parse_data_keyword
        .map(|_| DefinitionAttribute::Data)
        .parse(input)
}

#[cfg(test)]
mod tests {
    use nom::Finish;
    use nom_locate::LocatedSpan;

    use crate::exports::{
        DefinitionAttribute, DefinitionOrdinal, EntrynameAlias, ExportedName, ExportsDefinition,
        ExportsStatement, parse_exports_definition, parse_exports_statement,
    };

    #[test]
    fn single_export() {
        let data = "EXPORTS foo";

        let (_, stmt) = parse_exports_statement::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            ExportsStatement {
                definitions: vec![ExportsDefinition {
                    entryname: "foo",
                    ..Default::default()
                }]
            }
        );
    }

    #[test]
    fn multiple_exports() {
        let data = r#"EXPORTS
            foo
            bar"#;

        let (_, stmt) = parse_exports_statement::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            ExportsStatement {
                definitions: vec![
                    ExportsDefinition {
                        entryname: "foo",
                        ..Default::default()
                    },
                    ExportsDefinition {
                        entryname: "bar",
                        ..Default::default()
                    },
                ],
            }
        );
    }

    #[test]
    fn definition_internal_alias() {
        let data = "func2=func1";

        let (_, stmt) = parse_exports_definition::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            ExportsDefinition {
                entryname: "func2",
                entryname_alias: Some(EntrynameAlias::InternalName("func1")),
                ..Default::default()
            }
        );
    }

    #[test]
    fn definition_external_alias() {
        let data = "func2=other_module.func1";

        let (_, stmt) = parse_exports_definition::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            ExportsDefinition {
                entryname: "func2",
                entryname_alias: Some(EntrynameAlias::External {
                    other_module: "other_module",
                    exported_name: ExportedName::Name("func1")
                }),
                ..Default::default()
            }
        );
    }

    #[test]
    fn definition_alias_ordinal() {
        let data = "func2=other_module.#42";

        let (_, stmt) = parse_exports_definition::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            ExportsDefinition {
                entryname: "func2",
                entryname_alias: Some(EntrynameAlias::External {
                    other_module: "other_module",
                    exported_name: ExportedName::Ordinal(42)
                }),
                ..Default::default()
            },
        );
    }

    #[test]
    fn alias_whitespace() {
        let data = r#"EXPORTS
            foo= bar
            foo =bar
            foo = bar
            foo  =  bar
            foo = module.bar
            foo = module.#1
            "#;

        let (_, stmt) = parse_exports_statement::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            ExportsStatement {
                definitions: vec![
                    ExportsDefinition {
                        entryname: "foo",
                        entryname_alias: Some(EntrynameAlias::InternalName("bar")),
                        ..Default::default()
                    },
                    ExportsDefinition {
                        entryname: "foo",
                        entryname_alias: Some(EntrynameAlias::InternalName("bar")),
                        ..Default::default()
                    },
                    ExportsDefinition {
                        entryname: "foo",
                        entryname_alias: Some(EntrynameAlias::InternalName("bar")),
                        ..Default::default()
                    },
                    ExportsDefinition {
                        entryname: "foo",
                        entryname_alias: Some(EntrynameAlias::InternalName("bar")),
                        ..Default::default()
                    },
                    ExportsDefinition {
                        entryname: "foo",
                        entryname_alias: Some(EntrynameAlias::External {
                            other_module: "module",
                            exported_name: ExportedName::Name("bar")
                        }),
                        ..Default::default()
                    },
                    ExportsDefinition {
                        entryname: "foo",
                        entryname_alias: Some(EntrynameAlias::External {
                            other_module: "module",
                            exported_name: ExportedName::Ordinal(1)
                        }),
                        ..Default::default()
                    },
                ]
            }
        );
    }

    #[test]
    fn definition_alias_data() {
        let data = "foo = bar      DATA";

        let (_, stmt) = parse_exports_definition::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            ExportsDefinition {
                entryname: "foo",
                entryname_alias: Some(EntrynameAlias::InternalName("bar")),
                attribute: Some(DefinitionAttribute::Data),
                ..Default::default()
            },
        );
    }

    #[test]
    fn definition_ordinal() {
        let data = "foo @1";

        let (_, stmt) = parse_exports_definition::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            ExportsDefinition {
                entryname: "foo",
                ordinal: Some(DefinitionOrdinal {
                    value: 1,
                    noname: false
                }),
                ..Default::default()
            }
        );
    }

    #[test]
    fn data_export() {
        let data = "EXPORTS exported_global DATA";

        let (_, stmt) = parse_exports_statement::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            ExportsStatement {
                definitions: vec![ExportsDefinition {
                    entryname: "exported_global",
                    attribute: Some(DefinitionAttribute::Data),
                    ..Default::default()
                }],
            }
        );
    }

    #[test]
    fn docs_example() {
        let data = r#"EXPORTS
  DllCanUnloadNow      @1          PRIVATE
  DllWindowName = WindowName       DATA
  DllGetClassObject    @4 NONAME   PRIVATE
  DllRegisterServer    @7
  DllUnregisterServer
        "#;

        let (_, stmt) = parse_exports_statement::<nom::error::Error<_>, _>(LocatedSpan::new(data))
            .finish()
            .expect("Could not parse data");

        assert_eq!(
            stmt,
            ExportsStatement {
                definitions: vec![
                    ExportsDefinition {
                        entryname: "DllCanUnloadNow",
                        ordinal: Some(DefinitionOrdinal {
                            value: 1,
                            noname: false,
                        }),
                        attribute: Some(DefinitionAttribute::Private),
                        ..Default::default()
                    },
                    ExportsDefinition {
                        entryname: "DllWindowName",
                        entryname_alias: Some(EntrynameAlias::InternalName("WindowName")),
                        attribute: Some(DefinitionAttribute::Data),
                        ..Default::default()
                    },
                    ExportsDefinition {
                        entryname: "DllGetClassObject",
                        ordinal: Some(DefinitionOrdinal {
                            value: 4,
                            noname: true
                        }),
                        attribute: Some(DefinitionAttribute::Private),
                        ..Default::default()
                    },
                    ExportsDefinition {
                        entryname: "DllRegisterServer",
                        ordinal: Some(DefinitionOrdinal {
                            value: 7,
                            noname: false
                        }),
                        ..Default::default()
                    },
                    ExportsDefinition {
                        entryname: "DllUnregisterServer",
                        ..Default::default()
                    }
                ],
            }
        );
    }
}
