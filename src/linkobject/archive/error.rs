use std::path::PathBuf;

use crate::linkobject::import::TryFromImportFileError;

#[derive(Debug, thiserror::Error)]
pub enum LinkArchiveParseError {
    #[error("thin archives are not supported")]
    ThinArchive,

    #[error("archive is missing a symbol table")]
    NoSymbolMap,

    #[error("{0}")]
    Object(#[from] object::read::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractSymbolError {
    #[error("member for symbol does not exist")]
    NotFound,

    #[error("{0}")]
    ArchiveParse(#[from] ArchiveParseError),

    #[error("{0}")]
    MemberParse(#[from] MemberParseError),
}

#[derive(Debug, thiserror::Error)]
pub enum ArchiveMemberError {
    #[error("{0}")]
    ArchiveParse(ArchiveParseError),

    #[error("{0}")]
    MemberParse(MemberParseError),
}

#[derive(Debug, thiserror::Error)]
pub enum ArchiveSymbolError {
    #[error("symbol name is invalid: {0}")]
    Name(std::str::Utf8Error),

    #[error("failed parsing archive file: {0}")]
    Object(object::read::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ArchiveParseError {
    #[error("archive member name is invalid: {0}")]
    MemberName(std::str::Utf8Error),

    #[error("failed parsing archive file: {0}")]
    Object(#[from] object::read::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("could not parse member {}: {kind}", .path.display())]
pub struct MemberParseError {
    pub path: PathBuf,
    pub kind: MemberParseErrorKind,
}

impl MemberParseError {
    pub fn new(
        path: impl Into<PathBuf>,
        kind: impl Into<MemberParseErrorKind>,
    ) -> MemberParseError {
        Self {
            path: path.into(),
            kind: kind.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MemberParseErrorKind {
    #[error("failed parsing legacy import library symbol member: {0}")]
    LegacyImportLibrarySymbolMember(#[from] LegacyImportSymbolMemberParseError),

    #[error("failed parsing legacy import library head member: {0}")]
    LegacyImportLibraryHeadMember(#[from] LegacyImportHeadMemberParseError),

    #[error("failed parsing legacy import library tail member: {0}")]
    LegacyImportLibraryTailMember(#[from] LegacyImportTailMemberParseError),

    #[error("legacy import library is missing symbol '{0}'")]
    LegacyImportLibraryMissingSymbol(String),

    #[error("import library member is invalid: {0}")]
    ImportFile(#[from] TryFromImportFileError),

    #[error("{0}")]
    Object(#[from] object::read::Error),
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum LegacyImportSymbolMemberParseError {
    #[error("COFF is not a valid legacy import library symbol COFF")]
    Invalid,

    #[error("public symbol is missing")]
    MissingPublicSymbol,

    #[error("'_head_*' symbol is missing")]
    MissingHeadSymbol,

    #[error("import address table entry is missing or malformed")]
    Iat,

    #[error("{0}")]
    Object(#[from] object::read::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum LegacyImportHeadMemberParseError {
    #[error("invalid legacy import library head member")]
    Invalid,

    #[error("'*_iname' symbol for the linked tail member is missing")]
    MissingInameSymbol,

    #[error("{0}")]
    Object(#[from] object::read::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum LegacyImportTailMemberParseError {
    #[error("invalid legacy import library tail member COFF")]
    Invalid,

    #[error("'*_iname' symbol is missing")]
    MissingInameSymbol,

    #[error("section with the '*_iname' symbol is not valid")]
    InameSectionInvalid,

    #[error("could not parse DLL name: {0}")]
    DllName(std::str::Utf8Error),

    #[error("{0}")]
    Object(#[from] object::read::Error),
}
