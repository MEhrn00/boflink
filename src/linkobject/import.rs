use std::str::Utf8Error;

use anyhow::Context;
use object::{Architecture, pe::IMAGE_FILE_MACHINE_UNKNOWN};

/// An exported name from a DLL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportName<'a> {
    /// The symbol is exported by the ordinal value.
    Ordinal(u16),

    /// The symbol is exported by the symbol name.
    Name(&'a str),
}

impl<'a> TryFrom<object::read::coff::ImportName<'a>> for ImportName<'a> {
    type Error = Utf8Error;

    fn try_from(value: object::read::coff::ImportName<'a>) -> Result<Self, Self::Error> {
        Ok(match value {
            object::coff::ImportName::Ordinal(o) => Self::Ordinal(o),
            object::coff::ImportName::Name(name) => Self::Name(std::str::from_utf8(name)?),
        })
    }
}

/// The type of symbol being imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportType {
    /// The symbol is for executable code.
    Code,

    /// The symbol is for misc data.
    Data,

    /// The symbol is a constant value.
    Const,
}

impl From<object::read::coff::ImportType> for ImportType {
    fn from(value: object::read::coff::ImportType) -> Self {
        match value {
            object::coff::ImportType::Code => Self::Const,
            object::coff::ImportType::Data => Self::Data,
            object::coff::ImportType::Const => Self::Const,
        }
    }
}

/// A short import COFF member from import libraries.
#[derive(Debug, Clone)]
pub struct ImportMember<'a> {
    /// The architecture for the import.
    pub(crate) architecture: Architecture,

    /// The public symbol name.
    pub(crate) symbol: &'a str,

    /// The name of the DLL the symbol is from.
    pub(crate) dll: &'a str,

    /// The name exported from the DLL.
    pub(crate) import: ImportName<'a>,

    /// The type of import.
    pub(crate) typ: ImportType,
}

impl<'a> std::default::Default for ImportMember<'a> {
    fn default() -> Self {
        Self {
            architecture: Architecture::Unknown,
            symbol: "",
            dll: "",
            import: ImportName::Ordinal(0),
            typ: ImportType::Code,
        }
    }
}

impl<'a> TryFrom<object::read::coff::ImportFile<'a>> for ImportMember<'a> {
    type Error = anyhow::Error;

    fn try_from(value: object::read::coff::ImportFile<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            architecture: value.architecture(),
            symbol: std::str::from_utf8(value.symbol())
                .context("symbol field value could not be parsed")?,
            dll: std::str::from_utf8(value.dll()).context("DLL field value could not be parsed")?,
            import: value
                .import()
                .try_into()
                .context("import field value could not be parsed")?,
            typ: value.import_type().into(),
        })
    }
}

pub fn object_is_import_file(data: impl AsRef<[u8]>) -> bool {
    use std::mem::size_of_val;

    data.as_ref()
        .get(..size_of_val(&IMAGE_FILE_MACHINE_UNKNOWN))
        .is_some_and(|magic| magic == IMAGE_FILE_MACHINE_UNKNOWN.to_le_bytes())
}
