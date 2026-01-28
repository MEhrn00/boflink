mod beaconapi;

use std::{collections::HashMap, path::Path};

use typed_arena::Arena;

use crate::{
    linker::LinkerTargetArch,
    linkobject::{
        archive::{ArchiveMemberError, ArchiveSymbolError, LinkArchive, LinkArchiveMemberVariant},
        import::ImportMember,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum ApiSymbolsError {
    #[error("{0}")]
    Symbol(#[from] ArchiveSymbolError),

    #[error("{0}")]
    Member(#[from] ArchiveMemberError),
}

pub struct ApiSymbols<'a> {
    /// The custom API archive path if these symbols are from a custom API.
    archive_path: &'a Path,

    /// The symbols
    symbols: HashMap<&'a str, ImportMember<'a>>,
}

impl<'a> ApiSymbols<'a> {
    /// Creates a new [`ApiSymbols`] but using the Beacon API symbols.
    pub fn beacon(strings: &'a Arena<u8>, architecture: LinkerTargetArch) -> ApiSymbols<'a> {
        ApiSymbols {
            archive_path: Path::new("BEACONAPI"),
            symbols: beaconapi::symbols(strings, architecture),
        }
    }

    /// Returns the archive path for the API symbols.
    pub fn archive_path(&self) -> &'a Path {
        self.archive_path
    }

    /// Creates a new [`ApiSymbols`] from a [`LinkArchive`].
    pub fn new(
        path: &'a Path,
        archive: LinkArchive<'a>,
    ) -> Result<ApiSymbols<'a>, ApiSymbolsError> {
        let symbol_iter = archive.symbols();

        let symbol_count = symbol_iter.size_hint();
        let mut symbols = HashMap::with_capacity(symbol_count.1.unwrap_or(symbol_count.0));

        for symbol in symbol_iter {
            let symbol = symbol?;
            let (_, member) = symbol.extract()?;

            match member {
                LinkArchiveMemberVariant::Import(import_member) => {
                    symbols.insert(symbol.name(), import_member);
                }
                LinkArchiveMemberVariant::Coff(_) => {}
            }
        }

        Ok(ApiSymbols {
            archive_path: path,
            symbols,
        })
    }

    /// Gets the [`ImportMember`] associated with the specified symbol.
    pub fn get(&self, symbol: impl AsRef<str>) -> Option<&ImportMember<'a>> {
        self.symbols.get(symbol.as_ref())
    }
}
