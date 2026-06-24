use std::{collections::HashMap, path::Path};

use bumpalo::Bump;
use object::Architecture;

use crate::{
    coff::{ImportFile, ImportName, ImportType},
    linker::LinkerTargetArch,
    linkobject::archive::{LinkArchive, LinkArchiveMemberVariant},
};

const BEACONAPI_SYMBOLS: &[&str] = &[
    "BeaconAddValue",
    "BeaconCleanupProcess",
    "BeaconCloseHandle",
    "BeaconDataExtract",
    "BeaconDataInt",
    "BeaconDataLength",
    "BeaconDataParse",
    "BeaconDataPtr",
    "BeaconDataShort",
    "BeaconDataStoreAddItem",
    "BeaconDataStoreRemoveItem",
    "BeaconDataStoreGetItem",
    "BeaconDataStoreMaxEntries",
    "BeaconDataStoreProtectItem",
    "BeaconDataStoreUnprotectItem",
    "BeaconDisableBeaconGate",
    "BeaconDownload",
    "BeaconDuplicateHandle",
    "BeaconEnableBeaconGate",
    "BeaconFormatAlloc",
    "BeaconFormatAppend",
    "BeaconFormatFree",
    "BeaconFormatInt",
    "BeaconFormatPrintf",
    "BeaconFormatReset",
    "BeaconFormatToString",
    "BeaconGetCustomUserData",
    "BeaconGetSpawnTo",
    "BeaconGetSyscallInformation",
    "BeaconGetThreadContext",
    "BeaconGetValue",
    "BeaconInformation",
    "BeaconInjectProcess",
    "BeaconInjectTemporaryProcess",
    "BeaconIsAdmin",
    "BeaconOpenProcess",
    "BeaconOpenThread",
    "BeaconOutput",
    "BeaconPrintf",
    "BeaconReadProcessMemory",
    "BeaconRemoveValue",
    "BeaconResumeThread",
    "BeaconRevertToken",
    "BeaconSetThreadContext",
    "BeaconSpawnTemporaryProcess",
    "BeaconUnmapViewOfFile",
    "BeaconUseToken",
    "BeaconVirtualAlloc",
    "BeaconVirtualAllocEx",
    "BeaconVirtualFree",
    "BeaconVirtualProtect",
    "BeaconVirtualProtectEx",
    "BeaconVirtualQuery",
    "BeaconWriteProcessMemory",
    "toWideChar",
];

pub struct ApiSymbols<'a> {
    /// The custom API archive path if these symbols are from a custom API.
    archive_path: &'a Path,

    /// The symbols
    symbols: HashMap<&'a str, ImportFile<'a>>,
}

impl<'a> ApiSymbols<'a> {
    /// Creates a new [`ApiSymbols`] but using the Beacon API symbols.
    pub fn beacon(bump: &'a Bump, architecture: LinkerTargetArch) -> ApiSymbols<'a> {
        let mut symbols = HashMap::with_capacity(BEACONAPI_SYMBOLS.len() * 2);
        let architecture = Architecture::from(architecture);

        if architecture == Architecture::I386 {
            for &name in BEACONAPI_SYMBOLS {
                let mangled = &*bump.alloc_str(&format!("_{name}"));

                // Add plain symbol name
                symbols.insert(mangled, make_import_member(architecture, mangled, name));

                // Add declspec name
                let declspec = &*bump.alloc_str(&format!("__imp_{mangled}"));
                symbols.insert(declspec, make_import_member(architecture, mangled, name));
            }
        } else {
            for &name in BEACONAPI_SYMBOLS {
                // Add plain symbol name
                symbols.insert(name, make_import_member(architecture, name, name));

                // Add declspec names
                let declspec = &*bump.alloc_str(&format!("__imp_{name}"));
                symbols.insert(declspec, make_import_member(architecture, name, name));
            }
        }

        ApiSymbols {
            archive_path: Path::new("BEACONAPI"),
            symbols,
        }
    }

    /// Returns the archive path for the API symbols.
    pub fn archive_path(&self) -> &'a Path {
        self.archive_path
    }

    /// Creates a new [`ApiSymbols`] from a [`LinkArchive`].
    pub fn new(path: &'a Path, archive: LinkArchive<'a>) -> anyhow::Result<ApiSymbols<'a>> {
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
    pub fn get(&self, symbol: impl AsRef<str>) -> Option<&ImportFile<'a>> {
        self.symbols.get(symbol.as_ref())
    }
}

const fn make_import_member<'a>(
    architecture: Architecture,
    symbol: &'a str,
    import_name: &'a str,
) -> ImportFile<'a> {
    ImportFile {
        architecture,
        symbol,
        dll: "Beacon API",
        import: ImportName::Name(import_name),
        typ: ImportType::Code,
    }
}
