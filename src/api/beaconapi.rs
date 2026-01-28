use std::collections::HashMap;

use object::Architecture;
use typed_arena::Arena;

use crate::{
    linker::LinkerTargetArch,
    linkobject::import::{ImportMember, ImportName, ImportType},
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

pub fn symbols<'a>(
    strings: &'a Arena<u8>,
    architecture: LinkerTargetArch,
) -> HashMap<&'a str, ImportMember<'a>> {
    let mut symbol_map = HashMap::with_capacity(BEACONAPI_SYMBOLS.len() * 2);
    let architecture = Architecture::from(architecture);

    if architecture == Architecture::I386 {
        for &name in BEACONAPI_SYMBOLS {
            let mangled = &*strings.alloc_str(&format!("_{name}"));

            // Add plain symbol name
            symbol_map.insert(mangled, make_import_member(architecture, mangled, name));

            // Add declspec name
            let declspec = &*strings.alloc_str(&format!("__imp_{mangled}"));
            symbol_map.insert(declspec, make_import_member(architecture, mangled, name));
        }
    } else {
        for &name in BEACONAPI_SYMBOLS {
            // Add plain symbol name
            symbol_map.insert(name, make_import_member(architecture, name, name));

            // Add declspec names
            let declspec = &*strings.alloc_str(&format!("__imp_{name}"));
            symbol_map.insert(declspec, make_import_member(architecture, name, name));
        }
    }

    symbol_map
}

const fn make_import_member<'a>(
    architecture: Architecture,
    symbol: &'a str,
    import_name: &'a str,
) -> ImportMember<'a> {
    ImportMember {
        architecture,
        symbol,
        dll: "Beacon API",
        import: ImportName::Name(import_name),
        typ: ImportType::Code,
    }
}
