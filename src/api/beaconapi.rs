use std::collections::HashMap;

use crate::{
    linker::LinkerTargetArch,
    linkobject::import::{ImportMember, ImportName, ImportType},
};

const BEACONAPI64_SYMBOLS: &[(&str, &str)] = &[
    ("BeaconAddValue", "__imp_BeaconAddValue"),
    ("BeaconCleanupProcess", "__imp_BeaconCleanupProcess"),
    ("BeaconCloseHandle", "__imp_BeaconCloseHandle"),
    ("BeaconDataExtract", "__imp_BeaconDataExtract"),
    ("BeaconDataInt", "__imp_BeaconDataInt"),
    ("BeaconDataLength", "__imp_BeaconDataLength"),
    ("BeaconDataParse", "__imp_BeaconDataParse"),
    ("BeaconDataPtr", "__imp_BeaconDataPtr"),
    ("BeaconDataShort", "__imp_BeaconDataShort"),
    ("BeaconDataStoreGetItem", "__imp_BeaconDataStoreGetItem"),
    (
        "BeaconDataStoreMaxEntries",
        "__imp_BeaconDataStoreMaxEntries",
    ),
    (
        "BeaconDataStoreProtectItem",
        "__imp_BeaconDataStoreProtectItem",
    ),
    (
        "BeaconDataStoreUnprotectItem",
        "__imp_BeaconDataStoreUnprotectItem",
    ),
    ("BeaconDisableBeaconGate", "__imp_BeaconDisableBeaconGate"),
    ("BeaconDownload", "__imp_BeaconDownload"),
    ("BeaconDuplicateHandle", "__imp_BeaconDuplicateHandle"),
    ("BeaconEnableBeaconGate:", "__imp_BeaconEnableBeaconGate:"),
    ("BeaconFormatAlloc", "__imp_BeaconFormatAlloc"),
    ("BeaconFormatAppend", "__imp_BeaconFormatAppend"),
    ("BeaconFormatFree", "__imp_BeaconFormatFree"),
    ("BeaconFormatInt", "__imp_BeaconFormatInt"),
    ("BeaconFormatPrintf", "__imp_BeaconFormatPrintf"),
    ("BeaconFormatReset", "__imp_BeaconFormatReset"),
    ("BeaconFormatToString", "__imp_BeaconFormatToString"),
    ("BeaconGetCustomUserData", "__imp_BeaconGetCustomUserData"),
    ("BeaconGetSpawnTo", "__imp_BeaconGetSpawnTo"),
    (
        "BeaconGetSyscallInformation",
        "__imp_BeaconGetSyscallInformation",
    ),
    ("BeaconGetThreadContext", "__imp_BeaconGetThreadContext"),
    ("BeaconGetValue", "__imp_BeaconGetValue"),
    ("BeaconInformation", "__imp_BeaconInformation"),
    ("BeaconInjectProcess", "__imp_BeaconInjectProcess"),
    (
        "BeaconInjectTemporaryProcess",
        "__imp_BeaconInjectTemporaryProcess",
    ),
    ("BeaconIsAdmin", "__imp_BeaconIsAdmin"),
    ("BeaconOpenProcess", "__imp_BeaconOpenProcess"),
    ("BeaconOpenThread", "__imp_BeaconOpenThread"),
    ("BeaconOutput", "__imp_BeaconOutput"),
    ("BeaconPrintf", "__imp_BeaconPrintf"),
    ("BeaconReadProcessMemory", "__imp_BeaconReadProcessMemory"),
    ("BeaconRemoveValue", "__imp_BeaconRemoveValue"),
    ("BeaconResumeThread", "__imp_BeaconResumeThread"),
    ("BeaconRevertToken", "__imp_BeaconRevertToken"),
    ("BeaconSetThreadContext", "__imp_BeaconSetThreadContext"),
    (
        "BeaconSpawnTemporaryProcess",
        "__imp_BeaconSpawnTemporaryProcess",
    ),
    ("BeaconUnmapViewOfFile", "__imp_BeaconUnmapViewOfFile"),
    ("BeaconUseToken", "__imp_BeaconUseToken"),
    ("BeaconVirtualAlloc", "__imp_BeaconVirtualAlloc"),
    ("BeaconVirtualAllocEx", "__imp_BeaconVirtualAllocEx"),
    ("BeaconVirtualFree", "__imp_BeaconVirtualFree"),
    ("BeaconVirtualProtect", "__imp_BeaconVirtualProtect"),
    ("BeaconVirtualProtectEx", "__imp_BeaconVirtualProtectEx"),
    ("BeaconVirtualQuery", "__imp_BeaconVirtualQuery"),
    ("BeaconWriteProcessMemory", "__imp_BeaconWriteProcessMemory"),
    ("toWideChar", "__imp_toWideChar"),
];

const BEACONAPI32_SYMBOLS: &[(&str, &str)] = &[
    ("_BeaconAddValue", "__imp__BeaconAddValue"),
    ("_BeaconCleanupProcess", "__imp__BeaconCleanupProcess"),
    ("_BeaconCloseHandle", "__imp__BeaconCloseHandle"),
    ("_BeaconDataExtract", "__imp__BeaconDataExtract"),
    ("_BeaconDataInt", "__imp__BeaconDataInt"),
    ("_BeaconDataLength", "__imp__BeaconDataLength"),
    ("_BeaconDataParse", "__imp__BeaconDataParse"),
    ("_BeaconDataPtr", "__imp__BeaconDataPtr"),
    ("_BeaconDataShort", "__imp__BeaconDataShort"),
    ("_BeaconDataStoreGetItem", "__imp__BeaconDataStoreGetItem"),
    (
        "_BeaconDataStoreMaxEntries",
        "__imp__BeaconDataStoreMaxEntries",
    ),
    (
        "_BeaconDataStoreProtectItem",
        "__imp__BeaconDataStoreProtectItem",
    ),
    (
        "_BeaconDataStoreUnprotectItem",
        "__imp__BeaconDataStoreUnprotectItem",
    ),
    ("_BeaconDisableBeaconGate", "__imp__BeaconDisableBeaconGate"),
    ("_BeaconDownload", "__imp__BeaconDownload"),
    ("_BeaconDuplicateHandle", "__imp__BeaconDuplicateHandle"),
    ("_BeaconEnableBeaconGate:", "__imp__BeaconEnableBeaconGate:"),
    ("_BeaconFormatAlloc", "__imp__BeaconFormatAlloc"),
    ("_BeaconFormatAppend", "__imp__BeaconFormatAppend"),
    ("_BeaconFormatFree", "__imp__BeaconFormatFree"),
    ("_BeaconFormatInt", "__imp__BeaconFormatInt"),
    ("_BeaconFormatPrintf", "__imp__BeaconFormatPrintf"),
    ("_BeaconFormatReset", "__imp__BeaconFormatReset"),
    ("_BeaconFormatToString", "__imp__BeaconFormatToString"),
    ("_BeaconGetCustomUserData", "__imp__BeaconGetCustomUserData"),
    ("_BeaconGetSpawnTo", "__imp__BeaconGetSpawnTo"),
    (
        "_BeaconGetSyscallInformation",
        "__imp__BeaconGetSyscallInformation",
    ),
    ("_BeaconGetThreadContext", "__imp__BeaconGetThreadContext"),
    ("_BeaconGetValue", "__imp__BeaconGetValue"),
    ("_BeaconInformation", "__imp__BeaconInformation"),
    ("_BeaconInjectProcess", "__imp__BeaconInjectProcess"),
    (
        "_BeaconInjectTemporaryProcess",
        "__imp__BeaconInjectTemporaryProcess",
    ),
    ("_BeaconIsAdmin", "__imp__BeaconIsAdmin"),
    ("_BeaconOpenProcess", "__imp__BeaconOpenProcess"),
    ("_BeaconOpenThread", "__imp__BeaconOpenThread"),
    ("_BeaconOutput", "__imp__BeaconOutput"),
    ("_BeaconPrintf", "__imp__BeaconPrintf"),
    ("_BeaconReadProcessMemory", "__imp__BeaconReadProcessMemory"),
    ("_BeaconRemoveValue", "__imp__BeaconRemoveValue"),
    ("_BeaconResumeThread", "__imp__BeaconResumeThread"),
    ("_BeaconRevertToken", "__imp__BeaconRevertToken"),
    ("_BeaconSetThreadContext", "__imp__BeaconSetThreadContext"),
    (
        "_BeaconSpawnTemporaryProcess",
        "__imp__BeaconSpawnTemporaryProcess",
    ),
    ("_BeaconUnmapViewOfFile", "__imp__BeaconUnmapViewOfFile"),
    ("_BeaconUseToken", "__imp__BeaconUseToken"),
    ("_BeaconVirtualAlloc", "__imp__BeaconVirtualAlloc"),
    ("_BeaconVirtualAllocEx", "__imp__BeaconVirtualAllocEx"),
    ("_BeaconVirtualFree", "__imp__BeaconVirtualFree"),
    ("_BeaconVirtualProtect", "__imp__BeaconVirtualProtect"),
    ("_BeaconVirtualProtectEx", "__imp__BeaconVirtualProtectEx"),
    ("_BeaconVirtualQuery", "__imp__BeaconVirtualQuery"),
    (
        "_BeaconWriteProcessMemory",
        "__imp__BeaconWriteProcessMemory",
    ),
    ("_toWideChar", "__imp__toWideChar"),
];

pub fn symbols(architecture: LinkerTargetArch) -> HashMap<&'static str, ImportMember<'static>> {
    let symbol_names = if architecture == LinkerTargetArch::I386 {
        BEACONAPI32_SYMBOLS
    } else {
        BEACONAPI64_SYMBOLS
    };

    let mut symbol_map = HashMap::with_capacity(symbol_names.len() * 2);
    symbol_map.extend(symbol_names.iter().map(|&(symbol, _)| {
        (
            symbol,
            ImportMember {
                architecture: architecture.into(),
                symbol,
                dll: "Beacon API",
                import: ImportName::Name(symbol),
                typ: ImportType::Code,
            },
        )
    }));

    symbol_map.extend(symbol_names.iter().map(|&(symbol, import_symbol)| {
        (
            import_symbol,
            ImportMember {
                architecture: architecture.into(),
                symbol,
                dll: "Beacon API",
                import: ImportName::Name(symbol),
                typ: ImportType::Code,
            },
        )
    }));

    symbol_map
}
