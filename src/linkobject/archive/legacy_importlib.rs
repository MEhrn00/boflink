use std::ffi::CStr;

use object::{
    Object, ObjectSection, ObjectSymbol,
    coff::{CoffFile, ImageSymbol},
    pe::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SYM_CLASS_EXTERNAL},
};

use crate::linkobject::import::{ImportName, ImportType};

use super::error::{
    LegacyImportHeadMemberParseError, LegacyImportSymbolMemberParseError,
    LegacyImportTailMemberParseError,
};

const ILT64_ORDINAL_BIT_SHIFT: u64 = 63;
const ILT32_ORDINAL_BIT_SHIFT: u32 = 31;

const ILT_ORDINAL_NUMBER_MASK: u64 = 0xffff;

/// A parsed legacy import library member for a symbol.
pub struct LegacyImportSymbolMember<'a> {
    /// The public symbol name.
    pub public_symbol: &'a str,

    /// The name to import the symbol as.
    pub import_name: ImportName<'a>,

    /// The type of import.
    pub typ: ImportType,

    /// The name of the head symbol.
    pub head_symbol: &'a str,
}

impl<'a> LegacyImportSymbolMember<'a> {
    pub fn parse(
        coff: &CoffFile<'a>,
    ) -> Result<LegacyImportSymbolMember<'a>, LegacyImportSymbolMemberParseError> {
        if coff.coff_section_table().len() > 7 {
            return Err(LegacyImportSymbolMemberParseError::Invalid);
        }

        // This is the first '.idata' section after the .text, .data and .bss
        // sections. Use this as a smoke test to check if the COFF is valid.
        if coff.section_by_name(".idata$7").is_none() {
            return Err(LegacyImportSymbolMemberParseError::Invalid);
        }

        // Get the ILT for the import.
        let ilt_section = coff
            .section_by_name(".idata$4")
            .ok_or(LegacyImportSymbolMemberParseError::IltMissing)?;

        let ilt_data = ilt_section.data()?;

        let ilt = if coff.is_64() {
            u64::from_le_bytes(
                ilt_data[..8]
                    .try_into()
                    .map_err(|_| LegacyImportSymbolMemberParseError::IltMalformed)?,
            )
        } else {
            u32::from_le_bytes(
                ilt_data[..4]
                    .try_into()
                    .map_err(|_| LegacyImportSymbolMemberParseError::IltMalformed)?,
            )
            .into()
        };

        // Extract out the import name from the ILT
        let import_name = if (coff.is_64() && (ilt & (1 << ILT64_ORDINAL_BIT_SHIFT) != 0))
            || (!coff.is_64() && (ilt & (1 << ILT32_ORDINAL_BIT_SHIFT) != 0))
        {
            ImportName::Ordinal((ilt & ILT_ORDINAL_NUMBER_MASK) as u16)
        } else {
            let name_section = coff
                .section_by_name(".idata$6")
                .ok_or(LegacyImportSymbolMemberParseError::MissingIltNameSection)?;
            let name_data = name_section.data()?;

            let name_bytes = name_data
                .get(2..)
                .ok_or(LegacyImportSymbolMemberParseError::IltNameMalformed)?;

            let name = CStr::from_bytes_until_nul(name_bytes)
                .map(|name| name.to_str())
                .unwrap_or_else(|_| std::str::from_utf8(name_bytes))
                .map_err(LegacyImportSymbolMemberParseError::ImportName)?;

            ImportName::Name(name)
        };

        // Grab the IAT symbol.
        let iat_symbol = coff
            .symbols()
            .filter(|symbol| symbol.coff_symbol().storage_class() == IMAGE_SYM_CLASS_EXTERNAL)
            .find(|symbol| {
                symbol
                    .section_index()
                    .and_then(|section_idx| coff.section_by_index(section_idx).ok())
                    .and_then(|section| section.name().ok())
                    .is_some_and(|section_name| section_name.starts_with(".idata$"))
            })
            .ok_or(LegacyImportSymbolMemberParseError::MissingIatSymbol)?;

        let iat_section = coff
            .section_by_index(
                iat_symbol
                    .section_index()
                    .unwrap_or_else(|| unreachable!("IAT symbol should be defined in a section")),
            )
            .unwrap_or_else(|_| unreachable!("IAT symbol section is out of bounds"));

        let public_symbol = iat_symbol.name()?.trim_start_matches("__imp_");

        let mut typ = ImportType::Data;

        // Find the import type by searching for a thunk section with a relocation
        // to the IAT
        'sections: for section in coff.sections() {
            let section_name = match section.name() {
                Ok(name) => name,
                Err(_) => continue,
            };

            if section_name.starts_with(".idata$") {
                continue;
            }

            for reloc in section.coff_relocations().into_iter().flatten() {
                let reloc_symbol = match coff.symbol_by_index(reloc.symbol()) {
                    Ok(reloc_symbol) => reloc_symbol,
                    Err(_) => continue,
                };

                if reloc_symbol
                    .section_index()
                    .is_some_and(|reloc_section| reloc_section == iat_section.index())
                {
                    let characteristics = section
                        .coff_section()
                        .characteristics
                        .get(object::LittleEndian);

                    if characteristics & IMAGE_SCN_CNT_CODE != 0 {
                        typ = ImportType::Code;
                    } else if characteristics & IMAGE_SCN_MEM_READ != 0
                        && characteristics & IMAGE_SCN_MEM_WRITE == 0
                    {
                        typ = ImportType::Const;
                    }

                    break 'sections;
                }
            }
        }

        let head_symbol = coff
            .symbols()
            .filter(|symbol| symbol.coff_symbol().storage_class() == IMAGE_SYM_CLASS_EXTERNAL)
            .find_map(|symbol| symbol.is_undefined().then(|| symbol.name().ok()).flatten())
            .ok_or(LegacyImportSymbolMemberParseError::MissingHeadSymbol)?;

        Ok(LegacyImportSymbolMember {
            public_symbol,
            typ,
            import_name,
            head_symbol,
        })
    }
}

/// The parsed head member for a legacy import library.
pub struct LegacyImportHeadMember<'a> {
    /// The name of the '*_iname' symbol for the tail COFF.
    pub tail_symbol: &'a str,
}

impl<'a> LegacyImportHeadMember<'a> {
    pub fn parse(
        coff: &CoffFile<'a>,
    ) -> Result<LegacyImportHeadMember<'a>, LegacyImportHeadMemberParseError> {
        if coff.coff_section_table().len() > 6 {
            return Err(LegacyImportHeadMemberParseError::Invalid);
        }

        // This is the first '.idata' section after the .text, .data and .bss
        // sections. Use this as a smoke test to check if the COFF is valid.
        if coff.section_by_name(".idata$2").is_none() {
            return Err(LegacyImportHeadMemberParseError::Invalid);
        }

        for symbol in coff
            .symbols()
            .filter(|symbol| symbol.is_global() && symbol.is_undefined())
        {
            let symbol_name = symbol.name()?;
            if symbol_name.ends_with("_iname") {
                return Ok(LegacyImportHeadMember {
                    tail_symbol: symbol_name,
                });
            }
        }

        Err(LegacyImportHeadMemberParseError::MissingInameSymbol)
    }
}

/// The tail member for a legacy import library.
pub struct LegacyImportTailMember<'a> {
    /// The DLL name contained in the COFF.
    pub dll: &'a str,
}

impl<'a> LegacyImportTailMember<'a> {
    pub fn parse(
        coff: &CoffFile<'a>,
    ) -> Result<LegacyImportTailMember<'a>, LegacyImportTailMemberParseError> {
        if coff.coff_section_table().len() > 6 {
            return Err(LegacyImportTailMemberParseError::Invalid);
        }

        // This is the first '.idata' section after the .text, .data and .bss
        // sections. Use it as a smoke test to check if the COFF is valid.
        if coff.section_by_name(".idata$4").is_none() {
            return Err(LegacyImportTailMemberParseError::Invalid);
        }

        for symbol in coff
            .symbols()
            .filter(|symbol| symbol.is_global() && symbol.is_definition())
        {
            let symbol_name = symbol.name()?;
            if symbol_name.ends_with("_iname") {
                let iname_section = match symbol.section() {
                    object::SymbolSection::Section(section_idx) => {
                        coff.section_by_index(section_idx)?
                    }
                    _ => return Err(LegacyImportTailMemberParseError::InameSectionInvalid),
                };

                if iname_section.name()? != ".idata$7" {
                    return Err(LegacyImportTailMemberParseError::InameSectionInvalid);
                }

                let iname_data = iname_section.data()?;
                let dll = CStr::from_bytes_until_nul(iname_data)
                    .map(|name| name.to_str())
                    .unwrap_or_else(|_| std::str::from_utf8(iname_data))
                    .map_err(LegacyImportTailMemberParseError::DllName)?;

                return Ok(LegacyImportTailMember { dll });
            }
        }

        Err(LegacyImportTailMemberParseError::MissingInameSymbol)
    }
}
