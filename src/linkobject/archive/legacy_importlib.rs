use std::ffi::CStr;

use object::{
    Architecture, Object, ObjectSection, ObjectSymbol, SymbolSection, coff::CoffFile,
    pe::IMAGE_SCN_CNT_CODE,
};

use crate::linkobject::import::{ImportMember, ImportName, ImportType};

use super::error::{
    LegacyImportHeadMemberParseError, LegacyImportSymbolMemberParseError,
    LegacyImportTailMemberParseError,
};

/// A parsed legacy import library member for a symbol.
pub struct LegacyImportSymbolMember<'a> {
    /// The partiall built import file member.
    ///
    /// The dll portion is missing and lookup for the import tail
    pub import: ImportMember<'a>,

    /// The name of the head symbol which links this legacy import library
    /// symbol member to the import directory entry.
    pub head_symbol: &'a str,
}

impl<'a> LegacyImportSymbolMember<'a> {
    pub fn parse(
        coff: &CoffFile<'a>,
    ) -> Result<LegacyImportSymbolMember<'a>, LegacyImportSymbolMemberParseError> {
        if coff.coff_section_table().len() > 7 {
            return Err(LegacyImportSymbolMemberParseError::Invalid);
        }

        // Check for IAT (.idata$5) and Hint/Name table (.idata$6)
        let mut have_iat_section = false;
        let mut have_hintname_section = false;
        for section in coff.sections() {
            let name = section.name()?;
            if name == ".idata$5" {
                have_iat_section = true;
            } else if name == ".idata$6" {
                have_hintname_section = true;
            }
        }

        // If there is no IAT and Hint/Name table, this is not an import COFF
        if !(have_iat_section && have_hintname_section) {
            return Err(LegacyImportSymbolMemberParseError::Invalid);
        }

        let mut thunk_entry = None;
        let mut import_symbol = None;
        let mut head_symbol = None;

        // Scan symbol table for entries
        for symbol in coff.symbols() {
            if symbol.is_local() {
                continue;
            }

            if symbol.is_undefined() && head_symbol.is_none() {
                // Head symbol
                head_symbol = Some(symbol);
            } else if let SymbolSection::Section(section_index) = symbol.section() {
                // Either the import symbol or the thunk symbol
                let section = coff.section_by_index(section_index)?;
                let section_name = section.name()?;

                // Import symbol for the IAT entry
                if section_name == ".idata$5" && import_symbol.is_none() {
                    import_symbol = Some(symbol);
                } else if thunk_entry.is_none() {
                    // Symbol for the import thunk
                    thunk_entry = Some((symbol, section));
                }
            }
        }

        let import_symbol = import_symbol.ok_or(LegacyImportSymbolMemberParseError::Iat)?;

        let mut import = ImportMember {
            architecture: coff.architecture(),
            typ: ImportType::Data,
            ..Default::default()
        };

        if let Some((thunk_symbol, thunk_section)) = thunk_entry {
            // Use the thunk symbol as the public symbol name if found
            import.symbol = thunk_symbol.name()?;

            // Check if the thunk section is a code section and set the import
            // type
            let characteristics = thunk_section
                .coff_section()
                .characteristics
                .get(object::LittleEndian);
            if characteristics & IMAGE_SCN_CNT_CODE != 0 {
                import.typ = ImportType::Code;
            }
        } else {
            // If no thunk was found, use the stripped `__imp_` prefixed import
            // symbol
            import.symbol = import_symbol.name()?;
        }

        // Set the import name to the public symbol name. Remove the i386
        // mangling prefix if the COFF is i386
        import.import = if coff.architecture() == Architecture::I386 {
            ImportName::Name(import.symbol.trim_start_matches('_'))
        } else {
            ImportName::Name(import.symbol)
        };

        Ok(LegacyImportSymbolMember {
            import,
            head_symbol: head_symbol
                .ok_or(LegacyImportSymbolMemberParseError::MissingHeadSymbol)?
                .name()?,
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
