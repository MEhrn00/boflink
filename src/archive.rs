use std::{cell::RefCell, collections::BTreeMap, path::Path};

use anyhow::{Context, anyhow, bail};
use indexmap::IndexMap;
use object::{
    Architecture, Object, ObjectSection, ObjectSymbol, SymbolSection,
    coff::CoffFile,
    pe::IMAGE_SCN_CNT_CODE,
    read::archive::{
        ArchiveFile, ArchiveMember, ArchiveMemberIterator, ArchiveOffset, ArchiveSymbol,
        ArchiveSymbolIterator,
    },
};

use std::ffi::CStr;

use crate::coff::{ImportFile, ImportName, ImportType, object_is_import_file};

/// A parsed archive file for linking.
pub struct LinkArchive<'a> {
    /// The parsed archive file
    archive_file: ArchiveFile<'a>,

    /// The cached archive symbol table.
    symbol_cache: RefCell<CachedSymbolMap<'a>>,

    /// Map of legacy import member '_head_*' symbols to the associated
    /// library names.
    legacy_imports: RefCell<BTreeMap<&'a str, &'a str>>,

    /// The archive file data.
    archive_data: &'a [u8],
}

impl<'a> LinkArchive<'a> {
    /// Parses the data.
    pub fn parse(data: &'a [u8]) -> anyhow::Result<LinkArchive<'a>> {
        let archive_file = ArchiveFile::parse(data)?;

        if archive_file.is_thin() {
            bail!("thin archives are not supported");
        }

        let symbols = archive_file
            .symbols()?
            .context("archive is missing a symbol table")?;
        let symbol_count = symbols
            .size_hint()
            .1
            .unwrap_or_else(|| symbols.clone().count());

        Ok(Self {
            archive_file,
            symbol_cache: RefCell::new(CachedSymbolMap {
                cache: IndexMap::with_capacity(symbol_count),
                iter: Some(symbols),
            }),
            legacy_imports: RefCell::new(BTreeMap::new()),
            archive_data: data,
        })
    }

    /// Extracts the archive member that contains a definition for the
    /// specified symbol.
    pub fn extract_symbol(
        &self,
        symbol: &'a str,
    ) -> anyhow::Result<Option<(&'a Path, LinkArchiveMemberVariant<'a>)>> {
        let extracted = self.extract_archive_symbol(symbol)?;
        if let Some(member) = extracted {
            let member_name = std::str::from_utf8(member.name()).context("archive member name")?;

            Ok(Some(
                self.parse_archive_member(&member, member_name)
                    .with_context(|| format!("archive member '{member_name}'"))?,
            ))
        } else {
            Ok(None)
        }
    }

    /// Returns an iterator over the archive symbols.
    ///
    /// This iterator bypasses the internal symbol cache used in
    /// [`LinkArchive::extract_symbol`].
    pub fn symbols(&self) -> LinkArchiveSymbolsIterator<'_, 'a> {
        LinkArchiveSymbolsIterator {
            archive: self,
            iter: self.archive_file.symbols()
                .unwrap_or_else(|e| unreachable!("Archive file symbol map validity should have been checked in LinkArchive::parse ({e:?})"))
                .unwrap_or_else(|| unreachable!("Archive file symbol map existence should have been checked in LinkArchive::parse")),
        }
    }

    /// Returns an iterator over the archive COFF members.
    pub fn coff_members(&self) -> LinkArchiveCoffMembersIterator<'_, 'a> {
        LinkArchiveCoffMembersIterator {
            archive: self,
            iter: self.archive_file.members(),
        }
    }

    /// Parses a generic [`ArchiveMember`] into a [`LinkArchiveMemberVariant`].
    fn parse_archive_member(
        &self,
        member: &ArchiveMember<'a>,
        member_name: &'a str,
    ) -> anyhow::Result<(&'a Path, LinkArchiveMemberVariant<'a>)> {
        let member_data = member.data(self.archive_data)?;

        let member_path = Path::new(member_name);

        if object_is_import_file(member_data) {
            Ok((
                member_path,
                LinkArchiveMemberVariant::Import(ImportFile::parse(member_data)?),
            ))
        } else {
            let coff: CoffFile = CoffFile::parse(member_data)?;

            if LegacyImportSymbolMember::check(&coff) {
                self.parse_legacy_import(member_name, &coff)
                    .map(|member| (member_path, LinkArchiveMemberVariant::Import(member)))
            } else {
                Ok((member_path, LinkArchiveMemberVariant::Coff(coff)))
            }
        }
    }

    /// Parses a COFF from the archive as a legacy import symbol member.
    fn parse_legacy_import(
        &self,
        member_name: &str,
        coff: &CoffFile<'a>,
    ) -> anyhow::Result<ImportFile<'a>> {
        let member_path = Path::new(member_name);

        // Parse this COFF as a symbol member
        let mut symbol_member = LegacyImportSymbolMember::parse(coff)?;

        // Attach the DLL name to the import member. If the DLL name does
        // not exist in the cache, search for it in the archive.
        let mut imports_cache = self.legacy_imports.borrow_mut();
        symbol_member.import.dll = match imports_cache.entry(symbol_member.head_symbol) {
            std::collections::btree_map::Entry::Occupied(dll_entry) => *dll_entry.get(),
            std::collections::btree_map::Entry::Vacant(dll_entry) => {
                // Get the head COFF for this symbol import member
                let head_coff_member = self
                    .extract_archive_symbol(symbol_member.head_symbol)
                    .with_context(|| format!("extracting symbol '{}'", symbol_member.head_symbol))?
                    .with_context(|| {
                        format!(
                            "legacy import library is missing symbol '{}'",
                            symbol_member.head_symbol
                        )
                    })?;

                let head_coff_data = head_coff_member
                    .data(self.archive_data)
                    .with_context(|| format!("archive member {}", member_path.display()))?;

                let head_coff: CoffFile = CoffFile::parse(head_coff_data)
                    .with_context(|| format!("archive member {}", member_path.display()))?;

                let legacy_head_member = LegacyImportHeadMember::parse(&head_coff)
                    .with_context(|| format!("archive member {}", member_path.display()))?;

                // Get the tail COFF for the head member.
                let tail_coff_member = self
                    .extract_archive_symbol(legacy_head_member.tail_symbol)
                    .with_context(|| {
                        format!("extracting symbol '{}'", legacy_head_member.tail_symbol)
                    })?
                    .with_context(|| {
                        format!(
                            "legacy import library is missing symbol '{}'",
                            legacy_head_member.tail_symbol
                        )
                    })?;

                let member_name = Path::new(
                    std::str::from_utf8(tail_coff_member.name())
                        .map_err(|_| anyhow!("archive member name is not a valid utf8 string"))?,
                );

                let tail_coff_data = tail_coff_member
                    .data(self.archive_data)
                    .with_context(|| format!("archive member {}", member_name.display()))?;

                let tail_coff: CoffFile = CoffFile::parse(tail_coff_data)
                    .with_context(|| format!("archive member {}", member_name.display()))?;

                let legacy_tail_member = LegacyImportTailMember::parse(&tail_coff)
                    .with_context(|| format!("archive member {}", member_name.display()))?;

                // Store the mapping from the '_head' symbol found
                // in the symbol COFF to the DLL name found in the
                // '_iname' tail COFF.
                dll_entry.insert(legacy_tail_member.dll)
            }
        };

        Ok(symbol_member.import)
    }

    /// Extracts the [`ArchiveMember`] that contains a definition for `symbol`.
    fn extract_archive_symbol(&self, symbol: &'a str) -> anyhow::Result<Option<ArchiveMember<'a>>> {
        let mut symbol_map = self.symbol_cache.borrow_mut();
        let member_idx = match symbol_map.find_symbol(symbol) {
            Some(offset) => offset,
            None => return Ok(None),
        };

        Ok(Some(self.archive_file.member(member_idx)?))
    }
}

/// Iterator over the [`LinkArchive`] COFF members.
pub struct LinkArchiveCoffMembersIterator<'b, 'a> {
    archive: &'b LinkArchive<'a>,
    iter: ArchiveMemberIterator<'a>,
}

impl<'b, 'a> Iterator for LinkArchiveCoffMembersIterator<'b, 'a> {
    type Item = anyhow::Result<(&'a Path, CoffFile<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        for member in self.iter.by_ref() {
            let member = match member {
                Ok(member) => member,
                Err(e) => return Some(Err(e.into())),
            };

            let member_name = match std::str::from_utf8(member.name()) {
                Ok(member_name) => member_name,
                Err(e) => return Some(Err(e.into())),
            };

            let (member_path, member) =
                match self.archive.parse_archive_member(&member, member_name) {
                    Ok(parsed) => parsed,
                    Err(e) => return Some(Err(anyhow!("archive member {}: {e}", member_name))),
                };

            if let LinkArchiveMemberVariant::Coff(coff) = member {
                return Some(Ok((member_path, coff)));
            }
        }

        None
    }
}

/// Iterator over the [`LinkArchive`] symbols.
pub struct LinkArchiveSymbolsIterator<'b, 'a> {
    /// Reference to the archive
    archive: &'b LinkArchive<'a>,

    /// The symbol iterator
    iter: ArchiveSymbolIterator<'a>,
}

impl<'b, 'a> Iterator for LinkArchiveSymbolsIterator<'b, 'a> {
    type Item = anyhow::Result<LinkArchiveSymbol<'b, 'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let symbol = self.iter.next()?.map_err(anyhow::Error::new);

        Some(symbol.and_then(
            |symbol: ArchiveSymbol<'a>| -> anyhow::Result<LinkArchiveSymbol> {
                Ok(LinkArchiveSymbol {
                    archive: self.archive,
                    name: std::str::from_utf8(symbol.name())?,
                    offset: symbol.offset(),
                })
            },
        ))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

/// A symbol from the [`LinkArchive`] symbol map.
pub struct LinkArchiveSymbol<'b, 'a> {
    /// Reference to the archive
    archive: &'b LinkArchive<'a>,

    /// The name of the symbol
    name: &'a str,

    /// The archive offset for the member which holds this symbol
    offset: ArchiveOffset,
}

impl<'b, 'a> LinkArchiveSymbol<'b, 'a> {
    /// Returns the symbol name.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Extracts the archive member for this symbol.
    pub fn extract(&self) -> anyhow::Result<(&'a Path, LinkArchiveMemberVariant<'a>)> {
        let member = self
            .archive
            .archive_file
            .member(self.offset)
            .map_err(anyhow::Error::new)?;

        let member_name = std::str::from_utf8(member.name())?;
        self.archive.parse_archive_member(&member, member_name)
    }
}

pub enum LinkArchiveMemberVariant<'a> {
    Coff(CoffFile<'a>),
    Import(ImportFile<'a>),
}

/// The archive symbol map iterator with caching.
struct CachedSymbolMap<'a> {
    cache: IndexMap<&'a str, ArchiveOffset>,
    iter: Option<ArchiveSymbolIterator<'a>>,
}

impl CachedSymbolMap<'_> {
    fn find_symbol(&mut self, symbol: &str) -> Option<ArchiveOffset> {
        if let Some(found) = self.cache.get(symbol).copied() {
            return Some(found);
        }

        for archive_symbol in self.iter.iter_mut().flatten().flatten() {
            let archive_symbol_name = match std::str::from_utf8(archive_symbol.name()) {
                Ok(name) => name,
                Err(_) => continue,
            };

            self.cache
                .insert(archive_symbol_name, archive_symbol.offset());
            if archive_symbol_name == symbol {
                return Some(archive_symbol.offset());
            }
        }

        None
    }
}

/// A parsed legacy import library member for a symbol.
pub struct LegacyImportSymbolMember<'a> {
    /// The partiall built import file member.
    ///
    /// The dll portion is missing and lookup for the import tail
    pub import: ImportFile<'a>,

    /// The name of the head symbol which links this legacy import library
    /// symbol member to the import directory entry.
    pub head_symbol: &'a str,
}

impl<'a> LegacyImportSymbolMember<'a> {
    /// Checks if the passed in COFF is a symbol member for a legacy import library
    pub fn check(coff: &CoffFile<'a>) -> bool {
        if coff.coff_section_table().len() <= 10 {
            let mut have_iat_section = false;
            let mut have_hintname_section = false;
            for section in coff.sections() {
                if let Ok(name) = section.name() {
                    if name == ".idata$5" {
                        have_iat_section = true;
                    } else if name == ".idata$6" {
                        have_hintname_section = true;
                    }
                }

                if have_iat_section && have_hintname_section {
                    return true;
                }
            }
        }

        false
    }
    pub fn parse(coff: &CoffFile<'a>) -> anyhow::Result<LegacyImportSymbolMember<'a>> {
        if coff.coff_section_table().len() > 10 {
            bail!("COFF is not a legacy import symbol member");
        }

        // Check for IAT (.idata$5) and Hint/Name table (.idata$6)
        let mut have_iat_section = false;
        let mut have_hintname_section = false;
        for section in coff.sections() {
            if have_iat_section && have_hintname_section {
                break;
            }

            let name = section.name()?;
            if name == ".idata$5" {
                have_iat_section = true;
            } else if name == ".idata$6" {
                have_hintname_section = true;
            }
        }

        // If there is no IAT and Hint/Name table, this is not an import COFF
        if !(have_iat_section && have_hintname_section) {
            bail!("COFF has no IAT or hint name section");
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

        let import_symbol =
            import_symbol.context("import address table entry is missing or malformed")?;

        let mut import = ImportFile {
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
            head_symbol: head_symbol.context("'_head_*' symbol is missing")?.name()?,
        })
    }
}

/// The parsed head member for a legacy import library.
pub struct LegacyImportHeadMember<'a> {
    /// The name of the '*_iname' symbol for the tail COFF.
    pub tail_symbol: &'a str,
}

impl<'a> LegacyImportHeadMember<'a> {
    pub fn parse(coff: &CoffFile<'a>) -> anyhow::Result<LegacyImportHeadMember<'a>> {
        if coff.coff_section_table().len() > 6 && coff.section_by_name(".idata$2").is_none() {
            bail!("COFF is not a legacy import library head");
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

        bail!("'*_iname' symbol is missing")
    }
}

/// The tail member for a legacy import library.
pub struct LegacyImportTailMember<'a> {
    /// The DLL name contained in the COFF.
    pub dll: &'a str,
}

impl<'a> LegacyImportTailMember<'a> {
    pub fn parse(coff: &CoffFile<'a>) -> anyhow::Result<LegacyImportTailMember<'a>> {
        if coff.coff_section_table().len() > 6 || coff.section_by_name(".idata$4").is_none() {
            bail!("COFF is not a legacy import library tail");
        }

        for symbol in coff
            .symbols()
            .filter(|symbol| symbol.is_global() && symbol.is_definition())
        {
            let symbol_name = symbol.name()?;
            if symbol_name.ends_with("_iname")
                && let SymbolSection::Section(section_idx) = symbol.section()
                && let iname_section = coff.section_by_index(section_idx)?
                && iname_section.name()? == ".idata$7"
            {
                let iname_data = iname_section.data()?;
                let dll = CStr::from_bytes_until_nul(iname_data)
                    .map(|name| name.to_str())
                    .unwrap_or_else(|_| std::str::from_utf8(iname_data))
                    .map_err(|_| anyhow!("cannot parse '*_iname' symbol DLL name"))?;

                return Ok(LegacyImportTailMember { dll });
            }
        }

        bail!("'*_iname' symbol for tail member is missing")
    }
}
