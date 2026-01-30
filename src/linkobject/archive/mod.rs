use std::{cell::RefCell, collections::BTreeMap, path::Path};

use anyhow::{Context, anyhow, bail};
use indexmap::IndexMap;
use object::{
    Object, ObjectSection,
    coff::{CoffFile, ImportFile},
    read::archive::{
        ArchiveFile, ArchiveMember, ArchiveMemberIterator, ArchiveOffset, ArchiveSymbol,
        ArchiveSymbolIterator,
    },
};

use super::import::{ImportMember, object_is_import_file};

use legacy_importlib::{LegacyImportHeadMember, LegacyImportSymbolMember, LegacyImportTailMember};

mod legacy_importlib;

pub enum LinkArchiveMemberVariant<'a> {
    Coff(CoffFile<'a>),
    Import(ImportMember<'a>),
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
            let member_name = std::str::from_utf8(member.name())
                .with_context(|| format!("archive member name"))?;

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

    /// Returns an iterator over the archive members.
    pub fn members(&self) -> LinkArchiveMembersIterator<'_, 'a> {
        LinkArchiveMembersIterator {
            archive: self,
            iter: self.archive_file.members(),
        }
    }

    /// Returns an iterator over the archive COFF members.
    pub fn coff_members(&self) -> LinkArchiveCoffMembersIterator<'_, 'a> {
        LinkArchiveCoffMembersIterator {
            archive: self,
            iter: self.archive_file.members(),
        }
    }

    /// Returns an iterator over the archive import members.
    pub fn import_members(&self) -> LinkArchiveImportMembersIterator<'_, 'a> {
        LinkArchiveImportMembersIterator {
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
                LinkArchiveMemberVariant::Import(ImportFile::parse(member_data)?.try_into()?),
            ))
        } else {
            let coff: CoffFile = CoffFile::parse(member_data)?;

            if coff.coff_section_table().len() < 10
                && coff.sections().any(|section| {
                    section.name().is_ok_and(|name| {
                        name == ".idata$2"
                            || name == ".idata$4"
                            || name == ".idata$5"
                            || name == ".idata$6"
                            || name == ".idata$7"
                    })
                })
            {
                self.parse_legacy_import_member(member_name, &coff)
                    .map(|member| (member_path, LinkArchiveMemberVariant::Import(member)))
            } else {
                Ok((member_path, LinkArchiveMemberVariant::Coff(coff)))
            }
        }
    }

    /// Parses a COFF from the archive as a legacy import symbol member.
    fn parse_legacy_import_member(
        &self,
        member_name: &str,
        coff: &CoffFile<'a>,
    ) -> anyhow::Result<ImportMember<'a>> {
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

/// Iterator over the [`LinkArchive`] members.
pub struct LinkArchiveMembersIterator<'b, 'a> {
    archive: &'b LinkArchive<'a>,
    iter: ArchiveMemberIterator<'a>,
}

impl<'b, 'a> Iterator for LinkArchiveMembersIterator<'b, 'a> {
    type Item = anyhow::Result<(&'a Path, LinkArchiveMemberVariant<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        let member = match self.iter.next()? {
            Ok(member) => member,
            Err(e) => return Some(Err(e.into())),
        };

        let member_name = match std::str::from_utf8(member.name())
            .map_err(|_| anyhow!("archive member name is not a valid utf8 string"))
        {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        Some(self.archive.parse_archive_member(&member, member_name))
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

/// Iterator over the [`LinkArchive`] import members.
pub struct LinkArchiveImportMembersIterator<'b, 'a> {
    archive: &'b LinkArchive<'a>,
    iter: ArchiveMemberIterator<'a>,
}

impl<'b, 'a> Iterator for LinkArchiveImportMembersIterator<'b, 'a> {
    type Item = anyhow::Result<(&'a Path, ImportMember<'a>)>;

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

            if let LinkArchiveMemberVariant::Import(import_member) = member {
                return Some(Ok((member_path, import_member)));
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
