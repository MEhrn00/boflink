//! Module for handling object files
//!
//! An [`ObjectFile`] is meant to act as an abstraction for the different link
//! inputs. The purpose is to materialize [`InputSection`]s and [`InputSymbol`]s
//! which will contribute to the output file.
//!
//! This helps because not only traditional COFFs need to be handled but also
//! short import COFFs from modern
//! [import libraries](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-library-format)
//! and, in the future, LTO COFFs.
use std::sync::atomic::{AtomicBool, Ordering};

use bitflags::bitflags;
use boflink_arena::TypedArenaRef;
use boflink_index::{
    Idx, IndexSlice, IndexVec,
    bit_set::{AtomicDenseBitSet, DenseBitSet},
};
use bstr::BStr;
use object::{ReadRef, U16Bytes, coff::CoffHeader, pe};
use parking_lot::RwLockUpgradableReadGuard;

use crate::{
    ErrorContext, bail,
    chunks::{P2Align, SectionChunk},
    coff::{ImageFileMachine, ImageSymbol, SectionIndex, SectionTable, SymbolIndex, SymbolTable},
    context::LinkContext,
    fatal,
    inputs::InputFile,
    make_error,
    symbols::{GlobalSymbol, Symbol, SymbolId, SymbolMap, SyncSymbolMap},
};

/// Id for an object file. This is a tagged index using a `u32`.
/// - Index 0 is reserved for the internal file used for adding linker-synthesized
///   sections/symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectFileId(u32);

impl boflink_index::Idx for ObjectFileId {
    #[inline]
    fn from_usize(idx: usize) -> Self {
        assert!(idx <= u32::MAX as usize);
        Self(idx as u32)
    }

    #[inline]
    fn index(self) -> usize {
        self.0 as usize
    }
}

impl From<u32> for ObjectFileId {
    #[inline]
    fn from(value: u32) -> Self {
        Self(value)
    }
}

#[derive(Debug, Default)]
pub struct ObjectFile<'a> {
    pub file: InputFile<'a>,
    pub coff_sections: SectionTable<'a>,
    pub coff_symbols: SymbolTable<'a>,
    pub sections: IndexVec<SectionIndex, Option<InputSection<'a>>>,
    pub symbols: IndexVec<SymbolIndex, Option<InputSymbol<'a>>>,
    machine: ImageFileMachine,
    flags: ObjectFileFlags,
}

impl<'a> ObjectFile<'a> {
    #[inline]
    pub fn has_import_metadata(&self) -> bool {
        self.flags.contains(ObjectFileFlags::ImportMetadata)
    }

    #[inline]
    pub fn has_common_symbols(&self) -> bool {
        self.flags.contains(ObjectFileFlags::CommonSymbols)
    }

    #[inline]
    pub fn has_comdats(&self) -> bool {
        self.flags.contains(ObjectFileFlags::COMDATs)
    }

    #[inline]
    pub fn parsed_lazy(&self) -> bool {
        self.flags.contains(ObjectFileFlags::Lazy)
    }

    #[inline]
    pub fn section(&self, i: SectionIndex) -> Option<&InputSection<'a>> {
        self.sections.get(i).and_then(|section| section.as_ref())
    }

    #[inline]
    pub fn section_mut(&mut self, i: SectionIndex) -> Option<&mut InputSection<'a>> {
        self.sections
            .get_mut(i)
            .and_then(|section| section.as_mut())
    }

    #[inline]
    pub fn followers(&self, index: SectionIndex) -> SectionFollowers<'_, 'a> {
        SectionFollowers {
            sections: &self.sections,
            walker: SectionFollowersWalker { index },
        }
    }

    pub fn identify_coff_machine(data: &'a [u8], offset: u64) -> crate::Result<ImageFileMachine> {
        let machine = data
            .read_at::<U16Bytes<_>>(offset)
            .map_err(|_| make_error!("data is not large enough to be a COFF"))?
            .get(object::LittleEndian);

        Ok(ImageFileMachine::try_from(machine)?)
    }

    pub fn parse(
        ctx: &LinkContext<'a>,
        file: InputFile<'a>,
        lazy: bool,
        symtab: &SyncSymbolMap<'a>,
    ) -> crate::Result<Self> {
        ctx.stats.parse.coffs.fetch_add(1, Ordering::Relaxed);

        let mut offset = 0;
        let header = pe::ImageFileHeader::parse(file.data, &mut offset)
            .with_context(|| format!("cannot parse {file}"))?;
        offset += u64::from(header.size_of_optional_header.get(object::LittleEndian));

        let coff_sections = SectionTable::parse(header, file.data, offset)
            .with_context(|| format!("cannot parse {file}"))?;

        ctx.stats
            .parse
            .sections
            .fetch_add(coff_sections.len(), Ordering::Relaxed);

        let coff_symbols = SymbolTable::parse(header, file.data)
            .with_context(|| format!("cannot parse {file}"))?;

        ctx.stats
            .parse
            .symbols
            .fetch_add(coff_symbols.len(), Ordering::Relaxed);

        let mut this = Self {
            file,
            coff_sections,
            coff_symbols,
            machine: ImageFileMachine::try_from(header.machine())?,
            flags: ObjectFileFlags::empty(),
            sections: IndexVec::new(),
            symbols: IndexVec::new(),
        };

        this.initialize_externals(ctx, symtab)?;
        if !lazy {
            this.initialize(ctx)?;
        } else {
            this.flags.insert(ObjectFileFlags::Lazy);
        }

        Ok(this)
    }

    pub fn initialize(&mut self, ctx: &LinkContext<'a>) -> crate::Result<()> {
        self.initialize_sections(ctx)?;
        self.initialize_symbols(ctx)?;
        Ok(())
    }

    fn initialize_sections(&mut self, ctx: &LinkContext<'a>) -> crate::Result<()> {
        ctx.stats
            .parse
            .sections
            .fetch_add(self.coff_sections.len(), Ordering::Relaxed);

        self.sections.resize_to_elem(
            SectionIndex::from_usize(self.coff_sections.len() + 1),
            || None,
        );

        let strings = self.coff_symbols.strings();

        let mut comdats = 0;
        let mut count = 0usize;
        for (i, header) in self.coff_sections.enumerate() {
            let name = header
                .name(strings)
                .with_context(|| format!("reading long name at section number {i}"))?;

            if name == b".llvm_addrsig" || name == b".llvm.call-graph-profile" {
                continue;
            }

            let flags = header.characteristics.get(object::LittleEndian);

            // Skip other metadata sections marked for removal during linking.
            // We keep sections marked as `IMAGE_SCN_MEM_DISCARDABLE`. Stripping
            // them is left up to the user or COFF loader
            if flags & pe::IMAGE_SCN_LNK_REMOVE != 0 {
                continue;
            }

            let is_dwarf =
                || name.starts_with(b".debug_") && flags & pe::IMAGE_SCN_MEM_DISCARDABLE != 0;

            let is_codeview = || {
                [b".debug$F", b".debug$S", b".debug$P", b".debug$T"]
                    .iter()
                    .any(|n| *n == name)
                    && flags & pe::IMAGE_SCN_MEM_DISCARDABLE != 0
            };

            if ctx.options.strip_debug && (is_dwarf() || is_codeview()) {
                // Skip debug sections if using `--strip-debug`
                continue;
            }

            let flags = header.characteristics.get(object::LittleEndian);
            let isec = self.sections[i].insert(InputSection {
                name: BStr::new(name),
                data: header.coff_data(self.file.data)
                    .map_err(|_| make_error!("reading section data for section number {i}: PointerToRawData offset is not valid"))?,
                length: header.size_of_raw_data.get(object::LittleEndian),
                relocs: header.coff_relocations(self.file.data)
                    .with_context(|| format!("reading relocations for section number {i}"))?,
                live: true,
                visited: AtomicBool::new(ctx.options.gc_sections && header.is_gc_retained()),
                flags,
                check_sum: 0,
                selection: 0,
                follower_index: SectionIndex(0),
            });

            if isec.is_comdat() {
                comdats += 1;
            }

            if isec.is_idata() {
                self.flags.insert(ObjectFileFlags::ImportMetadata);
            }

            count += 1;
        }

        if comdats > 0 {
            self.flags.insert(ObjectFileFlags::COMDATs);
        }

        ctx.stats
            .parse
            .input_sections
            .fetch_add(count, Ordering::Relaxed);

        Ok(())
    }

    fn initialize_externals(
        &mut self,
        ctx: &LinkContext<'a>,
        symtab: &SyncSymbolMap<'a>,
    ) -> crate::Result<()> {
        self.symbols
            .resize_to_elem(SymbolIndex::from_usize(self.coff_symbols.len()), || None);

        let mut count = 0usize;
        for (i, symbol) in self.coff_symbols.iter() {
            if !symbol.is_global() {
                continue;
            }

            let external = self
                .read_external(symtab, i, symbol)
                .with_context(|| format!("symbol at index {i}"))?;
            let entry = &mut self.symbols[i];
            debug_assert!(
                entry.is_none(),
                "ObjectFile::initialize_externals() found existing entry at {i}"
            );
            let _ = entry.insert(InputSymbol::External(external));
            count += 1;
        }

        ctx.stats
            .parse
            .input_symbols
            .fetch_add(count, Ordering::Relaxed);

        Ok(())
    }

    fn initialize_symbols(&mut self, ctx: &LinkContext<'a>) -> crate::Result<()> {
        let mut handled_comdats;
        if self.has_comdats() {
            handled_comdats = DenseBitSet::new_empty(self.coff_sections.len() + 1);
        } else {
            handled_comdats = DenseBitSet::new_empty(0);
        }

        let mut count = 0usize;
        for (i, symbol) in self.coff_symbols.iter() {
            if symbol.is_local() {
                let Some(local) = self
                    .read_local(symbol)
                    .with_context(|| format!("symbol at index {i}"))?
                else {
                    continue;
                };

                let entry = &mut self.symbols[i];
                debug_assert!(entry.is_none());
                let _ = entry.insert(InputSymbol::Local(local));
                count += 1;
            }

            if let Some(definition) = self.read_symbol_definition(i, symbol) {
                let definition = definition.with_context(|| format!("symbol at index {i}"))?;
                if let Some(section_aux) = definition.symbol {
                    let section = self.sections[definition.index].as_mut().unwrap();
                    section.length = section_aux.length.get(object::LittleEndian);
                    section.check_sum = section_aux.check_sum.get(object::LittleEndian);
                    section.selection = section_aux.selection;

                    if section_aux.selection == pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE {
                        let parent_index =
                            SectionIndex(u32::from(section_aux.number.get(object::LittleEndian)));

                        let parent = self
                            .sections
                            .get_mut(parent_index)
                            .and_then(|parent| parent.as_mut())
                            .ok_or_else(|| {
                                make_error!(
                                    "follower {} references later parent {}",
                                    definition.index,
                                    parent_index
                                )
                            })?;

                        let head = std::mem::replace(&mut parent.follower_index, definition.index);
                        let section = self.sections[definition.index].as_mut().unwrap();
                        section.follower_index = head;
                    } else if section_aux.selection == pe::IMAGE_COMDAT_SELECT_EXACT_MATCH
                        && section.check_sum == 0
                    {
                        section.check_sum = crate::chunks::compute_checksum(section.data);
                    }
                } else if definition.section.characteristics.get(object::LittleEndian)
                    & pe::IMAGE_SCN_LNK_COMDAT
                    != 0
                    && handled_comdats.insert(definition.index)
                    && let Some(section) = self.sections[definition.index].as_ref()
                    && section.selection > 0
                    && section.selection != pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE
                    && let Some(external) = self.symbols[i].as_mut().unwrap().external_mut()
                {
                    external.selection = section.selection;
                }
            }
        }

        ctx.stats
            .parse
            .input_symbols
            .fetch_add(count, Ordering::Relaxed);

        Ok(())
    }

    fn read_external(
        &self,
        symtab: &SyncSymbolMap<'a>,
        i: SymbolIndex,
        symbol: &'a pe::ImageSymbol,
    ) -> crate::Result<ExternalSymbol> {
        debug_assert!(symbol.is_global());

        let mut hidden = false;
        if symbol.has_aux_weak_external() {
            let weak_aux = self
                .coff_symbols
                .aux_weak_external(i)
                .context("reading auxiliary weak external")?;

            // Verify the default symbol
            let default_index = weak_aux.default_symbol();
            let default_symbol = self
                .coff_symbols
                .symbol(default_index)
                .map_err(|_| make_error!("weak tag index references invalid symbol"))?;

            if default_symbol.storage_class != pe::IMAGE_SYM_CLASS_EXTERNAL
                && default_symbol.storage_class != pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
            {
                bail!("weak default symbol is local {default_index}")
            }

            let weak_search = weak_aux.characteristics.get(object::LittleEndian);
            // Weak externals need to be linkage scoped per the COFF spec.
            // Some weak externals, however, are treated as locally scoped
            // during symbol resolution. Making an external symbol hidden
            // marks it as not being used as a candidate for symbol resolution.
            if weak_search == pe::IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY {
                hidden = true;
            }
        }

        Ok(ExternalSymbol {
            id: symtab.get_or_create_default(self.read_symbol_name(symbol)?),
            selection: 0,
            hidden,
            weak_claimed: false,
        })
    }

    fn read_local(&self, symbol: &'a pe::ImageSymbol) -> crate::Result<Option<LocalSymbol<'a>>> {
        debug_assert!(symbol.is_local());

        if symbol.is_debug() {
            return Ok(None);
        } else if symbol.is_absolute() {
            let name = self.read_symbol_name(symbol)?;
            if name == b"@feat.00" || name == b"@comp.id" {
                return Ok(None);
            }
        }

        Ok(Some(LocalSymbol(symbol)))
    }

    fn read_symbol_definition(
        &self,
        i: SymbolIndex,
        symbol: &'a pe::ImageSymbol,
    ) -> Option<crate::Result<SymbolDefinition<'a>>> {
        symbol.section_index().map(|index| {
            self.coff_sections
                .section(index)
                .map_err(|_| make_error!("section number is invalid {index}"))
                .and_then(|section| {
                    if symbol.has_aux_section() {
                        let section_def = self.coff_symbols.aux_section(i)?;
                        Ok((section, Some(section_def)))
                    } else {
                        Ok((section, None))
                    }
                })
                .map(|(section, symbol)| SymbolDefinition {
                    index,
                    section,
                    symbol,
                })
        })
    }

    fn read_symbol_name(&self, symbol: &'a pe::ImageSymbol) -> crate::Result<&'a BStr> {
        symbol
            .name_bstr(self.coff_symbols.strings())
            .context("reading symbol name")
    }

    pub fn resolve_symbols(&self, id: ObjectFileId, symtab: &SymbolMap<'a>) {
        for (i, coff_symbol) in self.coff_symbols.iter() {
            if coff_symbol.is_global()
                && let Some(symbol) = self.symbols[i].as_ref().unwrap().external()
                && !symbol.hidden
            {
                if let Some(section_index) = coff_symbol.section_index()
                    && let Some(section) = self.section(section_index)
                    && !section.live
                {
                    continue;
                }

                let external_ref = symtab.get(symbol.id).unwrap();
                let mut global = external_ref.write();

                // Check if our copy of the symbol should be become the new global
                // symbol used
                let should_claim =
                    |global: &GlobalSymbol| match coff_symbol.priority().cmp(&global.priority()) {
                        std::cmp::Ordering::Equal => id < global.owner,
                        o => o == std::cmp::Ordering::Greater,
                    };

                if should_claim(&global) {
                    global.replace_with(id, i, coff_symbol);
                }
            }
        }
    }

    pub fn include_needed_objects(
        &self,
        ctx: &LinkContext<'a>,
        symtab: &SymbolMap<'a>,
        live_set: &AtomicDenseBitSet<ObjectFileId>,
        objs: &IndexSlice<ObjectFileId, TypedArenaRef<'a, ObjectFile<'a>>>,
        visit: impl Fn(ObjectFileId),
    ) {
        for (i, symbol) in self.symbols.iter_enumerated() {
            if let Some(symbol) = symbol.as_ref().and_then(|symbol| symbol.external())
                && !symbol.hidden
            {
                let coff_symbol = self.coff_symbols.symbol(i).unwrap();
                let external_ref = symtab.get(symbol.id).unwrap();
                let global = external_ref.read();
                if global.is_traced() {
                    if !coff_symbol.is_undefined() {
                        log::info!(logger: ctx, "{}: definition of {}", self.file, ctx.demangle(global.name, self.machine));
                    } else if coff_symbol.is_weak() {
                        log::info!(logger: ctx, "{}: weak external for {}", self.file, ctx.demangle(global.name, self.machine));
                    } else {
                        log::info!(logger: ctx, "{}: reference to {}", self.file, ctx.demangle(global.name, self.machine));
                    }
                }
                if global.is_undefined() {
                    continue;
                }

                if (coff_symbol.is_undefined() || coff_symbol.is_common())
                    && live_set.insert(global.owner, Ordering::Relaxed)
                {
                    let owner = &objs[global.owner];
                    if global.is_traced() {
                        log::info!(logger: ctx, "{}: needs {} from {}", self.file, ctx.demangle(global.name, self.machine), owner.file);
                    }

                    visit(global.owner);
                }
            }
        }
    }

    pub fn resolve_comdat_leaders(
        &self,
        id: ObjectFileId,
        symtab: &SymbolMap<'a>,
        live_set: &DenseBitSet<ObjectFileId>,
        objs: &IndexSlice<ObjectFileId, TypedArenaRef<'a, ObjectFile<'a>>>,
    ) {
        debug_assert!(self.has_comdats());

        for (i, symbol) in self.symbols.iter_enumerated() {
            if let Some(symbol) = symbol.as_ref().and_then(|symbol| symbol.external())
                && symbol.selection == pe::IMAGE_COMDAT_SELECT_LARGEST
            {
                let coff_symbol = self.coff_symbols.symbol(i).unwrap();
                let external = symtab.get(symbol.id).unwrap();
                let section = self.section(coff_symbol.section_index().unwrap()).unwrap();
                let mut global = external.write();

                let should_claim = |global: &GlobalSymbol| {
                    if !global.is_definition() || !live_set.contains(global.owner) {
                        return true;
                    }

                    let owner = &objs[global.owner];
                    let owner_section = owner.section(global.section_index().unwrap()).unwrap();
                    match section.length.cmp(&owner_section.length) {
                        // Choose the first definition if they are the same size
                        std::cmp::Ordering::Equal => id < global.owner,
                        o => o == std::cmp::Ordering::Greater,
                    }
                };

                if should_claim(&global) {
                    global.replace_with(id, i, coff_symbol);
                }
            }
        }
    }

    /// Discards COMDATs and associative sections not claimed by leader symbols.
    pub fn discard_unclaimed_comdats(&mut self, id: ObjectFileId, symtab: &SymbolMap<'a>) {
        debug_assert!(self.has_comdats());

        for (i, symbol) in self.symbols.iter_enumerated() {
            if let Some(symbol) = symbol.as_ref().and_then(|s| s.external())
                && symbol.selection != 0
            {
                let coff_symbol = self.coff_symbols.symbol(i).unwrap();
                let external = symtab.get(symbol.id).unwrap();
                let section_index = coff_symbol.section_index().unwrap();
                let section = self.sections[section_index].as_mut().unwrap();

                let live = external.read().owner == id;
                section.live = live;
                let mut followers = self.followers(section_index).detach();
                while let Some(follower) = followers.next(&self.sections) {
                    self.sections[follower].as_mut().unwrap().live = live;
                }
            }
        }
    }

    /// Fixes definitions for common symbols.
    ///
    /// This has to be done after archive extraction so that the correct symbols
    /// get extracted but the largest common definition should be used in place
    /// of duplicates and weak references.
    pub fn resolve_common_symbols(&self, id: ObjectFileId, symtab: &SymbolMap<'a>) {
        if !self.has_common_symbols() {
            return;
        }

        for (i, coff_symbol) in self.coff_symbols.iter() {
            if coff_symbol.is_common() {
                let symbol = self.symbols[i].as_ref().unwrap().external().unwrap();
                let external_ref = symtab.get(symbol.id).unwrap();
                let mut global = external_ref.write();

                // Two commons should use the largest definition. Common definitions
                // claim weak symbols.
                if global.is_weak() || (global.is_common() && coff_symbol.value() > global.value())
                {
                    global.replace_with(id, i, coff_symbol);
                }
            }
        }
    }

    pub fn collect_duplicate_symbol_errors(
        &self,
        ctx: &LinkContext<'a>,
        id: ObjectFileId,
        symtab: &SymbolMap<'a>,
        objs: &IndexSlice<ObjectFileId, TypedArenaRef<'a, ObjectFile<'a>>>,
    ) -> Vec<String> {
        let mut errors = Vec::new();
        for (i, coff_symbol) in self.coff_symbols.iter() {
            if coff_symbol.is_global()
                && coff_symbol.is_definition()
                && let Some(symbol) = self.symbols[i].as_ref().unwrap().external()
            {
                let external_ref = symtab.get(symbol.id).unwrap();
                let section = self.sections[coff_symbol.section_index().unwrap()]
                    .as_ref()
                    .unwrap();
                // Verify COMDATs
                if symbol.selection > 0 {
                    let global = external_ref.read();
                    if global.owner == id {
                        continue;
                    }

                    // The COFF spec does not explictly state how to handle COMDAT
                    // definitions with differing selection types. It makes sense
                    // to just throw an error on differing types since that would
                    // indicate possible ODR issues. LLD seems to do this but with
                    // some added leniency to account for MSVC/GCC/Clang differences.
                    // For now, just follow the table on how to handle COMDAT resolution
                    // errors for this definition without worrying if the selection
                    // types for each symbol match. This is probably not correct and
                    // will need to be fixed later.
                    let multiply_defined = match symbol.selection {
                        pe::IMAGE_COMDAT_SELECT_NODUPLICATES => global.owner == id,
                        pe::IMAGE_COMDAT_SELECT_SAME_SIZE => {
                            let owner = &objs[global.owner];
                            let owner_section =
                                owner.section(global.section_index().unwrap()).unwrap();
                            section.length != owner_section.length
                        }
                        pe::IMAGE_COMDAT_SELECT_EXACT_MATCH => {
                            let owner = &objs[global.owner];
                            let owner_section =
                                owner.section(global.section_index().unwrap()).unwrap();
                            !(section.length == owner_section.length
                                && section.check_sum == owner_section.check_sum)
                        }
                        pe::IMAGE_COMDAT_SELECT_ANY | pe::IMAGE_COMDAT_SELECT_LARGEST => false,
                        _ => false,
                    };

                    if multiply_defined {
                        let owner = &objs[global.owner];
                        // Yes, "multiply defined symbol" is a weird and rather vague error message.
                        // But, that is what the error message should be...
                        errors.push(format!(
                            "multiply defined symbol: {name}\n\
                            defined at {owner}\n\
                            defined at {this}",
                            name = ctx.demangle(global.name, self.machine),
                            owner = owner.file,
                            this = self.file,
                        ));
                    }
                } else if !section.live {
                    // Symbol is defined in a section discarded due to COMDAT deduplication.
                    continue;
                } else {
                    // Regularly defined symbol
                    let global = external_ref.read();
                    if global.owner != id {
                        let owner = &objs[global.owner];
                        errors.push(format!(
                            "duplicate symbol: {name}\n\
                                    defined at {owner}\n\
                                    defined at {this}",
                            name = ctx.demangle(global.name, self.machine),
                            owner = owner.file,
                            this = self.file,
                        ));
                    }
                }
            }
        }

        errors
    }

    pub fn claim_undefined_symbols(&mut self, id: ObjectFileId, symtab: &SymbolMap<'a>) {
        for (i, coff_symbol) in self.coff_symbols.iter() {
            if coff_symbol.is_local() {
                continue;
            }

            if coff_symbol.is_undefined() {
                let symbol = self.symbols[i].as_ref().unwrap().external().unwrap();
                let mut global = symtab.get(symbol.id).unwrap().write();
                if global.is_undefined() && id < global.owner {
                    global.replace_with(id, i, coff_symbol);
                }
            } else if coff_symbol.is_weak() {
                let symbol = self.symbols[i].as_mut().unwrap().external_mut().unwrap();
                let global_id = symbol.id;
                let global = symtab.get(global_id).unwrap().upgradable_read();
                if !(global.owner == id && global.index == i) {
                    continue;
                }
                symbol.weak_claimed = true;

                let mut weak_symbol = self.coff_symbols.aux_weak_external(i).unwrap();
                let mut default_index;
                let mut default_coffsym;
                loop {
                    default_index = weak_symbol.default_symbol();
                    default_coffsym = self.coff_symbols.symbol(default_index).unwrap();
                    // Cycles are invalid in the COFF/PE spec
                    if default_index == i {
                        fatal!(
                            "{}: '{}' cyclic weak default tag index chain",
                            self.file,
                            global.name
                        );
                    }

                    if default_coffsym.is_weak() {
                        let default_extern = self.symbols[default_index]
                            .as_ref()
                            .unwrap()
                            .external()
                            .unwrap();
                        assert_ne!(default_extern.id, global_id);
                        let default_global = symtab.get(default_extern.id).unwrap().read();
                        if default_global.is_weak() || default_global.is_undefined() {
                            // Continue traversing weak defaults if this one was not
                            // resolved to a definition
                            weak_symbol =
                                self.coff_symbols.aux_weak_external(default_index).unwrap();
                        } else {
                            let mut global = RwLockUpgradableReadGuard::upgrade(global);
                            global.replace_with(
                                default_global.owner,
                                default_global.index,
                                &*default_global,
                            );
                            return;
                        }
                    } else {
                        // Reached the local weak default
                        break;
                    }
                }

                let mut global = RwLockUpgradableReadGuard::upgrade(global);
                global.replace_with(id, default_index, default_coffsym);
            }
        }
    }

    pub fn define_common_symbols(&mut self, id: ObjectFileId, symtab: &SymbolMap<'a>) {
        if !self.has_common_symbols() {
            return;
        }

        let mut common = InputSection {
            name: BStr::new(b".common"),
            flags: pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA
                | pe::IMAGE_SCN_MEM_READ
                | pe::IMAGE_SCN_MEM_WRITE,
            live: true,
            ..Default::default()
        };

        for (i, coff_symbol) in self.coff_symbols.iter() {
            if coff_symbol.is_common() {
                let external = self.symbols[i].as_ref().unwrap().external().unwrap();
                let mut global = symtab.get(external.id).unwrap().write();
                if global.owner == id && global.index == i {
                    let size = coff_symbol.value();
                    common.length = common.length.next_multiple_of(size);
                    global.value = common.length;
                    global.section_number = self.sections.len() as i32;
                    common.length += size;
                }
            }
        }

        if common.length > 0 {
            self.sections.push(Some(common));
        }
    }
}

#[derive(Debug)]
struct SymbolDefinition<'a> {
    index: SectionIndex,
    section: &'a pe::ImageSectionHeader,
    symbol: Option<&'a pe::ImageAuxSymbolSection>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectFileFlags(u32);

bitflags! {
    impl ObjectFileFlags: u32 {
        /// File was parsed in a lazy state
        const Lazy = 1;

        /// Contains import metadata
        const ImportMetadata = 1 << 1;

        /// Has common symbols
        const CommonSymbols = 1 << 2;

        /// Has COMDATs
        const COMDATs = 1 << 3;
    }
}

#[derive(Debug)]
pub struct InputSection<'a> {
    pub name: &'a BStr,
    pub data: &'a [u8],
    pub length: u32,
    pub check_sum: u32,
    pub selection: u8,
    pub flags: u32,
    pub relocs: &'a [pe::ImageRelocation],
    pub live: bool,
    pub visited: AtomicBool,
    follower_index: SectionIndex,
}

impl<'a> InputSection<'a> {
    #[inline]
    pub fn characteristics(&self) -> u32 {
        self.flags
    }

    #[inline]
    pub fn is_comdat(&self) -> bool {
        self.characteristics() & pe::IMAGE_SCN_LNK_COMDAT != 0
    }

    #[inline]
    pub fn mark_visited(&self) -> bool {
        !(self.visited.load(Ordering::Relaxed) || self.visited.swap(true, Ordering::Relaxed))
    }
}

impl<'a> std::default::Default for InputSection<'a> {
    fn default() -> Self {
        Self {
            name: Default::default(),
            data: Default::default(),
            length: Default::default(),
            check_sum: Default::default(),
            selection: Default::default(),
            flags: Default::default(),
            relocs: Default::default(),
            live: false,
            visited: AtomicBool::new(false),
            follower_index: SectionIndex(0),
        }
    }
}

impl<'a> SectionChunk<'a> for InputSection<'a> {
    #[inline]
    fn name_bytes(&self) -> &'a [u8] {
        self.name.as_ref()
    }

    #[inline]
    fn contents_flags(&self) -> u32 {
        self.flags & 0xe0
    }

    #[inline]
    fn memory_flags(&self) -> u32 {
        self.flags & 0xfe000000
    }

    #[inline]
    fn p2align(&self) -> P2Align {
        P2Align::from_scn_flags(self.flags)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct InputSectionFlags(u8);

bitflags! {
    impl InputSectionFlags: u8 {
        /// Section is live
        const Live = 1;

        /// Section is for allocated COMMON symbols
        const SyntheticCommon = 1 << 1;
    }
}

#[derive(Debug)]
pub struct SectionFollowers<'b, 'a> {
    walker: SectionFollowersWalker,
    sections: &'b IndexSlice<SectionIndex, Option<InputSection<'a>>>,
}

impl<'b, 'a> SectionFollowers<'b, 'a> {
    #[inline]
    pub fn detach(&self) -> SectionFollowersWalker {
        self.walker
    }
}

impl<'b, 'a> Iterator for SectionFollowers<'b, 'a> {
    type Item = (SectionIndex, &'b InputSection<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        let index = self.walker.next(self.sections)?;
        Some((index, self.sections[index].as_ref().unwrap()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SectionFollowersWalker {
    index: SectionIndex,
}

impl SectionFollowersWalker {
    pub fn next<'b, 'a>(
        &mut self,
        sections: &'b IndexSlice<SectionIndex, Option<InputSection<'a>>>,
    ) -> Option<SectionIndex> {
        let index = self.checked_index(self.index)?;
        let section = sections.get(index).and_then(|section| section.as_ref())?;
        self.index = section.follower_index;
        self.checked_index(self.index)
    }

    fn checked_index(&self, index: SectionIndex) -> Option<SectionIndex> {
        (index.0 != 0).then_some(index)
    }
}

#[derive(Debug, Clone)]
pub enum InputSymbol<'a> {
    Local(LocalSymbol<'a>),
    External(ExternalSymbol),
}

impl<'a> InputSymbol<'a> {
    #[inline]
    pub fn local(&self) -> Option<&LocalSymbol<'a>> {
        if let Self::Local(s) = self {
            Some(s)
        } else {
            None
        }
    }

    #[inline]
    pub fn external(&self) -> Option<&ExternalSymbol> {
        if let Self::External(s) = self {
            Some(s)
        } else {
            None
        }
    }

    #[inline]
    pub fn external_mut(&mut self) -> Option<&mut ExternalSymbol> {
        if let Self::External(s) = self {
            Some(s)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct LocalSymbol<'a>(&'a pe::ImageSymbol);

impl Symbol for LocalSymbol<'_> {
    #[inline]
    fn value(&self) -> u32 {
        Symbol::value(self.0)
    }

    #[inline]
    fn storage_class(&self) -> u8 {
        self.0.storage_class
    }

    #[inline]
    fn section_number(&self) -> i32 {
        Symbol::section_number(self.0)
    }

    #[inline]
    fn is_function(&self) -> bool {
        self.0.is_function()
    }
}

#[derive(Debug, Clone)]
pub struct ExternalSymbol {
    pub id: SymbolId,
    selection: u8,
    hidden: bool,
    weak_claimed: bool,
}
