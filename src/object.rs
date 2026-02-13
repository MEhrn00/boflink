//! Module for handling object files
//!
//! An [`ObjectFile`] is meant to act as an abstraction for the different link
//! inputs. The purpose is to materialize [`ObjectSection`]s and [`ObjectSymbol`]s
//! which are used as the inputs for producing an output.
//!
//! This helps because not only traditional COFFs need to be handled but also
//! short import COFFs from modern
//! [import libraries](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-library-format)
//! and, in the future, LTO COFFs.
use std::{
    borrow::Cow,
    sync::atomic::{AtomicBool, Ordering},
};

use object::{
    Object as _, ObjectSection as _, ObjectSymbol as _, ReadRef, SectionIndex, SymbolIndex,
    SymbolScope, U16Bytes, U32Bytes,
    coff::{
        CoffFile, CoffHeader, ImageSymbol as _, ImportFile, ImportName, ImportType, SectionTable,
        SymbolTable,
    },
    pe::{
        IMAGE_COMDAT_SELECT_ASSOCIATIVE, IMAGE_REL_AMD64_REL32, IMAGE_REL_I386_DIR32,
        IMAGE_SYM_CLASS_FILE, IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY,
    },
};
use rayon::Scope;

use crate::{
    ErrorContext,
    arena::ArenaRef,
    coff::{
        CoffFlags, ComdatSelection, Feat00Flags, ImageFileMachine, SectionFlags, SectionNumber,
        StorageClass,
    },
    context::LinkContext,
    inputs::{InputFile, InputFileSource},
    make_error,
    outputs::OutputSectionId,
    symbols::{GlobalSymbol, SymbolId},
};

/// Id for an object file. This is a tagged index using a `u32`.
/// - Index 0 is reserved for the internal file used for adding linker-synthesized
///   sections/symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectFileId(u32);

impl ObjectFileId {
    pub fn new(idx: usize) -> Self {
        Self(
            u32::try_from(idx)
                .unwrap_or_else(|_| panic!("number of object files exceeded u32::MAX")),
        )
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// An object file being linked.
#[derive(Debug)]
pub struct ObjectFile<'a> {
    /// The id of this file.
    pub id: ObjectFileId,

    /// The file associated with this object file
    pub file: InputFile<'a>,

    /// File should be lazily included.
    ///
    /// This reflects the command line option context used when parsing this file.
    /// - Object files specified on the command line directly are not lazy
    /// - Object files wrapped in `--start-lib ... --end-lib` are lazy
    /// - Object files from archives are lazy
    /// - Object files from archives wrapped in `--whole-archive ... --no-whole-archive` are not lazy
    pub lazy: bool,

    /// File should be included in the linked output
    pub live: AtomicBool,

    /// Architecture
    pub machine: ImageFileMachine,

    /// File flags
    pub characteristics: CoffFlags,

    /// Raw COFF section headers.
    ///
    /// May be empty in a few scenarios.
    /// - This is the internal object file
    /// - Object file has no sections
    /// - Object file was initialized from an import file
    pub coff_sections: SectionTable<'a>,

    /// Raw COFF symbol table.
    ///
    /// May be empty in a few scenarios.
    /// - This is the internal object file
    /// - Object file has no symbols
    /// - Object file was initialized from an import file
    pub coff_symbols: SymbolTable<'a>,

    /// Input sections.
    ///
    /// Sections use 1-based indicies. This follows a structure as ELF's SHT_NULL section.
    /// The first section in this array will always be `None`. The rest of the
    /// sections retain the same 1-based indicies as the source file they
    /// were initialized from. `None` entries are sections that were skipped
    /// during initialization
    pub sections: Vec<Option<ObjectSection<'a>>>,

    /// Index of the .drectve section if present.
    ///
    /// This will be the index of the ghost `SHT_NULL` section `SectionIndex(0)`
    /// if not present.
    pub directives_index: SectionIndex,

    /// Index of the .llvm_addrsig section if present.
    ///
    /// This will be the index of the ghost `SHT_NULL` section `SectionIndex(0)`
    /// if not present.
    pub addrsig_index: SectionIndex,

    /// True if this COFF contains import information
    pub has_import_data: bool,

    /// Symbols.
    ///
    /// This vec retains the same symbol indicies as the original symbol table.
    pub symbols: Vec<Option<ObjectSymbol<'a>>>,

    /// Indicies of COMDAT symbols.
    ///
    /// These are either COMDAT leader symbols or section symbols depending on
    /// the selection type.
    pub comdat_indicies: Vec<SymbolIndex>,

    /// @feat.00 flags
    pub feat_flags: Feat00Flags,
}

impl<'a> ObjectFile<'a> {
    pub fn new(id: ObjectFileId, file: InputFile<'a>, lazy: bool) -> ObjectFile<'a> {
        Self {
            id,
            file,
            lazy,
            live: false.into(),
            machine: ImageFileMachine::Unknown,
            characteristics: CoffFlags::empty(),
            coff_sections: Default::default(),
            coff_symbols: Default::default(),
            sections: Vec::new(),
            symbols: Vec::new(),
            comdat_indicies: Vec::new(),
            directives_index: SectionIndex(0),
            has_import_data: false,
            addrsig_index: SectionIndex(0),
            feat_flags: Feat00Flags::empty(),
        }
    }

    pub fn source(&self) -> InputFileSource<'a> {
        self.file.source()
    }

    pub fn identify_coff_machine(data: &'a [u8], offset: u64) -> crate::Result<ImageFileMachine> {
        let machine = data
            .read_at::<U16Bytes<_>>(offset)
            .map_err(|_| make_error!("data is not large enough to be a COFF"))?
            .get(object::LittleEndian);

        Ok(ImageFileMachine::try_from(machine)?)
    }

    pub fn identify_importfile_machine(data: &'a [u8]) -> crate::Result<ImageFileMachine> {
        let machine = data
            .read_at::<U16Bytes<_>>(6)
            .map_err(|_| make_error!("data is not large enough to be an import file"))?
            .get(object::LittleEndian);

        Ok(ImageFileMachine::try_from(machine)?)
    }

    pub fn parse_coff(&mut self, ctx: &LinkContext<'a>) -> crate::Result<()> {
        ctx.stats.parse.coffs.fetch_add(1, Ordering::Relaxed);
        let coff: CoffFile = CoffFile::parse(self.file.data)?;
        let header = coff.coff_header();
        self.machine = ImageFileMachine::try_from(header.machine())?;
        self.characteristics = CoffFlags::from_bits_retain(header.characteristics());

        self.coff_sections = coff.coff_section_table();
        self.coff_symbols = header.symbols(self.file.data).unwrap();
        self.initialize_coff_sections(ctx, &coff)?;
        self.initialize_coff_symbols(ctx, &coff)?;
        Ok(())
    }

    fn initialize_coff_sections(
        &mut self,
        ctx: &LinkContext<'a>,
        coff: &CoffFile<'a>,
    ) -> crate::Result<()> {
        self.sections
            .resize_with(self.coff_sections.len() + 1, || None);

        let mut comdats = 0;
        for coff_section in coff.sections() {
            let name = coff_section.name_bytes().with_context(|| {
                format!(
                    "reading long name at section number {}",
                    coff_section.index()
                )
            })?;

            let mut characteristics = SectionFlags::from_bits_retain(
                coff_section
                    .coff_section()
                    .characteristics
                    .get(object::LittleEndian),
            );

            // Linker metadata
            let has_link_info = || characteristics.contains(SectionFlags::LnkInfo);

            // Store the index of the section with linker directives
            if name == b".drectve" && has_link_info() {
                // Verify data is present
                let data = coff_section
                    .data()
                    .map_err(|_| make_error!(".drectve section header is malformed"))?;
                if !data.is_empty() {
                    self.directives_index = coff_section.index();
                }
                continue;
            }

            // addrsig section is not used yet but store it anyway
            if name == b".llvm_addrsig" {
                self.addrsig_index = coff_section.index();
                continue;
            }

            // Skip over LLVM call graph profile
            if name == b".llvm.call-graph-profile" {
                continue;
            }

            // Skip other metadata sections marked for removal during linking.
            // We keep `IMAGE_SCN_MEM_DISCARDABLE` sections in for the user to
            // strip out manually or for the loader to handle
            if characteristics.contains(SectionFlags::LnkRemove) {
                continue;
            }

            // Debug sections are marked as mem discardable + readonly
            let has_debug_flags = || {
                characteristics.memory_flags()
                    == SectionFlags::MemRead | SectionFlags::MemDiscardable
            };

            let is_dwarf = || name.starts_with(b".debug_") && has_debug_flags();

            let is_codeview = || {
                [b".debug$F", b".debug$S", b".debug$P", b".debug$T"]
                    .iter()
                    .any(|&n| n == name)
                    && has_debug_flags()
            };

            // Skip debug sections if using `--strip-debug`
            if ctx.options.strip_debug && (is_dwarf() || is_codeview()) {
                continue;
            }

            let relocs = coff_section.coff_relocations().with_context(|| {
                format!(
                    "reading relocations for section number {}",
                    coff_section.index()
                )
            })?;

            let data = coff_section.data().with_context(|| {
                format!(
                    "reading section data for section number {}",
                    coff_section.index()
                )
            })?;

            // Symbol COFFs from legacy MinGW import libraries will inconsistently
            // set the IMAGE_SCN_CNT_INITIALIZED_DATA flag for .idata sections.
            // This flag needs to be set for these sections since it is used
            // later
            if name.starts_with(b".idata$")
                && !data.is_empty()
                && characteristics.contains(SectionFlags::MemRead | SectionFlags::MemWrite)
            {
                self.has_import_data = true;
                characteristics |= SectionFlags::CntInitializedData;
            }

            let mut length = data.len() as u32;
            // If the section contains uninitialized data, use the size_of_raw_data field
            // for the length
            if characteristics.contains(SectionFlags::CntUninitializedData) {
                length = coff_section
                    .coff_section()
                    .size_of_raw_data
                    .get(object::LittleEndian);
            }

            if characteristics.contains(SectionFlags::LnkComdat) {
                comdats += 1;
            }

            self.sections[coff_section.index().0] = Some(ObjectSection {
                name,
                data,
                length,
                virtual_address: 0,
                checksum: 0,
                characteristics,
                coff_relocs: relocs.into(),
                associative: None,
                index: coff_section.index(),
                discarded: AtomicBool::new(false),
                output: OutputSectionId::Null,
            });
        }

        ctx.stats
            .parse
            .comdats
            .fetch_add(comdats, Ordering::Relaxed);

        ctx.stats
            .parse
            .input_sections
            .fetch_add(self.sections.len() - 1, Ordering::Relaxed);

        Ok(())
    }

    fn initialize_coff_symbols(
        &mut self,
        ctx: &LinkContext<'a>,
        coff: &CoffFile<'a>,
    ) -> crate::Result<()> {
        self.symbols.resize_with(self.coff_symbols.len(), || None);

        let mut comdat_aux = Vec::new();
        comdat_aux.resize_with(self.coff_sections.len() + 1, || None);

        let mut locals = 0;

        for coff_symbol in coff.symbols() {
            if coff_symbol.coff_symbol().storage_class() == IMAGE_SYM_CLASS_FILE {
                continue;
            }

            let name = coff_symbol
                .name_bytes()
                .with_context(|| format!("reading name for symbol {}", coff_symbol.index()))?;

            let symbol = {
                let index = coff_symbol.index();
                let coff_symbol = coff_symbol.coff_symbol();
                let local_symbol = ObjectSymbol {
                    name,
                    index,
                    value: coff_symbol.value(),
                    section_number: coff_symbol.section_number().into(),
                    storage_class: coff_symbol
                        .storage_class()
                        .try_into()
                        .with_context(|| format!("symbol at index {index}"))?,
                    selection: None,
                    typ: coff_symbol.typ(),
                    external_id: None,
                };
                self.symbols[index.0] = Some(local_symbol);
                self.symbols[index.0].as_mut().unwrap()
            };

            if coff_symbol.is_weak() {
                let weak_aux = self
                    .coff_symbols
                    .aux_weak_external(coff_symbol.index())
                    .with_context(|| {
                        format!("reading weak aux for symbol {}", coff_symbol.index())
                    })?;

                let weak_search = weak_aux.weak_search_type.get(object::LittleEndian);

                // Check if the weak external symbol should be externally visible
                // for symbol resolution and unlink it from the global symbol map
                // if it should not.
                // It is confusing why a weak "external" would be treated as a
                // local symbol but it happens to be a thing.
                // These can be confusing since GCC tries to "simulate" weak definitions
                // even though only weak externals are supported by the COFF spec.
                // They do need to be supported properly since GCC (C++) and libstdc++
                // use them.
                // Related:
                // - https://sourceware.org/legacy-ml/binutils/2005-08/msg00205.html
                // - https://maskray.me/blog/2021-04-25-weak-symbol
                // - https://sourceware.org/bugzilla/show_bug.cgi?id=9687

                if weak_search != IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY {
                    symbol.external_id = Some(ctx.symbol_map.get_or_create_default(name));
                }
            } else if coff_symbol.scope() == SymbolScope::Linkage {
                symbol.external_id = Some(ctx.symbol_map.get_or_create_default(name));
            } else if coff_symbol.is_local() {
                locals += 1;
            }

            let Some(section_index) = coff_symbol.section_index() else {
                continue;
            };

            let section = {
                let section = self.sections.get_mut(section_index.0).ok_or_else(|| {
                    make_error!(
                        "symbol at index {}: section number is invalid {section_index}",
                        coff_symbol.index(),
                    )
                })?;

                let Some(section) = section else {
                    continue;
                };
                section
            };

            // Handle section symbols
            if coff_symbol.coff_symbol().has_aux_section() {
                let aux_section = self
                    .coff_symbols
                    .aux_section(coff_symbol.index())
                    .with_context(|| format!("symbol at index {}", coff_symbol.index()))?;

                // Overwrite length to match the aux symbol length. This value
                // is more accurate for computing section length since GCC inserts
                // padding into the raw data. The padding may get trimmed if
                // proprly aligned
                section.length = aux_section.length.get(object::LittleEndian);
                section.checksum = aux_section.check_sum.get(object::LittleEndian);

                if aux_section.selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE {
                    // Record associative COMDATs and setup the aux section
                    // for the leader to handle
                    let number = aux_section.number.get(object::LittleEndian);
                    section.associative = Some(SectionIndex(number as usize));
                    symbol.selection = Some(ComdatSelection::Associative);
                    self.comdat_indicies.push(symbol.index);
                } else if section.characteristics.contains(SectionFlags::LnkComdat) {
                    // For COMDAT sections that are not associative, record the
                    // auxiliary symbol for the leader to handle
                    comdat_aux[section_index.0] = Some(aux_section);
                }

                continue;
            }

            // Handle COMDAT sections that are pending a leader symbol
            if section.is_comdat()
                && let Some(aux_section) = comdat_aux[section_index.0].take()
            {
                let selection = ComdatSelection::try_from(aux_section.selection)
                    .with_context(|| format!("COMDAT leader for section {}", section.index))?;
                symbol.selection = Some(selection);
                self.comdat_indicies.push(symbol.index);
            }
        }

        ctx.stats
            .parse
            .local_symbols
            .fetch_add(locals, Ordering::Relaxed);

        ctx.stats
            .parse
            .input_symbols
            .fetch_add(self.symbols.len(), Ordering::Relaxed);

        Ok(())
    }

    pub fn parse_importfile(&mut self, ctx: &LinkContext<'a>) -> crate::Result<()> {
        let file = ImportFile::parse(self.file.data)?;
        self.machine = Self::identify_importfile_machine(self.file.data)?;
        self.characteristics = CoffFlags::LineNumsStripped;

        let strings = ctx.string_pool.get();

        let import_name = if let ImportName::Name(name) = file.import() {
            name
        } else {
            let mut public_symbol = file.symbol();
            log::warn!(
                "{}: using public symbol name '{}' for resolving NONAME ordinal import",
                self.source(),
                String::from_utf8_lossy(public_symbol)
            );

            if self.machine == ImageFileMachine::I386 {
                public_symbol = public_symbol.strip_prefix(b"_").unwrap_or(public_symbol);
            }
            public_symbol
        };

        let thunk_section_name = match file.import_type() {
            ImportType::Const => ".rdata",
            ImportType::Code => ".text",
            ImportType::Data => ".data",
        };

        let section_name = strings.alloc_bytes(
            [thunk_section_name.as_bytes(), b"$", import_name]
                .concat()
                .as_slice(),
        );
        let code = file.import_type() == ImportType::Code;

        let mut coff_relocs: Cow<[object::pe::ImageRelocation]> = Cow::Borrowed(&[]);
        if code {
            if self.machine == ImageFileMachine::Amd64 {
                static THUNK_RELOC: [object::pe::ImageRelocation; 1] =
                    [object::pe::ImageRelocation {
                        virtual_address: U32Bytes::from_bytes(2u32.to_le_bytes()),
                        symbol_table_index: U32Bytes::from_bytes(0u32.to_le_bytes()),
                        typ: U16Bytes::from_bytes(IMAGE_REL_AMD64_REL32.to_le_bytes()),
                    }];
                coff_relocs = Cow::Borrowed(&THUNK_RELOC);
            } else if self.machine == ImageFileMachine::I386 {
                static THUNK_RELOC: [object::pe::ImageRelocation; 1] =
                    [object::pe::ImageRelocation {
                        virtual_address: U32Bytes::from_bytes(2u32.to_le_bytes()),
                        symbol_table_index: U32Bytes::from_bytes(0u32.to_le_bytes()),
                        typ: U16Bytes::from_bytes(IMAGE_REL_I386_DIR32.to_le_bytes()),
                    }];
                coff_relocs = Cow::Borrowed(&THUNK_RELOC);
            }
        }

        let mut characteristics = SectionFlags::empty();
        characteristics.set_alignment(4);
        match file.import_type() {
            ImportType::Code => {
                characteristics |=
                    SectionFlags::CntCode | SectionFlags::MemExecute | SectionFlags::MemRead;
            }
            ImportType::Data => {
                characteristics |= SectionFlags::CntInitializedData
                    | SectionFlags::MemRead
                    | SectionFlags::MemWrite;
            }
            ImportType::Const => {
                characteristics |= SectionFlags::CntInitializedData | SectionFlags::MemRead;
            }
        }

        let section_data = if code {
            // jmp [rip + $<symbol>]
            [0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90].as_slice()
        } else {
            &[]
        };

        self.sections.push(Some(ObjectSection {
            name: section_name,
            data: section_data,
            checksum: 0,
            virtual_address: 0,
            length: section_data.len().saturating_sub(2) as u32,
            characteristics,
            coff_relocs,
            associative: None,
            index: SectionIndex(1),
            discarded: AtomicBool::new(false),
            output: OutputSectionId::Null,
        }));

        // TODO: Finish

        Ok(())
    }

    pub fn resolve_symbols(&self, ctx: &LinkContext<'a>, objs: &[ArenaRef<'a, ObjectFile<'a>>]) {
        let live = self.live.load(Ordering::Relaxed);
        for symbol in self.symbols.iter().flatten() {
            if symbol.is_local() || symbol.is_undefined() {
                continue;
            }

            if let Some(section) = symbol
                .section_number
                .index()
                .and_then(|index| self.sections[index.0].as_ref())
                && section.discarded.load(Ordering::Relaxed)
            {
                continue;
            }

            // Skip resolving local weak symbols
            if symbol.is_weak() && symbol.external_id.is_none() {
                continue;
            }

            let external_ref = ctx.symbol_map.get(symbol.external_id.unwrap()).unwrap();
            let mut global = external_ref.write().unwrap();

            // Check if our copy of the symbol should be become the new global
            // symbol used
            let should_claim = |global: &GlobalSymbol| {
                // Always claim symbols if the global one does not have an owner
                let Some(owner_id) = global.owner else {
                    return true;
                };

                let owner = &objs[owner_id.index()];
                let owner_symbol = owner.input_symbol(global.index).unwrap();
                let owner_live = owner.live.load(Ordering::Relaxed);

                // Compare symbol kinds. A greater kind means more symbol resolution
                // strength. Use the first symbol seen if they are equal
                match symbol.kind(live).cmp(&owner_symbol.kind(owner_live)) {
                    std::cmp::Ordering::Equal => self.id < owner_id,
                    o => o == std::cmp::Ordering::Greater,
                }
            };

            if should_claim(&global) {
                global.value = symbol.value;
                global.section_number = symbol.section_number;
                global.index = symbol.index;
                global.owner = Some(self.id);
            }
        }
    }

    pub fn resolve_comdat_leaders(
        &self,
        ctx: &LinkContext<'a>,
        objs: &[ArenaRef<'a, ObjectFile<'a>>],
    ) {
        assert!(self.live.load(Ordering::Relaxed));
        for symbol_index in self.comdat_indicies.iter().copied() {
            let symbol = self.symbols[symbol_index.0].as_ref().unwrap();

            // The stored COMDAT indicies are partitioned with leaders in the
            // front and associative COMDATs after. Once an associative COMDAT
            // is seen, there should not be any more leaders
            if !symbol.is_comdat_leader() {
                break;
            }

            // Section symbols for `IMAGE_COMDAT_SELECT_ASSOCIATIVE` and local
            // COMDATs will get added to this list. Only resolve globally scoped symbols
            if symbol.is_local() {
                continue;
            }

            let external_ref = ctx.symbol_map.get(symbol.external_id.unwrap()).unwrap();
            let mut global = external_ref.write().unwrap();

            let should_claim = |global: &GlobalSymbol| {
                let Some(owner_id) = global.owner else {
                    return true;
                };

                let owner = &objs[owner_id.index()];
                if !owner.live.load(Ordering::Relaxed) {
                    return true;
                }

                let owner_symbol = owner.input_symbol(global.index).unwrap();

                match symbol
                    .comdat_priority(self)
                    .cmp(&owner_symbol.comdat_priority(owner))
                {
                    std::cmp::Ordering::Equal => self.id < owner_id,
                    o => o == std::cmp::Ordering::Greater,
                }
            };

            if should_claim(&global) {
                global.value = symbol.value;
                global.section_number = symbol.section_number;
                global.index = symbol.index;
                global.owner = Some(self.id);
            }
        }
    }

    pub fn discard_unused_comdats(&mut self, ctx: &LinkContext<'a>) -> crate::Result<()> {
        assert!(*self.live.get_mut());
        // TODO: Sort COMDATs and handle discards
        Ok(())
    }

    pub fn include_needed_objects<'scope>(
        &self,
        ctx: &'scope LinkContext<'a>,
        objs: &'scope [ArenaRef<'a, ObjectFile<'a>>],
        scope: &Scope<'scope>,
    ) where
        'a: 'scope,
    {
        assert!(self.live.load(Ordering::Relaxed));
        for symbol in self.symbols.iter().flatten() {
            if symbol.is_local() {
                continue;
            }

            let Some(external_id) = symbol.external_id else {
                continue;
            };

            let external_ref = ctx.symbol_map.get(external_id).unwrap();
            let global = external_ref.read().unwrap();
            if global.traced {
                if symbol.is_defined() {
                    log::info!(logger: ctx, "{}: definition of {}", self.source(), global.demangle(ctx, self.machine));
                } else if symbol.is_weak() {
                    log::info!(logger: ctx, "{}: weak external for {}", self.source(), global.demangle(ctx, self.machine));
                } else {
                    log::info!(logger: ctx, "{}: reference to {}", self.source(), global.demangle(ctx, self.machine));
                }
            }

            let Some(owner) = global.owner.map(|id| &objs[id.index()]) else {
                return;
            };

            let symbol_is_needed = symbol.is_undefined() || symbol.is_common();
            let should_visit = |obj: &ArenaRef<'a, ObjectFile>| {
                obj.live
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .map(|live| !live)
                    .unwrap_or(false)
            };

            if symbol_is_needed && should_visit(owner) {
                if global.traced {
                    log::info!(logger: ctx, "{}: needs {} from {}", self.source(), global.demangle(ctx, self.machine), owner.source());
                }

                scope.spawn(move |scope| {
                    owner.include_needed_objects(ctx, objs, scope);
                });
            }
        }
    }

    pub fn input_section(&self, index: SectionIndex) -> Option<&ObjectSection<'a>> {
        self.sections
            .get(index.0)
            .and_then(|section| section.as_ref())
    }

    pub fn input_section_mut(&mut self, index: SectionIndex) -> Option<&mut ObjectSection<'a>> {
        self.sections
            .get_mut(index.0)
            .and_then(|section| section.as_mut())
    }

    pub fn input_symbol(&self, index: SymbolIndex) -> Option<&ObjectSymbol<'a>> {
        self.symbols.get(index.0).and_then(|symbol| symbol.as_ref())
    }

    /// Returns the DLL name if this COFF contains the DLL name entry for a short
    /// import
    pub fn dllname(&self) -> Option<&'a [u8]> {
        if !self.has_import_data {
            return None;
        }

        let idata_flags =
            SectionFlags::CntInitializedData | SectionFlags::MemRead | SectionFlags::MemWrite;

        for section in self.sections.iter().flatten() {
            if section.data.is_empty() {
                continue;
            }

            if section.name == b".idata$7" && section.characteristics.contains(idata_flags) {
                if let Some(nullbyte) = section.data.iter().position(|ch| *ch == 0) {
                    return Some(&section.data[..nullbyte]);
                } else {
                    return Some(section.data);
                }
            }
        }

        None
    }
}

#[derive(Debug)]
pub struct ObjectSection<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub virtual_address: u32,
    pub checksum: u32,
    pub length: u32,
    pub characteristics: SectionFlags,
    pub index: SectionIndex,
    pub coff_relocs: Cow<'a, [object::pe::ImageRelocation]>,
    pub associative: Option<SectionIndex>,
    pub discarded: AtomicBool,
    pub output: OutputSectionId,
}

impl<'a> ObjectSection<'a> {
    /// Returns `true` if this is a COMDAT section
    pub fn is_comdat(&self) -> bool {
        self.characteristics.contains(SectionFlags::LnkComdat)
    }
}

#[derive(Debug)]
pub struct ObjectSymbol<'a> {
    pub name: &'a [u8],
    pub value: u32,
    pub section_number: SectionNumber,
    pub index: SymbolIndex,
    pub storage_class: StorageClass,
    pub typ: u16,
    pub selection: Option<ComdatSelection>,
    pub external_id: Option<SymbolId>,
}

impl<'a> ObjectSymbol<'a> {
    /// Returns `true` if this is a globally scoped symbol.
    pub fn is_global(&self) -> bool {
        self.storage_class == StorageClass::External
            || self.storage_class == StorageClass::WeakExternal
    }

    /// Returns `true` if this is a local symbol.
    pub fn is_local(&self) -> bool {
        !self.is_global()
    }

    /// Returns `true` if this is an undefined global symbol.
    pub fn is_undefined(&self) -> bool {
        self.storage_class == StorageClass::External
            && self.section_number == SectionNumber::Undefined
            && self.value == 0
    }

    /// Returns `true` if this symbol is defined.
    ///
    /// This only returns `true` for symbols with external or static storage
    /// class
    pub fn is_defined(&self) -> bool {
        self.section_number > SectionNumber::Undefined
            && (self.is_global() || self.storage_class == StorageClass::Static)
    }

    /// Returns `true` if this is a COMMON symbol
    pub fn is_common(&self) -> bool {
        self.storage_class == StorageClass::External
            && self.section_number == SectionNumber::Undefined
            && self.value != 0
    }

    /// Returns `true` if this is weak
    pub fn is_weak(&self) -> bool {
        self.storage_class == StorageClass::WeakExternal
    }

    /// Returns `true` if this is a leader symbol for a COMDAT section
    pub fn is_comdat_leader(&self) -> bool {
        self.selection
            .is_some_and(|selection| selection != ComdatSelection::Associative)
    }

    pub fn kind(&self, live: bool) -> SymbolKind {
        if self.is_defined() {
            if live {
                SymbolKind::Defined
            } else {
                SymbolKind::LazyDefined
            }
        } else if self.is_weak() {
            if live {
                SymbolKind::Weak
            } else {
                SymbolKind::LazyWeak
            }
        } else if self.is_common() {
            if live {
                SymbolKind::Common
            } else {
                SymbolKind::LazyCommon
            }
        } else {
            SymbolKind::Unknown
        }
    }

    /// Returns the COMDAT priority level for this symbol.
    ///
    /// This handles selecting the correct definition for COMDAT leaders.
    /// Resolution for COMDAT leaders only happens on live object files after
    /// [`ObjectFile::include_needed_objects()`] is done.
    ///
    /// Special handling for COMDAT selection only needs to happen on `IMAGE_COMDAT_SELECT_LARGEST`
    /// COMDATs. This is because the COMDAT size is used as an additional factor
    /// for determining symbol strength. The other selection types only use an
    /// arbitrary definition for handling duplicates which will be the definition
    /// from the first live object file processed on the command line.
    ///
    /// The priority is determined by checking if the selection is `IMAGE_COMDAT_SELECT_LARGEST`
    /// and will return 1 + the section length. If this is not an `IMAGE_COMDAT_SELECT_LARGEST`
    /// COMDAT, it will return 0 and the priority will be determined based on file ordering.
    pub fn comdat_priority(&self, obj: &ObjectFile) -> usize {
        if self
            .selection
            .is_some_and(|selection| selection == ComdatSelection::Largest)
        {
            self.section_number
                .index()
                .and_then(|index| obj.input_section(index))
                .map(|section| section.length as usize + 1usize)
                .unwrap_or(0)
        } else {
            0
        }
    }
}

/// Symbol kinds.
///
/// These are ordered and can be compared to see if one kind has a higher resolution
/// strength over the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymbolKind {
    Unknown,
    LazyCommon,
    Common,
    LazyWeak,
    LazyDefined,
    Weak,
    Defined,
}
