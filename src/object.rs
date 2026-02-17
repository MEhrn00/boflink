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
    ReadRef, SectionIndex, SymbolIndex, U16Bytes,
    coff::{CoffFile, CoffHeader, SectionTable},
    pe,
};
use rayon::Scope;

use crate::{
    ErrorContext,
    arena::ArenaRef,
    bit_set::FixedDenseBitSet,
    coff::{CoffFlags, CoffSymbolRef, Feat00Flags, ImageFileMachine, SectionFlags, SymbolTable},
    context::LinkContext,
    inputs::{InputFile, InputFileSource},
    make_error,
    outputs::OutputSectionId,
    symbols::{ExternalRef, GlobalSymbol, Symbol, SymbolId, SymbolPriority},
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

    /// Creates a new [`ObjectFileId`] that should be used for the internal
    /// object file
    pub const fn internal() -> Self {
        ObjectFileId(0)
    }

    /// Returns true if this is [`ObjectFileId::internal()`]
    pub const fn is_internal(&self) -> bool {
        self.0 == Self::internal().0
    }

    /// Returns the index used for getting the object file from the list of input
    /// objects
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// An object file being linked.
#[derive(Debug)]
pub struct ObjectFile<'a> {
    /// The id of this file.
    pub id: ObjectFileId,

    /// Raw COFF section headers.
    ///
    /// May be empty in a few scenarios:
    /// - This is the internal object file for inserting linker-synthesized sections
    /// - There were no sections inside the read object file
    /// - This object file was initialized from a short import file
    pub coff_sections: SectionTable<'a>,

    /// The initialized input sections from this object file that may contribute
    /// to output sections.
    ///
    /// The sections in this list are structured so that 1-based section numbers
    /// from the original object file can be used to index into this table. It
    /// allows for symbols and relocations from the original object file to retain
    /// the same indicies instead of needing to go through and rewrite them.
    ///
    /// The table uses 1-based indicies with the first section always being `None`.
    /// Using 1-based indicies is similar to the ELF `SHT_NULL` section but it
    /// simplifies things here too. Symbols used 1-based indicies for the section
    /// number of the definition and auxiliary section symbols use 1-based indicies
    /// for associative sections.
    pub sections: Vec<Option<InputSection<'a>>>,

    /// Raw COFF symbol table.
    ///
    /// May be empty in a few scenarios:
    /// - This is the internal object file for inserting linker-synthesized symbols
    /// - There were no symbols inside the read object file
    /// - This object file was initialized from a short import file
    pub coff_symbols: SymbolTable<'a>,

    /// Initialized input symbols.
    ///
    /// The symbols in this vec can be indexed using the original symbol indicies
    /// from the COFF.
    pub symbols: Vec<Option<InputSymbol<'a>>>,

    /// Indicies of COMDAT leader symbols.
    ///
    /// Initialized during [`ObjectFile::initialize_symbols()`].
    pub comdat_leaders: Vec<SymbolIndex>,

    /// File should be included in the linked output.
    ///
    /// This is used as the main indicator for object file inclusion.
    pub live: AtomicBool,

    /// The file associated with this object file
    pub file: InputFile<'a>,

    /// File architecture
    pub machine: ImageFileMachine,

    /// The `IMAGE_FILE_*` flags of the object file.
    ///
    /// This is largely unused for object files.
    pub characteristics: CoffFlags,

    /// Index of the .llvm_addrsig section.
    ///
    /// This will be 0 if not present. The addrsig section is currently not used
    /// but will be needed in the future
    pub addrsig_index: SectionIndex,

    /// Flags from the @feat.00 symbol.
    ///
    /// These flags contain additional information on different compiler features
    /// that may require runtime support. Most of these runtime support features
    /// are not implemented with COFF loaders so the flags here are used to
    /// provide additional context if errors occur due to them.
    pub feat_flags: Feat00Flags,

    /// True if there is import information inside of this object file.
    ///
    /// This will be set if the object file was read from an import library that
    /// either contains legacy import-style COFFs with `.idata$<number>` sections
    /// or the object file was derived from a short import file.
    ///
    /// The import data is used for associating resolved DLL imported symbols to
    /// their associated library names.
    pub has_import_data: bool,

    /// True if this object file has any common symbols. Common symbols may need
    /// to have space allocated for them
    pub has_common_symbols: bool,

    /// Flag indicating if the file was read in a lazy context. This is not used
    /// as a direct indicator for determining what object files should be included
    /// in the link but non-lazy object files most likely will be included.
    ///
    /// An object file's lazy state is determined using these rules:
    /// - Files read from disk that are object files default to non-lazy.
    ///   - They will be considered lazy if surrounded by a set of `--start-lib ... --end-lib`
    ///     arguments.
    /// - Files that are members of archives read from disk are considered lazy.
    ///   - They will be considered non-lazy if the archive this object file is from
    ///     was surrounded by a set of `--whole-archive ... --no-whole-archive` arguments.
    pub lazy: bool,
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
            symbols: Vec::new(),
            sections: Vec::new(),
            addrsig_index: SectionIndex(0),
            feat_flags: Feat00Flags::empty(),
            comdat_leaders: Vec::new(),
            has_common_symbols: false,
            has_import_data: false,
        }
    }

    pub fn internal_obj() -> Self {
        Self::new(ObjectFileId::internal(), InputFile::internal(), false)
    }

    pub fn is_internal_obj(&self) -> bool {
        self.id.is_internal()
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
        self.coff_symbols = SymbolTable::parse(header, self.file.data).unwrap();

        self.initialize_externals(ctx)?;
        if !self.lazy {
            self.initialize_sections(ctx)?;
            self.initialize_symbols()?;
        }

        Ok(())
    }

    /// Initializes external references inside the object file.
    ///
    /// This will only go through linkage scoped symbols inside the object file
    /// to setup the bare minimum needed for doing symbol resolution. It should
    /// only be called once during the initial parsing phase.
    fn initialize_externals(&mut self, ctx: &LinkContext<'a>) -> crate::Result<()> {
        self.symbols.resize_with(self.coff_symbols.len(), || None);

        let strtab = self.coff_symbols.strings();
        for (i, symbol) in self.coff_symbols.iter() {
            if !symbol.is_global() {
                continue;
            }

            let name = symbol
                .name_bytes(strtab)
                .with_context(|| format!("reading name for symbol {i}"))?;

            let mut weak_default = SymbolIndex(0);
            let mut hidden = false;

            if symbol.has_aux_weak_external() {
                let weak_aux = self
                    .coff_symbols
                    .aux_weak_external(i)
                    .with_context(|| format!("reading auxiliary weak external for symbol {i}"))?;

                weak_default = weak_aux.default_symbol();
                let _ = self
                    .coff_symbols
                    .symbol(weak_default)
                    .with_context(|| format!("reading tag index for weak external symbol {i}"))?;

                let weak_search = weak_aux.weak_search_type.get(object::LittleEndian);
                if weak_search == pe::IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY {
                    hidden = true;
                }
            }

            let entry = &mut self.symbols[i.0];
            debug_assert!(
                entry.is_none(),
                "ObjectFile::initialize_externals() found existing entry at {i}"
            );
            let _ = entry.insert(InputSymbol::External(ExternalSymbol {
                id: ctx.symbol_map.get_or_create_default(name),
                weak_default,
                hidden,
                selection: 0,
            }));
        }

        Ok(())
    }

    /// Initializes input sections.
    ///
    /// Sections should only be initialized on live or non-lazy object files.
    pub fn initialize_sections(&mut self, ctx: &LinkContext<'a>) -> crate::Result<()> {
        debug_assert!(!self.lazy || *self.live.get_mut());
        self.sections
            .resize_with(self.coff_sections.len() + 1, || None);

        let mut comdats = 0;
        let strtab = self.coff_symbols.strings();
        for (i, coff_section) in self.coff_sections.enumerate() {
            let name = coff_section
                .name(strtab)
                .with_context(|| format!("reading long name at section number {i}"))?;

            let mut characteristics = SectionFlags::from_bits_retain(
                coff_section.characteristics.get(object::LittleEndian),
            );

            // addrsig section is not used yet but store it anyway
            if name == b".llvm_addrsig" {
                self.addrsig_index = i;
                continue;
            }

            // Skip over LLVM call graph profile
            if name == b".llvm.call-graph-profile" {
                continue;
            }

            // Skip other metadata sections marked for removal during linking.
            // We keep sections marked as `IMAGE_SCN_MEM_DISCARDABLE`. Stripping
            // them is left for the COFF loader to do or the user to do manually
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

            let relocs = coff_section
                .coff_relocations(self.file.data)
                .with_context(|| format!("reading relocations for section number {i}"))?;

            let data = coff_section
                .coff_data(self.file.data)
                .map_err(|_| make_error!("reading section data for section number {i}: PointerToRawData offset is not valid"))?;

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
                length = coff_section.size_of_raw_data.get(object::LittleEndian);
            }

            if characteristics.contains(SectionFlags::LnkComdat) {
                comdats += 1;
            }

            let entry = &mut self.sections[i.0];
            debug_assert!(
                entry.is_none(),
                "ObjectFile::initialize_sections() found existing entry at {i}"
            );
            let _ = entry.insert(InputSection {
                name,
                data,
                length,
                checksum: 0,
                characteristics,
                coff_relocs: relocs.into(),
                index: i,
                followers: Vec::new(),
                discarded: AtomicBool::new(false),
                gc_visited: AtomicBool::new(false),
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

    /// Initializes remaining symbols and COMDAT groups
    pub fn initialize_symbols(&mut self) -> crate::Result<()> {
        debug_assert!(!self.lazy || *self.live.get_mut());
        self.symbols.resize_with(self.coff_symbols.len(), || None);

        // Selections for COMDAT sections
        let mut comdat_sels: Box<[u8]> = vec![0; self.coff_sections.len() + 1].into_boxed_slice();

        let strtab = self.coff_symbols.strings();
        for (i, symbol) in self.coff_symbols.iter() {
            if symbol.is_debug() {
                continue;
            }

            let name = symbol
                .name_bytes(strtab)
                .with_context(|| format!("reading name for symbol {i}"))?;

            if symbol.is_absolute() {
                if name == b"@feat.00" {
                    self.feat_flags = Feat00Flags::from_bits_retain(symbol.value());
                    continue;
                } else if name == b"@comp.id" {
                    continue;
                }
            }

            if symbol.is_local() {
                let entry = &mut self.symbols[i.0];
                debug_assert!(
                    entry.is_none(),
                    "ObjectFile::initialize_locals() found existing local symbol entry at {i}"
                );
                let _ = entry.insert(InputSymbol::Local(LocalSymbol {
                    name,
                    value: symbol.value(),
                    section_number: symbol.section_number(),
                    typ: symbol.typ(),
                    storage_class: symbol.storage_class(),
                }));
            }

            let Some(section_index) = symbol.section() else {
                continue;
            };

            let section = {
                let section = self.sections.get_mut(section_index.0).ok_or_else(|| {
                    make_error!("symbol at index {i}: section number is invalid {section_index}",)
                })?;

                let Some(section) = section else {
                    continue;
                };
                section
            };

            // Handle section symbols
            if symbol.has_aux_section() {
                let aux_section = self
                    .coff_symbols
                    .aux_section(i)
                    .with_context(|| format!("symbol at index {i}"))?;

                // Overwrite section length using the auxiliary symbol length
                // if non-zero. GCC will insert padding at the end of sections
                // that contain initialized data. The length field here reflects
                // the actual section size and not the padded size
                let length = aux_section.length.get(object::LittleEndian);
                if length > 0 {
                    section.length = length;
                }
                section.checksum = aux_section.check_sum.get(object::LittleEndian);

                if aux_section.selection == pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE {
                    // Add the associative section to the parent's adjacency list
                    let number = aux_section.number.get(object::LittleEndian);
                    let parent_index = SectionIndex(number as usize);
                    let parent = self.sections
                        .get_mut(parent_index.0)
                        .and_then(|section| section.as_mut())
                        .with_context(|| format!("auxiliary section symbol at index {i} associative section is invalid"))?;
                    parent.followers.push(section_index);
                } else if aux_section.selection == pe::IMAGE_COMDAT_SELECT_EXACT_MATCH
                    && section.checksum == 0
                    && !section.data.is_empty()
                {
                    // If the COMDAT selection type is exact match, the checksum
                    // needs to be valid
                    section.compute_checksum();
                } else if section.is_comdat() {
                    // All other COMDATs get marked as pending for the leader to
                    // handle. The leader symbol will get set to the section
                    // symbol until it is paired with the correct leader
                    let _ = comdat_sels[section_index.0] = aux_section.selection;
                }

                continue;
            } else if section.is_comdat() {
                // Handle leaders for pending COMDATs
                let selection_entry = &mut comdat_sels[section_index.0];
                if *selection_entry > 0 {
                    let selection = std::mem::replace(selection_entry, 0);
                    if let Some(external) = self.symbols[i.0]
                        .as_mut()
                        .and_then(|symbol| symbol.external_mut())
                    {
                        external.selection = selection;
                        self.comdat_leaders.push(i);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn resolve_symbols(&self, ctx: &LinkContext<'a>, objs: &[ArenaRef<'a, ObjectFile<'a>>]) {
        let live = self.live.load(Ordering::Relaxed);
        for (i, symbol) in self.coff_symbols.iter() {
            if symbol.is_local() || symbol.is_undefined() {
                continue;
            }

            if let Some(section) = symbol.section().and_then(|index| self.section(index))
                && section.discarded.load(Ordering::Relaxed)
            {
                continue;
            }

            let external_symbol = self.external_symbol(i).unwrap();
            if external_symbol.hidden {
                continue;
            }

            let (_, external_ref) = self.external_symbol_ref(ctx, i).unwrap();
            let mut global = external_ref.write();

            // Check if our copy of the symbol should be become the new global
            // symbol used
            let should_claim = |global: &GlobalSymbol| {
                // Always claim symbols if the global one is undefined and owned
                // by the internal object file
                if global.owner.is_internal() {
                    return true;
                }

                let owner = &objs[global.owner.index()];
                let owner_live = owner.live.load(Ordering::Relaxed);

                // Compare symbol kinds. A greater kind means more symbol resolution
                // strength. Use the first symbol seen if they are equal
                match SymbolPriority::new(symbol, live).cmp(&global.priority(owner_live)) {
                    std::cmp::Ordering::Equal => self.id < owner.id,
                    o => o == std::cmp::Ordering::Greater,
                }
            };

            if should_claim(&global) {
                global.owner = self.id;
                global.value = symbol.value();
                global.section_number = symbol.section_number();
                global.typ = symbol.typ();
                global.storage_class = symbol.storage_class();
                global.index = i;
            }
        }
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
        for (i, symbol) in self.coff_symbols.iter() {
            if symbol.is_local() {
                continue;
            }

            let external = self.external_symbol(i).unwrap();
            if external.hidden {
                continue;
            }

            let (_, external_ref) = self.external_symbol_ref(ctx, i).unwrap();
            let global = external_ref.read();
            if global.traced {
                if !symbol.is_undefined() {
                    log::info!(logger: ctx, "{}: definition of {}", self.source(), global.demangle(ctx, self.machine));
                } else if symbol.is_weak() {
                    log::info!(logger: ctx, "{}: weak external for {}", self.source(), global.demangle(ctx, self.machine));
                } else {
                    log::info!(logger: ctx, "{}: reference to {}", self.source(), global.demangle(ctx, self.machine));
                }
            }

            if global.owner.is_internal() {
                continue;
            }

            let owner = &objs[global.owner.index()];

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

    pub fn resolve_comdat_leaders(
        &self,
        ctx: &LinkContext<'a>,
        objs: &[ArenaRef<'a, ObjectFile<'a>>],
    ) {
        assert!(self.live.load(Ordering::Relaxed));

        for &i in self.comdat_leaders.iter() {
            let Some((external, external_ref)) = self.external_symbol_ref(ctx, i) else {
                // Global COMDATs should always have an external reference.
                assert!(!self.coff_symbol(i).unwrap().is_global());
                continue;
            };

            // All of the COMDAT types except for largest choose an arbitrary
            // definition. This will be the first definition seen due to regular
            // symbol resolution passes. Largest COMDATs contain an additional
            // factor which could shift the selected definition
            if external.selection != pe::IMAGE_COMDAT_SELECT_LARGEST {
                continue;
            }

            let symbol = self.coff_symbol(i).unwrap();
            let mut global = external_ref.write();

            let should_claim = |global: &GlobalSymbol| {
                if global.owner.is_internal() && global.is_undefined() {
                    return true;
                }

                let owner = &objs[global.owner.index()];
                if !owner.live.load(Ordering::Relaxed) {
                    return true;
                }

                let owner_symbol = owner.coff_symbol(global.index).unwrap();
                let section = self.section(symbol.section().unwrap()).unwrap();

                let owner_section = owner.section(owner_symbol.section().unwrap()).unwrap();
                match section.length.cmp(&owner_section.length) {
                    // Choose the first definition if they are the same size
                    std::cmp::Ordering::Equal => self.id < owner.id,
                    o => o == std::cmp::Ordering::Greater,
                }
            };

            if should_claim(&global) {
                global.owner = self.id;
                global.value = symbol.value();
                global.section_number = symbol.section_number();
                global.typ = symbol.typ();
                global.index = i;
            }
        }
    }

    pub fn discard_unclaimed_comdats(&mut self, ctx: &LinkContext<'a>) {
        assert!(*self.live.get_mut());

        // Visit sections which have not been visited before. If a section has
        // been visited, check its discard status that was set by the last COMDAT leader
        // - If the visited COMDAT is discarded but this leader is kept, continue visiting followers and mark them live
        // - If the visited COMDAT was kept and this leader is kept, stop traversing the follower chain
        // - If the visited COMDAT was kept but this leader was discarded, be keep the followers
        //   live for the other leader
        let should_visit = |section: &mut InputSection, discard: bool| -> bool {
            *section.discarded.get_mut() && !discard
        };

        let mut visited = FixedDenseBitSet::new_empty(self.sections.len());
        for &i in self.comdat_leaders.iter() {
            let Some((_, external_ref)) = self.external_symbol_ref(ctx, i) else {
                continue;
            };

            // Set the discard status
            let discard = external_ref.read().owner != self.id;
            let symbol = self.coff_symbol(i).unwrap();
            let section_index = symbol.section().unwrap();

            // Do a DFS traversal over followers to update discard status
            let mut stack = vec![section_index];
            while let Some(section_index) = stack.pop() {
                let section = self.sections[section_index.0].as_mut().unwrap();
                if !visited.contains(section.index.0) || should_visit(section, discard) {
                    visited.insert(section.index.0);
                    *section.discarded.get_mut() = discard;
                    stack.extend(&section.followers);
                }
            }
        }
    }

    /// Fixes definitions for common symbols
    ///
    /// The rules for this are global definition > common definition > weak definition.
    /// In rare cases, this precedence can be out of order when common symbols
    /// are intermixed with weak/common symbols from extracted archive members.
    ///
    /// Regular symbol resolution will select the first common symbol seen if
    /// there are duplicates to handle archive extraction. If duplicate common
    /// symbols are present after archive extraction, the one with the largest
    /// definition should be used.
    ///
    /// There are many weird rules with common symbols. They hardly make sense
    /// in C/C++ but for some reason, were added to mimic FORTRAN 77 behavior.
    /// GCC and Clang have defaulted to `-fno-common` so common symbols should
    /// not be seen when using those compilers.
    /// MSVC unfortunately still uses common symbols...
    pub fn fix_commons_resolution(&mut self, ctx: &LinkContext<'a>) {
        if !self.has_common_symbols {
            return;
        }

        for (i, symbol) in self.coff_symbols.iter() {
            if !symbol.is_common() {
                continue;
            }

            let (_, external_ref) = self.external_symbol_ref(ctx, i).unwrap();
            let mut global = external_ref.write();
            if global.owner == self.id {
                continue;
            }

            if global.is_common() {
                if symbol.value() > global.value() {
                    global.owner = self.id;
                    global.value = symbol.value();
                    global.section_number = symbol.section_number();
                    global.typ = symbol.typ();
                    global.storage_class = symbol.storage_class();
                    global.index = i;
                }

                continue;
            }

            if global.is_weak() {
                global.owner = self.id;
                global.value = symbol.value();
                global.section_number = symbol.section_number();
                global.typ = symbol.typ();
                global.storage_class = symbol.storage_class();
                global.index = i;
                continue;
            }
        }
    }

    pub fn collect_duplicate_symbol_errors(
        &self,
        ctx: &LinkContext<'a>,
        objs: &[ArenaRef<'a, ObjectFile<'a>>],
    ) -> Vec<String> {
        if !self.live.load(Ordering::Relaxed) {
            return Vec::new();
        }

        let mut errors = Vec::new();
        for (i, symbol) in self.coff_symbols.iter() {
            if symbol.is_local() || symbol.is_undefined() || symbol.is_common() || symbol.is_weak()
            {
                continue;
            }

            let (external, external_ref) = self.external_symbol_ref(ctx, i).unwrap();

            // Handle COMDAT selections
            if external.selection != 0 {
                let global = external_ref.read();

                // The COFF spec does not explictly state how to handle COMDAT
                // definitions with differing selection types. It makes sense
                // to just throw an error on differing types since that would
                // indicate possible ODR issues. LLD seems to do this but with
                // some added leniency to account for MSVC/GCC/Clang differences.
                // For now, just follow the table on how to handle COMDAT resolution
                // errors for this definition without worrying if the selection
                // types for each symbol match. This is probably not correct and
                // will need to be fixed later.
                let multiply_defined = match external.selection {
                    pe::IMAGE_COMDAT_SELECT_NODUPLICATES => global.owner != self.id,
                    pe::IMAGE_COMDAT_SELECT_SAME_SIZE => {
                        let section = self.section(symbol.section().unwrap()).unwrap();
                        let owner = &objs[global.owner.index()];
                        let owner_section = owner.section(global.section().unwrap()).unwrap();
                        section.length != owner_section.length
                    }
                    pe::IMAGE_COMDAT_SELECT_EXACT_MATCH => {
                        let section = self.section(symbol.section().unwrap()).unwrap();
                        let owner = &objs[global.owner.index()];
                        let owner_section = owner.section(global.section().unwrap()).unwrap();

                        section.length == owner_section.length
                            && section.checksum == owner_section.checksum
                    }
                    pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE => panic!(
                        "globally scoped COMDAT leader should not have associative selection"
                    ),
                    // These do not throw duplicate errors
                    pe::IMAGE_COMDAT_SELECT_ANY | pe::IMAGE_COMDAT_SELECT_LARGEST => false,
                    _ => continue,
                };

                if multiply_defined {
                    let owner = &objs[global.owner.index()];
                    // Yes, "multiply defined symbol" is a weird and rather vague error message.
                    // But, that is what the error message should be...
                    errors.push(format!(
                        "multiply defined symbol: {name}\n\
                            defined at {owner}\n\
                            defined at {this}",
                        name = global.demangle(ctx, self.machine),
                        owner = owner.source(),
                        this = self.source(),
                    ));
                }
            } else if let Some(section) = self.section(symbol.section().unwrap())
                && section.discarded.load(Ordering::Relaxed)
            {
                // Symbol is defined in a section discarded due to COMDAT deduplication.
                continue;
            } else {
                // Regularly defined symbol
                let global = external_ref.read();
                if global.owner != self.id {
                    let owner = &objs[global.owner.index()];
                    errors.push(format!(
                        "duplicate symbol: {name}\n\
                                    defined at {owner}\n\
                                    defined at {this}",
                        name = global.demangle(ctx, self.machine),
                        owner = owner.source(),
                        this = self.source(),
                    ));
                }
            }
        }

        errors
    }

    pub fn claim_undefined_symbols(&mut self, ctx: &LinkContext<'a>) {}

    pub fn section(&self, index: SectionIndex) -> Option<&InputSection<'a>> {
        self.sections
            .get(index.0)
            .and_then(|section| section.as_ref())
    }

    pub fn section_mut(&mut self, index: SectionIndex) -> Option<&mut InputSection<'a>> {
        self.sections
            .get_mut(index.0)
            .and_then(|section| section.as_mut())
    }

    pub fn coff_symbol(&self, index: SymbolIndex) -> Option<CoffSymbolRef<'a>> {
        self.coff_symbols.symbol(index).ok()
    }

    pub fn symbol(&self, index: SymbolIndex) -> Option<&InputSymbol<'a>> {
        self.symbols.get(index.0).and_then(|symbol| symbol.as_ref())
    }

    pub fn symbol_mut(&mut self, index: SymbolIndex) -> Option<&mut InputSymbol<'a>> {
        self.symbols
            .get_mut(index.0)
            .and_then(|symbol| symbol.as_mut())
    }

    pub fn local_symbol(&self, index: SymbolIndex) -> Option<&LocalSymbol<'a>> {
        self.symbol(index).and_then(|symbol| symbol.local())
    }

    pub fn local_symbol_mut(&mut self, index: SymbolIndex) -> Option<&mut LocalSymbol<'a>> {
        self.symbol_mut(index).and_then(|symbol| symbol.local_mut())
    }

    pub fn external_symbol(&self, index: SymbolIndex) -> Option<&ExternalSymbol> {
        self.symbol(index).and_then(|symbol| symbol.external())
    }

    pub fn external_symbol_mut(&mut self, index: SymbolIndex) -> Option<&mut ExternalSymbol> {
        self.symbol_mut(index)
            .and_then(|symbol| symbol.external_mut())
    }

    pub fn external_symbol_ref<'ctx>(
        &self,
        ctx: &'ctx LinkContext<'a>,
        index: SymbolIndex,
    ) -> Option<(&ExternalSymbol, ExternalRef<'ctx, 'a>)> {
        if let Some(symbol) = self.external_symbol(index) {
            let id = symbol.id;
            ctx.symbol_map.get(id).map(|external| (symbol, external))
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct InputSection<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub checksum: u32,
    pub length: u32,
    pub characteristics: SectionFlags,
    pub index: SectionIndex,
    pub coff_relocs: Cow<'a, [object::pe::ImageRelocation]>,
    pub followers: Vec<SectionIndex>,
    pub discarded: AtomicBool,
    pub gc_visited: AtomicBool,
    pub output: OutputSectionId,
}

impl<'a> std::default::Default for InputSection<'a> {
    fn default() -> Self {
        Self {
            name: Default::default(),
            data: Default::default(),
            checksum: 0,
            length: 0,
            characteristics: SectionFlags::empty(),
            index: SectionIndex(0),
            coff_relocs: Default::default(),
            followers: Vec::new(),
            discarded: AtomicBool::new(false),
            gc_visited: AtomicBool::new(false),
            output: OutputSectionId::new(0),
        }
    }
}

impl<'a> InputSection<'a> {
    /// Returns `true` if this is a COMDAT section
    pub fn is_comdat(&self) -> bool {
        self.characteristics.contains(SectionFlags::LnkComdat)
    }

    /// Computes and updates the section data checksum field
    pub fn compute_checksum(&mut self) {
        self.checksum = section_checksum(self.data);
    }
}

/// Input symbols for an object file.
///
/// An object file contains two types of input symbols. An external or a local.
/// This is slightly different than the symbol storage class scope
/// (`IMAGE_SYM_CLASS_EXTERNAL`, `IMAGE_SYM_CLASS_STATIC`).
/// This is used to determine the ownership of the symbol. Symbols are either
/// owned by an object file or by the global symbol map. A symbol owned by the
/// symbol map has shared ownership between 1 or more object files. In most instances,
/// this will follow the storage class scope.
#[derive(Debug)]
pub enum InputSymbol<'a> {
    /// Symbol is owned by the object file.
    Local(LocalSymbol<'a>),

    /// Symbol is owned by the global symbol map and this is the ID used to
    /// access it
    External(ExternalSymbol),
}

impl<'a> InputSymbol<'a> {
    pub fn local(&self) -> Option<&LocalSymbol<'a>> {
        if let Self::Local(symbol) = self {
            Some(symbol)
        } else {
            None
        }
    }

    pub fn local_mut(&mut self) -> Option<&mut LocalSymbol<'a>> {
        if let Self::Local(symbol) = self {
            Some(symbol)
        } else {
            None
        }
    }

    pub fn external(&self) -> Option<&ExternalSymbol> {
        if let Self::External(symbol) = self {
            Some(symbol)
        } else {
            None
        }
    }

    pub fn external_mut(&mut self) -> Option<&mut ExternalSymbol> {
        if let Self::External(symbol) = self {
            Some(symbol)
        } else {
            None
        }
    }
}

/// A symbol that is owned by an object file.
#[derive(Debug, Clone)]
pub struct LocalSymbol<'a> {
    pub name: &'a [u8],
    pub value: u32,
    pub section_number: u16,
    pub typ: u16,
    pub storage_class: u8,
}

impl<'a> Symbol for &LocalSymbol<'a> {
    fn value(&self) -> u32 {
        self.value
    }

    fn section_number(&self) -> u16 {
        self.section_number
    }

    fn typ(&self) -> u16 {
        self.typ
    }

    fn storage_class(&self) -> u8 {
        self.storage_class
    }
}

impl<'a> Symbol for &mut LocalSymbol<'a> {
    fn value(&self) -> u32 {
        self.value
    }

    fn section_number(&self) -> u16 {
        self.section_number
    }

    fn typ(&self) -> u16 {
        self.typ
    }

    fn storage_class(&self) -> u8 {
        self.storage_class
    }
}

/// Symbol that is owned by the symbol map.
///
/// The fields here should be exclusive to the object file and shared data kept
/// in the global symbol map
#[derive(Debug, Clone)]
pub struct ExternalSymbol {
    /// Id of the global symbol in the symbol map
    pub id: SymbolId,

    /// The default symbol index if this is a weak external.
    ///
    /// This will be 0 if the symbol is not a weak external. The weak status of
    /// the symbol should be checked through the corresponding COFF symbol
    pub weak_default: SymbolIndex,

    /// Contains the COMDAT selection if this is a COMDAT leader or 0
    pub selection: u8,

    /// Weak externals include an `IMAGE_WEAK_EXTERN_SEARCH_*` characteristic
    /// value within the auxiliary symbol table record. This indicates whether the
    /// symbol should be searched for during symbol resolution.
    /// A `IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY` will make the external symbol
    /// "hidden" meaning that it should not be used to resolve references but
    /// a strong symbol that ends up being defined will take the place of it.
    ///
    /// This is used so that weak symbols do not cause archive extraction if
    /// that is not intended.
    pub hidden: bool,
}

/// COMDAT group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComdatGroup {
    /// Index of the leader symbol.
    ///
    /// This will be the index of the section symbol if there is no leader symbol.
    /// It is technically invalid to have a COMDAT section without a leader but
    /// MinGW will create them anyway.
    pub leader: SymbolIndex,

    /// COMDAT selection type
    pub selection: u8,
}

fn section_checksum(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new_with_initial(u32::MAX);
    h.update(data);
    !h.finalize()
}
