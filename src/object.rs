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
    collections::HashSet,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

use bstr::BStr;
use object::{
    ReadRef, SectionIndex, SymbolIndex, U16Bytes,
    coff::{CoffFile, CoffHeader, ImageSymbol},
    pe,
};
use rayon::Scope;

use crate::{
    ErrorContext,
    arena::ArenaRef,
    bit_set::FixedBitSet,
    coff::{
        CoffFlags, Feat00Flags, ImageFileMachine, Relocation, Section, SectionTable, Symbol,
        SymbolTable,
    },
    context::LinkContext,
    inputs::{InputFile, InputFileSource},
    make_error,
    outputs::OutputSectionId,
    symbols::{ExternalRef, GlobalSymbol, SymbolId, SymbolPriority},
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

    /// Raw COFF symbol table.
    ///
    /// May be empty in a few scenarios:
    /// - This is the internal object file for inserting linker-synthesized symbols
    /// - There were no symbols inside the read object file
    /// - This object file was initialized from a short import file
    pub coff_symbols: SymbolTable<'a>,

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
    pub sections: InputSectionTable<'a>,

    /// Initialized input symbols.
    ///
    /// The symbols in this vec can be indexed using the original symbol indicies
    /// from the COFF.
    pub symbols: ObjectFileSymbolTable<'a>,

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
            live: AtomicBool::new(false),
            machine: ImageFileMachine::Unknown,
            characteristics: CoffFlags::empty(),
            coff_sections: Default::default(),
            coff_symbols: Default::default(),
            symbols: ObjectFileSymbolTable::new(),
            sections: InputSectionTable::new(),
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
                .name(strtab)
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

            let entry = self.symbols.symbol_entry_mut(i).unwrap();
            debug_assert!(
                entry.is_none(),
                "ObjectFile::initialize_externals() found existing entry at {i}"
            );
            let _ = entry.insert(ObjectFileSymbol::External(ExternalSymbol {
                id: ctx.symbol_map.get_or_create_default(BStr::new(name)),
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
        debug_assert!(!self.lazy || self.is_live());
        self.sections
            .resize_with(self.coff_sections.len() + 1, || None);

        let mut comdats = 0;
        let strtab = self.coff_symbols.strings();
        for (i, section) in self.coff_sections.enumerate() {
            let name = section
                .name(strtab)
                .with_context(|| format!("reading long name at section number {i}"))?;

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
            if section.characteristics() & pe::IMAGE_SCN_LNK_REMOVE != 0 {
                continue;
            }

            let is_dwarf = || {
                let flags = pe::IMAGE_SCN_MEM_READ | pe::IMAGE_SCN_MEM_DISCARDABLE;
                name.starts_with(b".debug_") && section.characteristics() & flags == flags
            };

            // Skip debug sections if using `--strip-debug`
            if ctx.options.strip_debug && (is_dwarf() || section.is_codeview()) {
                continue;
            }

            let relocs = section
                .coff_relocations(self.file.data)
                .with_context(|| format!("reading relocations for section number {i}"))?;

            let data = section
                .coff_data(self.file.data)
                .map_err(|_| make_error!("reading section data for section number {i}: PointerToRawData offset is not valid"))?;

            let mut length = data.len() as u32;
            // If the section contains uninitialized data, use the size_of_raw_data field
            // for the length
            if section.contains_uninitialized_data() {
                length = section.size_of_raw_data();
            }

            if section.is_comdat() {
                comdats += 1;
            }

            let entry = self.sections.section_entry_mut(i).unwrap();
            debug_assert!(
                entry.is_none(),
                "ObjectFile::initialize_sections() found existing entry at {i}"
            );
            let _ = entry.insert(InputSection::new(name, data, length, section, relocs));
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
        debug_assert!(!self.lazy || self.is_live());
        self.symbols.resize_with(self.coff_symbols.len(), || None);

        // Selections for COMDAT sections
        let mut comdat_sels: Box<[u8]> = vec![0; self.coff_sections.len() + 1].into_boxed_slice();

        let strtab = self.coff_symbols.strings();
        for (i, symbol) in self.coff_symbols.iter() {
            if symbol.is_debug() {
                continue;
            }

            let name = symbol
                .name(strtab)
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
                let entry = self.symbols.symbol_entry_mut(i).unwrap();
                debug_assert!(
                    entry.is_none(),
                    "ObjectFile::initialize_locals() found existing local symbol entry at {i}"
                );
                let _ = entry.insert(ObjectFileSymbol::Local(LocalSymbol {
                    name: BStr::new(name),
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
                let section = self
                    .sections
                    .section_entry_mut(section_index)
                    .ok_or_else(|| {
                        make_error!(
                            "symbol at index {i}: section number is invalid {section_index}",
                        )
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

                section.checksum = aux_section.check_sum.get(object::LittleEndian);

                // Overwrite section length using the auxiliary symbol length
                // if non-zero. GCC will insert padding at the end of sections
                // that contain initialized data. The length field here reflects
                // the actual section size and not the padded size
                let length = aux_section.length.get(object::LittleEndian);
                if length > 0 {
                    section.length = length;
                }

                if aux_section.selection == pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE {
                    // Add the associative section to the parent's adjacency list
                    let number = aux_section.number.get(object::LittleEndian);
                    let parent_index = SectionIndex(number as usize);
                    let parent = self.sections.section_mut(parent_index).with_context(|| {
                        format!(
                            "auxiliary section symbol at index {i} associative section is invalid"
                        )
                    })?;
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
                    comdat_sels[section_index.0] = aux_section.selection;
                }

                continue;
            } else if section.is_comdat() {
                // Handle leaders for pending COMDATs
                let selection_entry = &mut comdat_sels[section_index.0];
                if *selection_entry > 0 {
                    let selection = std::mem::replace(selection_entry, 0);
                    if let Some(external) = self.symbols.external_symbol_mut(i) {
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

            if let Some(section) = symbol
                .section()
                .and_then(|index| self.sections.section(index))
                && section.discarded.load(Ordering::Relaxed)
            {
                continue;
            }

            let (external_symbol, external_ref) =
                self.symbols.external_symbol_ref2(ctx, i).unwrap();
            if external_symbol.hidden {
                continue;
            }

            let mut global = external_ref.write();

            // Check if our copy of the symbol should be become the new global
            // symbol used
            let should_claim = |global: &GlobalSymbol| {
                // Always claim symbols if the global one is undefined and owned
                // by the internal object file
                if global.owner.is_internal() && global.is_undefined() {
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

            let (external_symbol, external_ref) =
                self.symbols.external_symbol_ref2(ctx, i).unwrap();
            if external_symbol.hidden {
                continue;
            }

            let global = external_ref.read();
            if global.is_traced() {
                if !symbol.is_undefined() {
                    log::info!(logger: ctx, "{}: definition of {}", self.source(), ctx.demangle(global.name, self.machine));
                } else if symbol.is_weak() {
                    log::info!(logger: ctx, "{}: weak external for {}", self.source(), ctx.demangle(global.name, self.machine));
                } else {
                    log::info!(logger: ctx, "{}: reference to {}", self.source(), ctx.demangle(global.name, self.machine));
                }
            }

            if global.owner.is_internal() {
                continue;
            }

            let owner = &objs[global.owner.index()];

            let symbol_is_needed = symbol.is_undefined() || symbol.is_common();

            if symbol_is_needed && owner.atomic_set_live() {
                if global.is_traced() {
                    log::info!(logger: ctx, "{}: needs {} from {}", self.source(), ctx.demangle(global.name, self.machine), owner.source());
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
            let Some((external, external_ref)) = self.symbols.external_symbol_ref2(ctx, i) else {
                // Global COMDATs should always have an external reference.
                assert!(!self.coff_symbols.symbol(i).unwrap().is_global());
                continue;
            };

            // All of the COMDAT types except for largest choose an arbitrary
            // definition. This will be the first definition seen due to regular
            // symbol resolution passes. Largest COMDATs contain an additional
            // factor which could shift the selected definition
            if external.selection != pe::IMAGE_COMDAT_SELECT_LARGEST {
                continue;
            }

            let symbol = self.coff_symbols.symbol(i).unwrap();
            let mut global = external_ref.write();

            let should_claim = |global: &GlobalSymbol| {
                let owner = &objs[global.owner.index()];
                if !owner.live.load(Ordering::Relaxed) {
                    return true;
                }

                let owner_symbol = owner.coff_symbols.symbol(global.index).unwrap();
                let section = &self.sections[symbol.section().unwrap()];

                let owner_section = &owner.sections[owner_symbol.section().unwrap()];
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
                global.index = i;
            }
        }
    }

    /// Discards COMDATs and associative sections not claimed by eader symbols.
    ///
    /// COMDATs and associative sections are modeled as a directed graph with
    /// nodes being sections and edges are links to associative sections. The
    /// graph is a reversed version of how the associative sections are laid out
    /// in auxiliary section symbols. An IMAGE_COMDAT_SELECT_ASSOCIATIVE section
    /// in a COFF auxiliary record contains variable number of links to the
    /// parent section which ends up at the COMDAT leader section.
    /// These links are reversed where the COMDAT leader contains outgoing
    /// associative sections to the follower sections. This makes traversal
    /// easier since once the leader is handled, discarding/keeping associative
    /// sections is a simple DFS traversal.
    pub fn discard_unclaimed_comdats(&mut self, ctx: &LinkContext<'a>) {
        assert!(self.is_live());

        let mut visited = FixedBitSet::new_empty(self.sections.len());

        // It is possible (but unlikely) that an associative section is associative
        // to multiple different COMDAT leaders.
        // - If the section has not been visited before, its followers should
        //   be visited.
        // - If the section has been visited before, its followers should be
        //   visited only if a previous visit discarded this section but the
        //   chain needs to be kept
        let should_visit = |section: &mut InputSection, discard: bool| -> bool {
            section.is_discarded() && !discard
        };

        for &i in self.comdat_leaders.iter() {
            let Some(external_ref) = self.symbols.external_symbol_ref(ctx, i) else {
                continue;
            };

            // Set the discard status
            let discard = external_ref.read().owner != self.id;
            let symbol = self.coff_symbols.symbol(i).unwrap();
            let section_index = symbol.section().unwrap();

            // Do a DFS traversal over followers to update discard status
            let mut stack = vec![section_index];
            while let Some(section_index) = stack.pop() {
                let section = &mut self.sections[section_index];
                if visited.insert(section_index.0) || should_visit(section, discard) {
                    section.set_discarded(discard);
                    stack.extend(&section.followers);
                }
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
            if symbol.is_local()
                || symbol.is_undefined()
                || symbol.is_common()
                || symbol.is_weak()
                || symbol.is_absolute()
            {
                continue;
            }

            let (external, external_ref) = self.symbols.external_symbol_ref2(ctx, i).unwrap();

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
                        let section = &self.sections[symbol.section().unwrap()];
                        let owner = &objs[global.owner.index()];
                        let owner_section = &owner.sections[global.section().unwrap()];
                        section.length != owner_section.length
                    }
                    pe::IMAGE_COMDAT_SELECT_EXACT_MATCH => {
                        let section = &self.sections[symbol.section().unwrap()];
                        let owner = &objs[global.owner.index()];
                        let owner_section = &owner.sections[global.section().unwrap()];

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
                        name = ctx.demangle(global.name, self.machine),
                        owner = owner.source(),
                        this = self.source(),
                    ));
                }
            } else if let Some(section) = self.sections.section(symbol.section().unwrap())
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
                        name = ctx.demangle(global.name, self.machine),
                        owner = owner.source(),
                        this = self.source(),
                    ));
                }
            }
        }

        errors
    }

    pub fn scan_relocations(
        &self,
        ctx: &LinkContext<'a>,
        objs: &[ArenaRef<'a, ObjectFile<'a>>],
    ) -> crate::Result<()> {
        for (i, _) in self.sections.enumerate() {
            self.scan_section_relocations(ctx, i, objs)?;
        }

        Ok(())
    }

    fn scan_section_relocations(
        &self,
        ctx: &LinkContext<'a>,
        index: SectionIndex,
        objs: &[ArenaRef<'a, ObjectFile>],
    ) -> crate::Result<()> {
        let reloc_section = &self.sections[index];
        if reloc_section.discarded.load(Ordering::Relaxed) {
            return Ok(());
        }

        for reloc in reloc_section.relocs.iter() {
            let symbol = self.coff_symbols.symbol(reloc.symbol()).with_context(|| {
                format!(
                    "{}: relocation at '{}+{:#x}' references invalid symbol {}",
                    self.source(),
                    reloc_section.name,
                    reloc.virtual_address(),
                    reloc.symbol(),
                )
            })?;

            let symbol_name = || {
                if symbol.is_local() {
                    self.symbols.local_symbol(reloc.symbol()).unwrap().name
                } else {
                    let external_ref = self
                        .symbols
                        .external_symbol_ref(ctx, reloc.symbol())
                        .unwrap();
                    external_ref.read().name
                }
            };

            let mut obj = self;
            let mut section_index = SectionIndex(0);

            if symbol.is_local() {
                section_index = symbol.section().unwrap();
            } else {
                let external_ref = self
                    .symbols
                    .external_symbol_ref(ctx, reloc.symbol())
                    .unwrap();
                let global = external_ref.read();
                obj = &objs[global.owner.index()];
                if let Some(index) = global.section() {
                    section_index = index;
                    if global.is_imported() {
                        // Import definitions are discarded before relocation scanning.
                        // If an object file references an import, it needs to be marked
                        // live and its relocations need to be scanned.
                        if obj.sections[section_index].atomic_set_live() {
                            obj.scan_section_relocations(ctx, section_index, objs)?;
                        }
                    }
                }
            }

            if section_index == SectionIndex(0) {
                // TODO: report undefined symbols
                let _ = symbol_name;
                let _ = obj;
                continue;
            }
        }

        Ok(())
    }

    /// If this is an object file with import information, this will resolve the
    /// name of the DLL that the import refers to.
    ///
    /// This follows the import scheme from MinGW import libraries since they
    /// are the only common import library variants that still use full COFFs
    /// with .idata sections to handle imports instead of short import files.
    ///
    /// MinGW uses dlltool from binutils to create the prepacked import libraries.
    /// The layout and creation of these import files can be found at
    /// <https://git.sr.ht/~sourceware/binutils-gdb/tree/master/item/binutils/dlltool.c>.
    ///
    /// This can be called from any of the MinGW import COFFs to find the DLL
    /// name. The function will recursively search undefined references until
    /// it finds a symbol defined inside the .idata$7 section
    pub fn resolve_import_dllname(
        &self,
        ctx: &LinkContext<'a>,
        objs: &[ArenaRef<'a, ObjectFile<'a>>],
    ) -> Option<&'a [u8]> {
        if !self.has_import_data {
            return None;
        }

        let mut visited = HashSet::new();
        let mut stack = vec![self.id];
        while let Some(obj) = stack.pop() {
            let obj = &objs[obj.index()];
            // If visiting an object file without import data or that has already
            // been visited before, assume the search failed.
            if !obj.has_import_data || !visited.insert(obj.id) {
                return None;
            }

            for (i, symbol) in obj.coff_symbols.iter() {
                if symbol.is_local() {
                    continue;
                }

                let external_ref = obj.symbols.external_symbol_ref(ctx, i).unwrap();
                if symbol.is_undefined() {
                    let global = external_ref.read();
                    stack.push(global.owner);
                } else if let Some(section_index) = symbol.section() {
                    let section = &obj.sections[section_index];
                    if section.name == b".idata$7" && !section.data.is_empty() {
                        let mut name = section.data;
                        let nullbyte = section.data.iter().position(|&b| b == 0);
                        if let Some(nullbyte) = nullbyte {
                            name = &name[..nullbyte];
                        }

                        // Trim off the .dll suffix
                        if let Some(suffix) = name.get(name.len() - 4..)
                            && suffix.eq_ignore_ascii_case(b".dll")
                        {
                            name = &name[..name.len() - 4];
                        }

                        return Some(name);
                    }
                }
            }
        }

        None
    }

    /// Returns `true` if this object file is live.
    ///
    /// This is a convenience function over doing `*obj.live.get_mut()` if
    /// `self` is mutable.
    pub fn is_live(&mut self) -> bool {
        *self.live.get_mut()
    }

    /// Sets the live status for this object file.
    ///
    /// This is a convenience function over doing `*obj.live.get_mut() = v` if
    /// `self` is mutable.
    pub fn set_live(&mut self, value: bool) {
        *self.live.get_mut() = value;
    }

    /// Atomically sets this object file as live.
    ///
    /// Returns `true` if the object file was newly set to live.
    pub fn atomic_set_live(&self) -> bool {
        !(self.live.load(Ordering::Relaxed) || self.live.swap(true, Ordering::Relaxed))
    }
}

/// An input section initialized from an object file.
#[derive(Debug)]
pub struct InputSection<'a> {
    /// The name of the section
    pub name: &'a BStr,

    /// The section data.
    ///
    /// This will be empty if the section has no data or is for uninitialized
    /// data.
    pub data: &'a [u8],

    /// The length of the section from the aux section definition symbol.
    ///
    /// This reflects the true length of the section without padding and for
    /// holding uninitialized data.
    pub length: u32,

    /// The section data checksum.
    ///
    /// Used for COMDAT deduplication
    pub checksum: u32,

    /// Adjacency list of associative COMDAT sections.
    ///
    /// This is a linked list of section indicies. The head is the COMDAT with
    /// the leader and the followers are associated sections in the chain.
    pub followers: Vec<SectionIndex>,

    /// If this section has been discarded.
    ///
    /// Sections will get discarded through COMDAT deduplication GC sections
    /// or other means.
    pub discarded: AtomicBool,

    /// Visit status for GC sections
    pub gc_visited: AtomicBool,

    /// ID of the output section this section is mapped to.
    pub output: OutputSectionId,

    /// Virtual address of the section after rebasing
    pub virtual_address: AtomicU32,

    /// The COFF section header where this section is from.
    pub header: &'a pe::ImageSectionHeader,

    /// The relocations contained in this section.
    pub relocs: &'a [object::pe::ImageRelocation],
}

impl<'a> InputSection<'a> {
    pub fn new(
        name: &'a [u8],
        data: &'a [u8],
        length: u32,
        header: &'a pe::ImageSectionHeader,
        relocs: &'a [object::pe::ImageRelocation],
    ) -> Self {
        Self {
            name: BStr::new(name),
            data,
            length,
            checksum: 0,
            followers: Vec::new(),
            discarded: AtomicBool::new(false),
            gc_visited: AtomicBool::new(false),
            output: OutputSectionId::Null,
            virtual_address: AtomicU32::new(0),
            header,
            relocs,
        }
    }

    /// Returns `true` if this section is discarded.
    ///
    /// This is a convenience function doing `*section.discarded.get_mut()` if
    /// `self` is mutable.
    pub fn is_discarded(&mut self) -> bool {
        *self.discarded.get_mut()
    }

    /// Set the discard status for this section.
    ///
    /// This is a convenience function for doing
    /// `*section.discarded.get_mut() = v` if `self` is mutable.
    pub fn set_discarded(&mut self, value: bool) {
        *self.discarded.get_mut() = value;
    }

    /// Atomically sets this section as discarded.
    ///
    /// Returns `true` if the section was newly set as discarded.
    pub fn atomic_set_discarded(&self) -> bool {
        !(self.discarded.load(Ordering::Relaxed) || self.discarded.swap(true, Ordering::Relaxed))
    }

    /// Atomically sets this section as live (!discarded).
    ///
    /// Returns `true` if the section was newly set to live.
    pub fn atomic_set_live(&self) -> bool {
        !(!self.discarded.load(Ordering::Relaxed) || !self.discarded.swap(false, Ordering::Relaxed))
    }

    pub fn compute_checksum(&mut self) {
        self.checksum = crate::coff::section::compute_checksum(self.data);
    }
}

impl<'a> Section for InputSection<'a> {
    fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    fn size_of_raw_data(&self) -> u32 {
        self.length
    }

    fn characteristics(&self) -> u32 {
        self.header.characteristics()
    }
}

#[derive(Debug, Default)]
#[repr(transparent)]
pub struct InputSectionTable<'a>(Vec<Option<InputSection<'a>>>);

impl<'a> InputSectionTable<'a> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn resize_with(&mut self, new_len: usize, f: impl FnMut() -> Option<InputSection<'a>>) {
        self.0.resize_with(new_len, f);
    }

    pub fn push(&mut self, section: InputSection<'a>) -> SectionIndex {
        let index = SectionIndex(self.0.len());
        self.0.push(Some(section));
        index
    }

    pub fn section_entry(&self, index: SectionIndex) -> Option<&Option<InputSection<'a>>> {
        self.0.get(index.0)
    }

    pub fn section(&self, index: SectionIndex) -> Option<&InputSection<'a>> {
        self.section_entry(index).and_then(|entry| entry.as_ref())
    }

    pub fn section_entry_mut(
        &mut self,
        index: SectionIndex,
    ) -> Option<&mut Option<InputSection<'a>>> {
        self.0.get_mut(index.0)
    }

    pub fn section_mut(&mut self, index: SectionIndex) -> Option<&mut InputSection<'a>> {
        self.section_entry_mut(index)
            .and_then(|entry| entry.as_mut())
    }

    pub fn iter(&self) -> impl Iterator<Item = &InputSection<'a>> {
        self.0.iter().filter_map(|entry| entry.as_ref())
    }

    pub fn iter_entries(&self) -> impl Iterator<Item = &Option<InputSection<'a>>> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut InputSection<'a>> {
        self.0.iter_mut().filter_map(|entry| entry.as_mut())
    }

    pub fn iter_entries_mut(&mut self) -> impl Iterator<Item = &mut Option<InputSection<'a>>> {
        self.0.iter_mut()
    }

    pub fn enumerate(&self) -> impl Iterator<Item = (SectionIndex, &InputSection<'a>)> {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, section)| section.as_ref().map(|section| (SectionIndex(i), section)))
    }

    pub fn enumerate_mut(&mut self) -> impl Iterator<Item = (SectionIndex, &mut InputSection<'a>)> {
        self.0
            .iter_mut()
            .enumerate()
            .filter_map(|(i, section)| section.as_mut().map(|section| (SectionIndex(i), section)))
    }
}

impl<'a> std::ops::Index<SectionIndex> for InputSectionTable<'a> {
    type Output = InputSection<'a>;

    fn index(&self, index: SectionIndex) -> &Self::Output {
        self.section(index).unwrap()
    }
}

impl<'a> std::ops::IndexMut<SectionIndex> for InputSectionTable<'a> {
    fn index_mut(&mut self, index: SectionIndex) -> &mut Self::Output {
        self.section_mut(index).unwrap()
    }
}

/// Input symbols from an object file.
///
/// An object file contains two types of input symbols. An external or a local.
/// This is slightly different than the symbol storage class scope
/// (`IMAGE_SYM_CLASS_EXTERNAL`, `IMAGE_SYM_CLASS_STATIC`).
/// This is used to determine the ownership of the symbol. Symbols are either
/// owned by an object file or by the global symbol map. A symbol owned by the
/// symbol map has shared ownership between 1 or more object files. In most instances,
/// this will follow the storage class scope.
#[derive(Debug, Clone)]
pub enum ObjectFileSymbol<'a> {
    /// Symbol is owned by the object file.
    Local(LocalSymbol<'a>),

    /// Symbol is owned by the global symbol map and this is the ID used to
    /// access it
    External(ExternalSymbol),
}

impl<'a> ObjectFileSymbol<'a> {
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocalSymbol<'a> {
    pub name: &'a BStr,
    pub value: u32,
    pub section_number: i32,
    pub typ: u16,
    pub storage_class: u8,
}

impl<'a> Symbol for &LocalSymbol<'a> {
    fn value(&self) -> u32 {
        self.value
    }

    fn section_number(&self) -> i32 {
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

    fn section_number(&self) -> i32 {
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

#[derive(Debug, Default)]
#[repr(transparent)]
pub struct ObjectFileSymbolTable<'a>(Vec<Option<ObjectFileSymbol<'a>>>);

impl<'a> ObjectFileSymbolTable<'a> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn resize_with(&mut self, new_len: usize, f: impl FnMut() -> Option<ObjectFileSymbol<'a>>) {
        self.0.resize_with(new_len, f);
    }

    pub fn symbol_entry(&self, index: SymbolIndex) -> Option<&Option<ObjectFileSymbol<'a>>> {
        self.0.get(index.0)
    }

    pub fn symbol(&self, index: SymbolIndex) -> Option<&ObjectFileSymbol<'a>> {
        self.symbol_entry(index).and_then(|entry| entry.as_ref())
    }

    pub fn symbol_entry_mut(
        &mut self,
        index: SymbolIndex,
    ) -> Option<&mut Option<ObjectFileSymbol<'a>>> {
        self.0.get_mut(index.0)
    }

    pub fn symbol_mut(&mut self, index: SymbolIndex) -> Option<&mut ObjectFileSymbol<'a>> {
        self.symbol_entry_mut(index)
            .and_then(|entry| entry.as_mut())
    }

    pub fn iter(&self) -> impl Iterator<Item = &ObjectFileSymbol<'a>> {
        self.0.iter().filter_map(|entry| entry.as_ref())
    }

    pub fn iter_entries(&self) -> impl Iterator<Item = &Option<ObjectFileSymbol<'a>>> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut ObjectFileSymbol<'a>> {
        self.0.iter_mut().filter_map(|entry| entry.as_mut())
    }

    pub fn iter_entries_mut(&mut self) -> impl Iterator<Item = &mut Option<ObjectFileSymbol<'a>>> {
        self.0.iter_mut()
    }

    pub fn enumerate(&self) -> impl Iterator<Item = (SymbolIndex, &ObjectFileSymbol<'a>)> {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, symbol)| symbol.as_ref().map(|section| (SymbolIndex(i), section)))
    }

    pub fn enumerate_mut(
        &mut self,
    ) -> impl Iterator<Item = (SymbolIndex, &mut ObjectFileSymbol<'a>)> {
        self.0
            .iter_mut()
            .enumerate()
            .filter_map(|(i, symbol)| symbol.as_mut().map(|section| (SymbolIndex(i), section)))
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
    ) -> Option<ExternalRef<'ctx, 'a>> {
        if let Some(symbol) = self.external_symbol(index) {
            let id = symbol.id;
            ctx.symbol_map.get(id)
        } else {
            None
        }
    }

    pub fn external_symbol_ref2<'ctx>(
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

impl<'a> std::ops::Index<SymbolIndex> for ObjectFileSymbolTable<'a> {
    type Output = ObjectFileSymbol<'a>;

    fn index(&self, index: SymbolIndex) -> &Self::Output {
        self.symbol(index).unwrap()
    }
}

impl<'a> std::ops::IndexMut<SymbolIndex> for ObjectFileSymbolTable<'a> {
    fn index_mut(&mut self, index: SymbolIndex) -> &mut Self::Output {
        self.symbol_mut(index).unwrap()
    }
}
