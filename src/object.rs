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
    U16Bytes,
    coff::{CoffFile, CoffHeader, ImageSymbol, SectionTable, SymbolTable},
    pe::{
        IMAGE_COMDAT_SELECT_ASSOCIATIVE, IMAGE_SYM_ABSOLUTE, IMAGE_SYM_CLASS_EXTERNAL,
        IMAGE_SYM_DEBUG, IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY,
    },
};
use rayon::Scope;

use crate::{
    ErrorContext,
    arena::ArenaRef,
    bail,
    bit_set::FixedDenseBitSet,
    coff::{
        CoffFlags, ComdatSelection, Feat00Flags, ImageFileMachine, SectionFlags, SectionNumber,
        StorageClass,
    },
    context::LinkContext,
    inputs::{InputFile, InputFileSource},
    make_error,
    outputs::OutputSectionId,
    symbols::{GlobalSymbol, SymbolDemangler, SymbolId},
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

    /// The initialized input symbols that may contribute to the output file.
    ///
    /// Like with the sections, the symbols in this vec retain the same indicies
    /// as the original object file. This allows relocations to index into this
    /// vec without needing to keep an intermediate lookup table
    pub symbols: Vec<Option<InputSymbol<'a>>>,

    /// Indicies of COMDAT leader symbols used for handling COMDAT deduplication.
    ///
    /// The leader symbol contains the unique name used for the COMDAT section
    /// definition. It is a symbol defined in the COMDAT section where the symbol
    /// table record for it is the first one appearing after the COMDAT section
    /// symbol.
    ///
    /// One thing ambiguous with COMDAT leader selection is on the storage class
    /// requirements for the defined symbol. This is left unspecified; however,
    /// it is possible for the COMDAT leader to be `IMAGE_SYM_CLASS_STATIC` or
    /// a default definition for a weak symbol.
    pub comdat_leaders: Vec<SymbolIndex>,

    /// File should be included in the linked output.
    ///
    /// This is used as the main indicator for object file inclusion.
    pub live: AtomicBool,

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

    /// The file associated with this object file
    pub file: InputFile<'a>,

    /// Index of the .drectve section if present.
    ///
    /// This will be set to 0 if the object file does not contain any linker
    /// directives.
    pub directives_index: SectionIndex,

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

    /// File architecture
    pub machine: ImageFileMachine,

    /// The `IMAGE_FILE_*` flags of the object file.
    ///
    /// This is largely unused for object files.
    pub characteristics: CoffFlags,

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
            comdat_leaders: Vec::new(),
            directives_index: SectionIndex(0),
            addrsig_index: SectionIndex(0),
            feat_flags: Feat00Flags::empty(),
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

            self.sections[coff_section.index().0] = Some(InputSection {
                name,
                data,
                length,
                checksum: 0,
                characteristics,
                coff_relocs: relocs.into(),
                associative_edges: Vec::new(),
                index: coff_section.index(),
                discarded: AtomicBool::new(false),
                gc_visited: AtomicBool::new(false),
                output: OutputSectionId::Null,
            });
        }

        // Every COMDAT should have at least one symbol associated with it
        self.comdat_leaders.reserve(comdats);

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

        // Map of COMDAT selections indexable by section number. Used for setting
        // up COMDAT leaders
        let mut comdat_sels = Vec::new();
        comdat_sels.resize_with(self.coff_sections.len() + 1, || None);

        let mut locals = 0;

        for coff_symbol in coff.symbols() {
            let image_symbol = coff_symbol.coff_symbol();

            // These are closures so that they are lazily evaluated. Local symbol
            // creation depends on a variety of factors. Deferring these makes it
            // so that they do not perform any work unless needed

            let symbol_name = || {
                coff_symbol
                    .name_bytes()
                    .with_context(|| format!("reading name for symbol {}", coff_symbol.index()))
            };

            let make_symbol =
                |name: &'a [u8], index: SymbolIndex| -> crate::Result<InputSymbol<'a>> {
                    Ok(InputSymbol {
                        name,
                        index,
                        value: image_symbol.value(),
                        section_number: image_symbol.section_number().into(),
                        storage_class: image_symbol
                            .storage_class()
                            .try_into()
                            .with_context(|| format!("symbol at index {index}"))?,
                        selection: None,
                        typ: image_symbol.typ(),
                        external_id: None,
                        definition: None,
                    })
                };

            if image_symbol.section_number() == IMAGE_SYM_ABSOLUTE {
                let name = symbol_name()?;
                if name == b"@feat.00" {
                    self.feat_flags = Feat00Flags::from_bits_retain(image_symbol.value());
                    continue;
                } else if name == b"@comp.id" {
                    continue;
                }

                let index = coff_symbol.index();
                let symbol = self.symbols[index.0].insert(make_symbol(name, index)?);
                if image_symbol.storage_class() == IMAGE_SYM_CLASS_EXTERNAL {
                    symbol.external_id = Some(ctx.symbol_map.get_or_create_default(name));
                }
                continue;
            } else if image_symbol.section_number() == IMAGE_SYM_DEBUG {
                continue;
            }

            let index = coff_symbol.index();
            let symbol = self.symbols[index.0].insert(make_symbol(symbol_name()?, index)?);
            if symbol.is_weak() {
                // Handle IMAGE_SYM_CLASS_WEAK_EXTERNAL without an aux record
                if image_symbol.number_of_aux_symbols() == 0 {
                    bail!(
                        "{}: missing weak extern auxiliary record",
                        symbol.demangle(ctx, self.machine)
                    );
                }

                let weak_aux = self
                    .coff_symbols
                    .aux_weak_external(symbol.index)
                    .with_context(|| format!("reading weak aux for symbol {}", symbol.index))?;

                let weak_search = weak_aux.weak_search_type.get(object::LittleEndian);

                // Check if the weak external symbol should be externally visible
                // for symbol resolution.
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
                if weak_search == IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY {
                    continue;
                }
            } else if symbol.is_global() {
                symbol.external_id = Some(ctx.symbol_map.get_or_create_default(symbol.name));
            } else {
                locals += 1;
            }

            let Some(section_index) = symbol.section_number.index() else {
                if symbol.is_common() {
                    self.has_common_symbols = true;
                }
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
            if image_symbol.has_aux_section() {
                let aux_section = self
                    .coff_symbols
                    .aux_section(symbol.index)
                    .with_context(|| format!("symbol at index {}", symbol.index))?;

                // Overwrite section length using the auxiliary symbol length
                // if non-zero. GCC will insert padding at the end of sections
                // that contain initialized data. The length field here reflects
                // the actual section size and not the padded size
                let length = aux_section.length.get(object::LittleEndian);
                if length > 0 {
                    section.length = length;
                }
                section.checksum = aux_section.check_sum.get(object::LittleEndian);

                if aux_section.selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE {
                    // Add associative COMDATs to the parent associative adjacency
                    // list
                    let number = aux_section.number.get(object::LittleEndian);
                    let parent_index = SectionIndex(number as usize);
                    let parent = self.sections
                        .get_mut(parent_index.0)
                        .and_then(|section| section.as_mut())
                        .with_context(|| format!("auxiliary section symbol at index {} associative section is invalid", symbol.index))?;
                    parent.associative_edges.push(section_index);
                } else if section.characteristics.contains(SectionFlags::LnkComdat) {
                    // For COMDAT sections that are not associative, record the
                    // selection type for the leader to handle
                    let selection =
                        ComdatSelection::try_from(aux_section.selection).with_context(|| {
                            format!("auxiliary section symbol at index {}", symbol.index)
                        })?;
                    comdat_sels[section_index.0] = Some(selection);
                }

                continue;
            }

            // Associate COMDAT selections to leader symbols
            if section.is_comdat()
                && let Some(selection) = comdat_sels[section_index.0].take()
            {
                symbol.selection = Some(selection);
                self.comdat_leaders.push(symbol.index);
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
            if symbol.is_weak() {
                continue;
            }

            let Some(external_id) = symbol.external_id else {
                continue;
            };

            let external_ref = ctx.symbol_map.get(external_id).unwrap();
            let mut global = external_ref.write().unwrap();

            // Check if our copy of the symbol should be become the new global
            // symbol used
            let should_claim = |global: &GlobalSymbol| {
                // Always claim symbols if the global one is undefined and owned
                // by the internal object file
                if global.owner.is_internal() && global.is_undefined() {
                    return true;
                }

                let owner = &objs[global.owner.index()];
                let owner_symbol = owner.symbol(global.index).unwrap();
                let owner_live = owner.live.load(Ordering::Relaxed);

                // Compare symbol kinds. A greater kind means more symbol resolution
                // strength. Use the first symbol seen if they are equal
                match symbol
                    .priority(live)
                    .cmp(&owner_symbol.priority(owner_live))
                {
                    std::cmp::Ordering::Equal => self.id < owner.id,
                    o => o == std::cmp::Ordering::Greater,
                }
            };

            if should_claim(&global) {
                symbol.claim(self.id, &mut global);
            }
        }
    }

    pub fn resolve_comdat_leaders(
        &self,
        ctx: &LinkContext<'a>,
        objs: &[ArenaRef<'a, ObjectFile<'a>>],
    ) {
        assert!(self.live.load(Ordering::Relaxed));
        for symbol_index in self.comdat_leaders.iter().copied() {
            let symbol = self.symbols[symbol_index.0].as_ref().unwrap();
            // Check for local COMDAT leaders
            if symbol.is_local() {
                continue;
            }

            let external_ref = ctx.symbol_map.get(symbol.external_id.unwrap()).unwrap();
            let mut global = external_ref.write().unwrap();

            let should_claim = |global: &GlobalSymbol| {
                if global.owner.is_internal() && global.is_undefined() {
                    return true;
                }

                let owner = &objs[global.owner.index()];
                if !owner.live.load(Ordering::Relaxed) {
                    return true;
                }

                let owner_symbol = owner.symbol(global.index).unwrap();

                match symbol
                    .comdat_priority(self)
                    .cmp(&owner_symbol.comdat_priority(owner))
                {
                    std::cmp::Ordering::Equal => self.id < owner.id,
                    o => o == std::cmp::Ordering::Greater,
                }
            };

            if should_claim(&global) {
                symbol.claim(self.id, &mut global);
            }
        }
    }

    pub fn discard_unclaimed_comdats(&mut self, ctx: &LinkContext<'a>) {
        assert!(*self.live.get_mut());

        // Visit sections which have not been visited before. If a section has
        // been visited, check its discard status that was set by the last COMDAT leader
        // - If the visited COMDAT is discarded but this leader is kept, continue visiting followers and mark them live
        // - If the visited COMDAT was kept and this leader is kept, stop traversing the follower chain
        // - If the visited COMDAT was kept but this leader was discarded, be conservative and stop
        // traversing the chain to keep the followers live for the other leader
        let should_visit = |section: &mut InputSection, discard: bool| -> bool {
            *section.discarded.get_mut() && !discard
        };

        let mut visited = FixedDenseBitSet::new_empty(self.sections.len());
        for &symbol_index in self.comdat_leaders.iter() {
            let symbol = self.symbols[symbol_index.0].as_ref().unwrap();

            // Set the discard status
            let mut discard = false;
            if symbol.is_global() {
                let external_ref = ctx.symbol_map.get(symbol.external_id.unwrap()).unwrap();
                let global = external_ref.read().unwrap();
                if global.owner != self.id {
                    discard = true;
                }
            }

            let section_index = symbol.section_number.index().unwrap();

            // Do a DFS traversal over associative edges to update discard status
            let mut stack = vec![section_index];
            while let Some(section_index) = stack.pop() {
                let section = self.sections[section_index.0].as_mut().unwrap();
                if !visited.contains(section.index.0) || should_visit(section, discard) {
                    visited.insert(section.index.0);
                    *section.discarded.get_mut() = discard;
                    stack.extend(&section.associative_edges);
                }
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

    pub fn symbol(&self, index: SymbolIndex) -> Option<&InputSymbol<'a>> {
        self.symbols.get(index.0).and_then(|symbol| symbol.as_ref())
    }

    pub fn demangle_symbol(
        &self,
        ctx: &LinkContext,
        index: SymbolIndex,
    ) -> Option<SymbolDemangler<'a>> {
        self.symbols
            .get(index.0)
            .and_then(|symbol| symbol.as_ref())
            .map(|symbol| symbol.demangle(ctx, self.machine))
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
    pub associative_edges: Vec<SectionIndex>,
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
            associative_edges: Vec::new(),
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
}

#[derive(Debug)]
pub struct InputSymbol<'a> {
    pub name: &'a [u8],
    pub value: u32,
    pub section_number: SectionNumber,
    pub index: SymbolIndex,
    pub storage_class: StorageClass,
    pub typ: u16,
    pub selection: Option<ComdatSelection>,
    pub definition: Option<SymbolIndex>,
    pub external_id: Option<SymbolId>,
}

impl<'a> InputSymbol<'a> {
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

    pub fn claim(&self, id: ObjectFileId, global: &mut GlobalSymbol<'a>) {
        global.value = self.value;
        global.section_number = self.section_number;
        global.index = self.index;
        global.weak = self.is_weak();
        global.owner = id;
    }

    pub fn priority(&self, live: bool) -> SymbolPriority {
        if self.is_defined() {
            if live {
                SymbolPriority::Defined
            } else {
                SymbolPriority::LazyDefined
            }
        } else if self.is_weak() {
            if live {
                SymbolPriority::Weak
            } else {
                SymbolPriority::LazyWeak
            }
        } else if self.is_common() {
            if live {
                SymbolPriority::Common
            } else {
                SymbolPriority::LazyCommon
            }
        } else {
            SymbolPriority::Unknown
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
                .and_then(|index| obj.section(index))
                .map(|section| section.length as usize + 1usize)
                .unwrap_or(0)
        } else {
            0
        }
    }

    pub fn demangle(
        &self,
        ctx: &LinkContext,
        architecture: ImageFileMachine,
    ) -> SymbolDemangler<'a> {
        crate::symbols::demangle(ctx, self.name, architecture)
    }
}

/// Symbol priorities.
///
/// These are ordered and can be compared to see if one kind has a higher resolution
/// strength over the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymbolPriority {
    Unknown,
    LazyCommon,
    Common,
    LazyWeak,
    LazyDefined,
    Weak,
    Defined,
}
