use std::{
    borrow::Cow,
    ffi::OsStr,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use object::{
    Object as _, ObjectSection, ObjectSymbol as _, ReadRef, SectionIndex, SymbolIndex, U16Bytes,
    U32Bytes,
    coff::{
        CoffFile, CoffHeader, ImageSymbol, ImportFile, ImportName, ImportType, SectionTable,
        SymbolTable,
    },
    pe::{
        self, IMAGE_COMDAT_SELECT_ASSOCIATIVE, IMAGE_REL_AMD64_REL32, IMAGE_REL_I386_DIR32,
        IMAGE_SYM_CLASS_FILE, IMAGE_WEAK_EXTERN_SEARCH_ALIAS, IMAGE_WEAK_EXTERN_SEARCH_LIBRARY,
        IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY, ImageAuxSymbolSection,
    },
};
use rayon::Scope;

use crate::{
    ErrorContext,
    arena::ArenaRef,
    coff::{
        CoffFlags, ComdatSelection, ImageFileMachine, SectionFlags, SectionNumber, StorageClass,
    },
    context::LinkContext,
    make_error,
    symbols::{SymbolId, SymbolKind, SymbolPriority},
};

#[derive(Debug)]
pub struct InputFile<'a> {
    pub data: &'a [u8],
    pub path: &'a Path,
    pub parent: Option<&'a InputFile<'a>>,
}

impl<'a> InputFile<'a> {
    /// Makes a new internal input file
    pub fn internal() -> InputFile<'a> {
        InputFile {
            data: &[],
            path: Path::new(""),
            parent: None,
        }
    }

    pub fn is_internal(&self) -> bool {
        self.path.as_os_str().is_empty()
    }

    pub fn source(&self) -> InputFileSource<'a> {
        self.parent
            .map(|parent| InputFileSource::Member {
                archive: parent.path,
                path: self.path,
            })
            .unwrap_or_else(|| {
                if self.is_internal() {
                    InputFileSource::Internal
                } else {
                    InputFileSource::Disk(self.path)
                }
            })
    }
}

/// Full source of an input file.
///
/// Used for diagnostic messages.
///
/// The [`std::fmt::Display`] implementation will display the file path if the
/// file was read directly from disk or it will display `path(member)` if
/// the file is a member of an archive.
///
/// [`InputFileSource::to_short()`] can be used for only displaying the file name
/// parts instead of the full paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InputFileSource<'a> {
    /// Internal file that is created for misc usage
    Internal,

    /// An input file read directly from disk.
    Disk(&'a Path),

    /// An archive member.
    Member { archive: &'a Path, path: &'a Path },
}

impl<'a> InputFileSource<'a> {
    /// Returns the [`ShortInputFileSource`] from of this input source
    pub fn to_short(&self) -> ShortInputFileSource<'a> {
        let fname_or_path =
            |path: &'a Path| -> &'a OsStr { path.file_name().unwrap_or(path.as_os_str()) };

        match self {
            Self::Internal => ShortInputFileSource::Internal,
            Self::Disk(path) => ShortInputFileSource::Disk(fname_or_path(path)),
            Self::Member { archive, path } => ShortInputFileSource::Member {
                archive: fname_or_path(archive),
                filename: fname_or_path(path),
            },
        }
    }
}

impl std::fmt::Display for InputFileSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "<internal>"),
            Self::Disk(path) => write!(f, "{}", path.display()),
            Self::Member {
                archive: parent,
                path,
            } => {
                write!(f, "{}({})", parent.display(), path.display())
            }
        }
    }
}

/// A short form version of an input source with only the filename components.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ShortInputFileSource<'a> {
    Internal,

    /// The name of the file read from disk.
    Disk(&'a OsStr),

    /// An archive member
    Member {
        archive: &'a OsStr,
        filename: &'a OsStr,
    },
}

impl std::fmt::Display for ShortInputFileSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "<internal>"),
            Self::Disk(file) => write!(f, "{}", file.to_string_lossy()),
            Self::Member { archive, filename } => {
                write!(
                    f,
                    "{}({})",
                    archive.to_string_lossy(),
                    filename.to_string_lossy()
                )
            }
        }
    }
}

/// Type of input file derived from the file data magic bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileKind {
    /// Archive file
    Archive,

    /// Regular COFF
    Coff,

    /// Short form COFF import file
    Import,

    /// Module definition file
    ModuleDef,
}

impl FileKind {
    /// Attempts to detect the [`FileKind`] based on the passed in data.
    pub fn detect(data: &[u8]) -> Result<FileKind, UnknownFileError> {
        let Some(magic) = data.get(..18) else {
            return Err(UnknownFileError);
        };

        let detect_archive = || {
            let magic = magic.get(..object::archive::MAGIC.len())?;
            (magic == object::archive::MAGIC || magic == object::archive::THIN_MAGIC)
                .then_some(FileKind::Archive)
        };

        let detect_coff = || match magic[..5] {
            [0x00, 0x00, 0xff, 0xff, 0x00, 0x00] => Some(FileKind::Import),
            [0x64, 0x86, ..]
            | [0x4c, 0x01, ..]
            | [0xc0, 0x01, ..]
            | [0x64, 0xaa, ..]
            | [0x41, 0xa6, ..]
            | [0x4e, 0xa6, ..]
            | [0xc4, 0x1, ..]
            | [0xc2, 0x1, ..] => Some(FileKind::Coff),
            _ => None,
        };

        let detect_module = || {
            if magic.iter().any(|c| c.is_ascii()) {
                let data_str = std::str::from_utf8(data).ok()?;
                data_str
                    .lines()
                    .any(|line| {
                        line.starts_with(';')
                            || line.contains("LIBRARY")
                            || line.contains("EXPORTS")
                            || line.contains("NAME")
                    })
                    .then_some(FileKind::ModuleDef)
            } else {
                None
            }
        };

        detect_archive()
            .or_else(detect_coff)
            .or_else(detect_module)
            .ok_or(UnknownFileError)
    }
}

#[derive(Debug)]
pub struct UnknownFileError;

impl std::fmt::Display for UnknownFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unknown file type")
    }
}

impl std::error::Error for UnknownFileError {}

/// Id for an object file. This is a tagged index using a `u32`.
/// - Index 0 is reserved for the internal file used for adding linker-synthesized
///   sections/symbols.
/// - [`u32::MAX`] is for an invalid index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectFileId(u32);

impl ObjectFileId {
    pub const fn internal() -> Self {
        Self(0)
    }

    pub const fn is_internal(&self) -> bool {
        self.0 == Self::internal().0
    }

    pub const fn invalid() -> Self {
        Self(u32::MAX)
    }

    pub const fn is_invalid(&self) -> bool {
        self.0 == Self::invalid().0
    }

    pub const fn is_valid(&self) -> bool {
        !self.is_invalid()
    }

    pub fn new(idx: usize) -> Self {
        let idx = u32::try_from(idx).unwrap_or_else(|_| panic!("object file ID overflowed"));
        if idx == u32::MAX {
            panic!("object file ID overflowed");
        }

        Self(idx)
    }

    pub const fn index(self) -> Option<usize> {
        if self.is_valid() {
            Some(self.0 as usize)
        } else {
            None
        }
    }
}

/// An object file being linked.
#[derive(Debug)]
pub struct ObjectFile<'a> {
    /// The id of this file.
    pub id: ObjectFileId,

    /// The file path and data associated with this object file.
    pub file: InputFile<'a>,

    /// If this file was lazy during initialization.
    pub lazy: bool,

    /// If this file is being included.
    pub live: AtomicBool,

    /// The machine file of the file
    pub machine: ImageFileMachine,

    /// The COFF flags
    pub characteristics: CoffFlags,

    /// Raw COFF section headers
    pub coff_sections: SectionTable<'a>,

    /// Raw COFF symbol table
    pub coff_symbols: SymbolTable<'a>,

    /// Input sections from the COFF.
    ///
    /// The sections are indexable by symbol section numbers. The first section will
    /// always be `None` and acts as a section for undefined symbols.
    pub sections: Vec<Option<InputSection<'a>>>,

    /// The COFF symbols
    ///
    /// This vec retains the same indicies as the original symbol table.
    pub symbols: Vec<Option<InputSymbol<'a>>>,

    /// The DLL name that the symbols in this file refer to.
    ///
    /// This will be set if this object file was created from an import file. It will
    /// also be set when handling legacy MinGW import files
    pub dll: &'a [u8],

    /// Data from the .drectve section
    pub directives: &'a [u8],
}

impl<'a> ObjectFile<'a> {
    pub fn new_internal() -> ObjectFile<'a> {
        Self::new(ObjectFileId::internal(), InputFile::internal(), true)
    }

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
            dll: &[],
            directives: &[],
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
        self.sections.reserve_exact(self.coff_sections.len());
        self.sections
            .resize_with(self.coff_sections.len() + 1, || None);

        for (i, coff_section) in coff.sections().enumerate() {
            let name = coff_section
                .name_bytes()
                .with_context(|| format!("section at index {i}"))?;

            if name == b".drectve" {
                self.directives = coff_section.data().map_err(|_| {
                    make_error!("section at index {i}: section data size exceeds file bounds")
                })?;
                continue;
            } else if name == b".llvm_addrsig" || name == b".llvm.call-graph-profile" {
                continue;
            }

            let characteristics = SectionFlags::from_bits_retain(
                coff_section
                    .coff_section()
                    .characteristics
                    .get(object::LittleEndian),
            );
            if characteristics.contains(SectionFlags::LnkRemove) {
                continue;
            }

            let is_dwarf = || name.starts_with(b".debug_");

            let is_codeview = || {
                name == b".debug$F"
                    || name == b".debug$S"
                    || name == b".debug$P"
                    || name == b".debug$T"
            };

            if ctx.options.strip_debug && (is_dwarf() || is_codeview()) {
                continue;
            }

            let relocs = coff_section
                .coff_relocations()
                .with_context(|| format!("section at index {i}"))?;

            self.sections[i] = Some(InputSection {
                name,
                data: coff_section
                    .data()
                    .with_context(|| format!("section at index {i}"))?,
                length: 0,
                checksum: 0,
                characteristics,
                coff_relocs: relocs.into(),
                associative: None,
                discarded: AtomicBool::new(false),
            });
        }

        Ok(())
    }

    fn initialize_coff_symbols(
        &mut self,
        ctx: &LinkContext<'a>,
        coff: &CoffFile<'a>,
    ) -> crate::Result<()> {
        self.symbols.resize_with(self.coff_symbols.len(), || None);

        let mut comdat_aux: Vec<Option<&'a ImageAuxSymbolSection>> = Vec::new();
        comdat_aux.resize_with(self.coff_sections.len() + 1, || None);

        let mut pending_weak = Vec::new();

        for coff_symbol in coff.symbols() {
            if coff_symbol.coff_symbol().storage_class() == IMAGE_SYM_CLASS_FILE {
                continue;
            }

            let name = coff_symbol
                .name_bytes()
                .with_context(|| format!("symbol at index {}", coff_symbol.index()))?;

            let local_symbol = {
                let index = coff_symbol.index();
                let coff_symbol = coff_symbol.coff_symbol();
                let local_symbol = InputSymbol {
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
                    external_id: SymbolId::invalid(),
                };
                self.symbols[index.0] = Some(local_symbol);
                self.symbols[index.0].as_mut().unwrap()
            };

            if coff_symbol.is_global() {
                local_symbol.external_id = ctx.symbol_map.get_or_create_default(name);
            }

            if coff_symbol.is_weak() {
                let weak_aux = self
                    .coff_symbols
                    .aux_weak_external(coff_symbol.index())
                    .with_context(|| format!("symbol at index {}", coff_symbol.index()))?;

                let default_idx = weak_aux.default_symbol();

                let weak_default = coff
                    .symbol_by_index(default_idx)
                    .with_context(|| format!("symbol at index {}", default_idx))?;

                let weak_search = weak_aux.weak_search_type.get(object::LittleEndian);

                if (weak_default.is_global() && weak_search == IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY)
                    || (weak_default.is_local() && weak_search == IMAGE_WEAK_EXTERN_SEARCH_LIBRARY)
                    || (coff_symbol.is_global()
                        && weak_default.is_local()
                        && weak_search == IMAGE_WEAK_EXTERN_SEARCH_ALIAS)
                {
                    pending_weak.push((default_idx.0, weak_aux));
                }
            }

            let Some(section_index) = coff_symbol.section_index().map(|index| index.0 - 1) else {
                continue;
            };

            let section = {
                let section = self.sections.get_mut(section_index).ok_or_else(|| {
                    make_error!(
                        "symbol at index {}: section number is invalid {}",
                        coff_symbol.index(),
                        section_index
                    )
                })?;

                let Some(section) = section else {
                    continue;
                };
                section
            };

            if coff_symbol.coff_symbol().has_aux_section() {
                let aux_section = self
                    .coff_symbols
                    .aux_section(coff_symbol.index())
                    .with_context(|| format!("symbol at index {}", coff_symbol.index()))?;
                section.length = aux_section.length.get(object::LittleEndian);
                section.checksum = aux_section.check_sum.get(object::LittleEndian);

                if aux_section.selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE {
                    section.associative = Some(SectionIndex(
                        (aux_section.number.get(object::LittleEndian) - 1) as usize,
                    ));
                } else if section.characteristics.contains(SectionFlags::LnkComdat) {
                    comdat_aux[section_index] = Some(aux_section);
                }
            } else if coff_symbol.is_global()
                && section.characteristics.contains(SectionFlags::LnkComdat)
            {
                if let Some(aux_section) = comdat_aux[section_index].take() {
                    local_symbol.selection = Some(
                        ComdatSelection::try_from(aux_section.selection)
                            .with_context(|| format!("symbol at index {}", coff_symbol.index()))?,
                    );
                }
            }
        }

        for (default_idx, weak_aux) in pending_weak {
            let Some(weak_default) = &mut self.symbols[default_idx] else {
                unreachable!();
            };

            let weak_search = weak_aux.weak_search_type.get(object::LittleEndian);
            if weak_default.storage_class == StorageClass::External
                && weak_search == IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY
            {
                weak_default.external_id = SymbolId::invalid();
            } else if weak_default.storage_class != StorageClass::External
                && (weak_search == IMAGE_WEAK_EXTERN_SEARCH_LIBRARY
                    || weak_search == IMAGE_WEAK_EXTERN_SEARCH_ALIAS)
            {
                weak_default.external_id = ctx.symbol_map.get_or_create_default(weak_default.name);
            }
        }

        Ok(())
    }

    pub fn parse_importfile(&mut self, ctx: &LinkContext<'a>) -> crate::Result<()> {
        let file = ImportFile::parse(self.file.data)?;
        self.machine = Self::identify_importfile_machine(self.file.data)?;
        self.characteristics = CoffFlags::LineNumsStripped | CoffFlags::Reserved40;
        self.dll = file.dll();

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

        let mut coff_relocs: Cow<[pe::ImageRelocation]> = Cow::Borrowed(&[]);
        if code {
            if self.machine == ImageFileMachine::Amd64 {
                static THUNK_RELOC: [pe::ImageRelocation; 1] = [pe::ImageRelocation {
                    virtual_address: U32Bytes::from_bytes(2u32.to_le_bytes()),
                    symbol_table_index: U32Bytes::from_bytes(0u32.to_le_bytes()),
                    typ: U16Bytes::from_bytes(IMAGE_REL_AMD64_REL32.to_le_bytes()),
                }];
                coff_relocs = Cow::Borrowed(&THUNK_RELOC);
            } else if self.machine == ImageFileMachine::I386 {
                static THUNK_RELOC: [pe::ImageRelocation; 1] = [pe::ImageRelocation {
                    virtual_address: U32Bytes::from_bytes(2u32.to_le_bytes()),
                    symbol_table_index: U32Bytes::from_bytes(0u32.to_le_bytes()),
                    typ: U16Bytes::from_bytes(IMAGE_REL_I386_DIR32.to_le_bytes()),
                }];
                coff_relocs = Cow::Borrowed(&THUNK_RELOC);
            }
        }

        self.sections.push(Some(InputSection {
            name: section_name,
            data: if code {
                // jmp [rip + $<symbol>]
                &[0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90]
            } else {
                &[]
            },
            checksum: 0,
            length: if code { 6 } else { 0 },
            characteristics: SectionFlags::Align4Bytes
                | SectionFlags::MemRead
                | if file.import_type() == ImportType::Code {
                    SectionFlags::CntCode | SectionFlags::MemExecute
                } else if file.import_type() == ImportType::Data {
                    SectionFlags::MemWrite
                } else {
                    SectionFlags::from_bits_retain(0)
                },
            coff_relocs,
            associative: None,
            discarded: AtomicBool::new(false),
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
            {
                if section.discarded.load(Ordering::Relaxed) {
                    continue;
                }
            }

            let external_ref = symbol.external_id;
            ctx.symbol_map.inspect(external_ref, |global_ref| {
                let mut global = global_ref.write().unwrap();
                if symbol.priority(live, self.id) < global.priority(objs) {
                    global.value = symbol.value;
                    global.section_number = symbol.section_number;
                    global.storage_class = symbol.storage_class;
                    global.index = symbol.index;
                    global.owner = self.id;
                }
            });
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

            let external_ref = symbol.external_id;
            ctx.symbol_map.inspect(external_ref, |global_ref| {
                let global = global_ref.read().unwrap();

                if global.traced {
                    if symbol.is_defined() {
                        log::info!(logger: ctx, "{}: definition of {}", self.source(), global.demangle(ctx, self.machine));
                    } else if symbol.is_weak_external() {
                        log::info!(logger: ctx, "{}: weak external for {}", self.source(), global.demangle(ctx, self.machine));
                    } else {
                        log::info!(logger: ctx, "{}: reference to {}", self.source(), global.demangle(ctx, self.machine));
                    }
                }

                let Some(owner) = global.owner.index().map(|index| &objs[index]) else {
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
            });
        }
    }

    pub fn input_section(&self, index: SectionIndex) -> Option<&InputSection<'a>> {
        self.sections
            .get(index.0)
            .and_then(|section| section.as_ref())
    }
}

#[derive(Debug)]
pub struct InputSection<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub checksum: u32,
    pub length: u32,
    pub characteristics: SectionFlags,
    pub coff_relocs: Cow<'a, [pe::ImageRelocation]>,
    pub associative: Option<SectionIndex>,
    pub discarded: AtomicBool,
}

#[derive(Debug)]
pub struct InputSymbol<'a> {
    pub name: &'a [u8],
    pub value: u32,
    pub section_number: SectionNumber,
    pub storage_class: StorageClass,
    pub typ: u16,
    pub selection: Option<ComdatSelection>,
    pub index: SymbolIndex,
    pub external_id: SymbolId,
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

    /// Returns `true` if this is a weak external symbol
    pub fn is_weak_external(&self) -> bool {
        self.storage_class == StorageClass::WeakExternal
    }

    pub fn kind(&self) -> SymbolKind {
        if self.is_defined() {
            SymbolKind::Defined
        } else if self.is_weak_external() {
            SymbolKind::Weak
        } else if self.is_common() {
            SymbolKind::Common
        } else {
            SymbolKind::Unknown
        }
    }

    pub fn priority(&self, live: bool, id: ObjectFileId) -> SymbolPriority {
        SymbolPriority::new(id, self.kind(), live)
    }
}
