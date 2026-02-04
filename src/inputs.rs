use std::{borrow::Cow, ffi::OsStr, path::Path, sync::atomic::AtomicBool};

use object::{
    Object as _, ObjectSection, ObjectSymbol as _, ReadRef, SectionIndex, U16Bytes, U32Bytes,
    coff::{
        CoffFile, CoffHeader, ImageSymbol, ImportFile, ImportName, ImportType, SectionTable,
        SymbolTable,
    },
    pe::{
        self, IMAGE_COMDAT_SELECT_ASSOCIATIVE, IMAGE_REL_AMD64_REL32, IMAGE_REL_I386_DIR32,
        IMAGE_SYM_ABSOLUTE, IMAGE_SYM_CLASS_FILE, IMAGE_SYM_DEBUG, IMAGE_SYM_UNDEFINED,
        IMAGE_WEAK_EXTERN_SEARCH_ALIAS, IMAGE_WEAK_EXTERN_SEARCH_LIBRARY,
        IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY, ImageAuxSymbolSection,
    },
};

use crate::{
    ErrorContext,
    coff::{
        CoffFlags, ComdatSelection, ImageFileMachine, SectionFlags, SectionNumber, StorageClass,
    },
    context::LinkContext,
    make_error,
    symbols::{ExternalId, Symbol},
    syncpool::BumpBox,
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

    pub fn source(&self) -> InputFileSource<'a> {
        self.parent
            .map(|parent| InputFileSource::PathedMember {
                parent: parent.path,
                path: self.path,
            })
            .unwrap_or_else(|| {
                if self.path.as_os_str().is_empty() {
                    InputFileSource::Internal
                } else {
                    InputFileSource::Disk(self.path)
                }
            })
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
    /// Attempts to detect the [`InputFileKind`] based on the passed in data.
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

/// Full source of an input file.
///
/// Used for diagnostic messages.
///
/// The [`std::fmt::Display`] implementation will display the file path if the
/// file was read directly from disk or it will display `path(member)` if
/// the file is a member of an archive.
///
/// [`InputSource::to_short()`] can be used for only displaying the file names
/// for each path instead of the full paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InputFileSource<'a> {
    Internal,

    /// An input file read directly from disk.
    Disk(&'a Path),

    /// Pathed archive member.
    PathedMember {
        parent: &'a Path,
        path: &'a Path,
    },
}

impl<'a> InputFileSource<'a> {
    /// Returns the [`ShortInputSource`] from of this input source
    pub fn to_short(&self) -> ShortFileSource<'a> {
        let fname_or_path =
            |path: &'a Path| -> &'a OsStr { path.file_name().unwrap_or(path.as_os_str()) };

        match self {
            Self::Internal => ShortFileSource::Internal,
            Self::Disk(path) => ShortFileSource::Disk(fname_or_path(path)),
            Self::PathedMember { parent, path } => ShortFileSource::PathedMember {
                parent: fname_or_path(parent),
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
            Self::PathedMember { parent, path } => {
                write!(f, "{}({})", parent.display(), path.display())
            }
        }
    }
}

/// A short form version of an input source with only the filename components.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ShortFileSource<'a> {
    Internal,

    /// The name of the file read from disk.
    Disk(&'a OsStr),

    /// Pathed member
    PathedMember {
        parent: &'a OsStr,
        filename: &'a OsStr,
    },
}

impl std::fmt::Display for ShortFileSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "<internal>"),
            Self::Disk(file) => write!(f, "{}", file.to_string_lossy()),
            Self::PathedMember { parent, filename } => {
                write!(
                    f,
                    "{}({})",
                    parent.to_string_lossy(),
                    filename.to_string_lossy()
                )
            }
        }
    }
}

/// Id for an object file. This is a tagged index using a `u32`.
/// - Index 0 is reserved for the internal file used for adding linker-synthesized
/// sections/symbols.
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

    pub fn new(idx: usize) -> Self {
        let idx = u32::try_from(idx).unwrap_or_else(|_| panic!("object file ID overflowed"));
        if idx == u32::MAX {
            panic!("object file ID overflowed");
        }

        Self(idx)
    }

    pub fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug)]
pub struct ObjectFile<'a> {
    pub id: ObjectFileId,
    pub file: InputFile<'a>,
    pub lazy: bool,
    pub live: AtomicBool,
    pub machine: ImageFileMachine,
    pub characteristics: CoffFlags,
    pub coff_sections: SectionTable<'a>,
    pub coff_symbols: SymbolTable<'a>,
    pub sections: Vec<Option<InputSection<'a>>>,
    pub symbols: Vec<Option<(Symbol<'a>, ExternalId)>>,
    pub has_idata: bool,
    pub dll: &'a [u8],
    pub directives: &'a [u8],
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
            has_idata: false,
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

            if name == b".idata" || name.starts_with(b".idata$") {
                self.has_idata = true;
            }
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

        for symbol in coff.symbols() {
            if symbol.coff_symbol().storage_class() == IMAGE_SYM_CLASS_FILE {
                continue;
            }

            let name = symbol
                .name_bytes()
                .with_context(|| format!("symbol at index {}", symbol.index()))?;

            let (obj_symbol, external_id) = {
                self.symbols[symbol.index().0] = Some((
                    Symbol {
                        name,
                        value: symbol.coff_symbol().value(),
                        section: match symbol.coff_symbol().section_number() {
                            IMAGE_SYM_UNDEFINED => SectionNumber::Undefined,
                            IMAGE_SYM_DEBUG => SectionNumber::Debug,
                            IMAGE_SYM_ABSOLUTE => SectionNumber::Absolute,
                            o => SectionNumber::from(o as u16),
                        },
                        storage_class: StorageClass::try_from(symbol.coff_symbol().storage_class())
                            .with_context(|| format!("symbol at index {}", symbol.index()))?,
                        typ: symbol.coff_symbol().typ(),
                        owner: self.id,
                        table_index: symbol.index(),
                        selection: None,
                    },
                    ExternalId::invalid(),
                ));

                let Some(obj_symbol) = &mut self.symbols[symbol.index().0] else {
                    unreachable!();
                };
                obj_symbol
            };

            if symbol.is_global() {
                *external_id = ctx.symbol_map.get_or_default(name);
            }

            if symbol.is_weak() {
                let weak_aux = self
                    .coff_symbols
                    .aux_weak_external(symbol.index())
                    .with_context(|| format!("symbol at index {}", symbol.index()))?;

                let default_idx = weak_aux.default_symbol();

                let weak_default = coff
                    .symbol_by_index(default_idx)
                    .with_context(|| format!("symbol at index {}", default_idx))?;

                let weak_search = weak_aux.weak_search_type.get(object::LittleEndian);

                if (weak_default.is_global() && weak_search == IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY)
                    || (weak_default.is_local() && weak_search == IMAGE_WEAK_EXTERN_SEARCH_LIBRARY)
                    || (symbol.is_global()
                        && weak_default.is_local()
                        && weak_search == IMAGE_WEAK_EXTERN_SEARCH_ALIAS)
                {
                    pending_weak.push((default_idx.0, weak_aux));
                }
            }

            let Some(section_index) = symbol.section_index().map(|index| index.0 - 1) else {
                continue;
            };

            let section = {
                let section = self.sections.get_mut(section_index).ok_or_else(|| {
                    make_error!(
                        "symbol at index {}: section number is invalid {}",
                        symbol.index(),
                        section_index
                    )
                })?;

                let Some(section) = section else {
                    continue;
                };
                section
            };

            if symbol.coff_symbol().has_aux_section() {
                let aux_section = self
                    .coff_symbols
                    .aux_section(symbol.index())
                    .with_context(|| format!("symbol at index {}", symbol.index()))?;
                section.length = aux_section.length.get(object::LittleEndian);
                section.checksum = aux_section.check_sum.get(object::LittleEndian);

                if aux_section.selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE {
                    section.associative = Some(SectionIndex(
                        (aux_section.number.get(object::LittleEndian) - 1) as usize,
                    ));
                } else if section.characteristics.contains(SectionFlags::LnkComdat) {
                    comdat_aux[section_index] = Some(aux_section);
                }
            } else if symbol.is_global()
                && section.characteristics.contains(SectionFlags::LnkComdat)
            {
                if let Some(aux_section) = comdat_aux[section_index].take() {
                    obj_symbol.selection = Some(
                        ComdatSelection::try_from(aux_section.selection)
                            .with_context(|| format!("symbol at index {}", symbol.index()))?,
                    );
                }
            }
        }

        for (default_idx, weak_aux) in pending_weak {
            let Some((weak_default, external_id)) = &mut self.symbols[default_idx] else {
                unreachable!();
            };

            let weak_search = weak_aux.weak_search_type.get(object::LittleEndian);
            if weak_default.storage_class == StorageClass::External
                && weak_search == IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY
            {
                *external_id = ExternalId::invalid();
            } else if weak_default.storage_class != StorageClass::External
                && (weak_search == IMAGE_WEAK_EXTERN_SEARCH_LIBRARY
                    || weak_search == IMAGE_WEAK_EXTERN_SEARCH_ALIAS)
            {
                *external_id = ctx.symbol_map.get_or_default(weak_default.name);
            }
        }

        Ok(())
    }

    pub fn parse_importfile(&mut self, ctx: &LinkContext<'a>) -> crate::Result<()> {
        let file = ImportFile::parse(self.file.data)?;
        self.machine = Self::identify_importfile_machine(self.file.data)?;
        self.characteristics = CoffFlags::LineNumsStripped | CoffFlags::Reserved40;
        self.dll = file.dll();

        let bump = ctx.bump_pool.get();

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
                public_symbol = public_symbol.strip_prefix(&[b'_']).unwrap_or(public_symbol);
            }
            public_symbol
        };

        let thunk_section_name = match file.import_type() {
            ImportType::Const => ".rdata",
            ImportType::Code => ".text",
            ImportType::Data => ".data",
        };

        let section_name = bump.alloc_bytes(
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

    pub fn resolve_symbols(&self, ctx: &LinkContext<'a>, objs: &[BumpBox<'a, ObjectFile<'a>>]) {}
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
