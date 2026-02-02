use std::{
    ffi::OsStr,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use bitflags::Flags;
use num_enum::TryFromPrimitive;
use object::{
    Object as _, ObjectSection, ObjectSymbol as _, ReadRef, SectionIndex, SymbolIndex, U16Bytes,
    coff::{CoffFile, CoffHeader, ImageSymbol, ImportFile, ImportName, ImportType},
    pe::{
        self, IMAGE_COMDAT_SELECT_ASSOCIATIVE, IMAGE_SYM_ABSOLUTE, IMAGE_SYM_CLASS_FILE,
        IMAGE_SYM_DEBUG, IMAGE_SYM_UNDEFINED, IMAGE_WEAK_EXTERN_SEARCH_ALIAS,
        IMAGE_WEAK_EXTERN_SEARCH_LIBRARY, IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY,
        ImageAuxSymbolSection,
    },
};

use crate::{
    ErrorContext,
    coff::{
        ComdatSelection, ImageFileMachine, SectionFlags, SectionTable, StorageClass,
        SymbolSectionNumber, SymbolTable,
    },
    context::LinkContext,
    error,
    symbols::{Symbol, SymbolId},
};

#[derive(Debug)]
pub struct InputFile<'a> {
    pub data: &'a [u8],
    pub path: &'a Path,
    pub parent: Option<&'a InputFile<'a>>,
}

impl<'a> InputFile<'a> {
    pub fn source(&self) -> InputFileSource<'a> {
        self.parent
            .map(|parent| InputFileSource::PathedMember {
                parent: parent.path,
                path: self.path,
            })
            .unwrap_or(InputFileSource::Disk(self.path))
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
        write!(f, "unknown file type")
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectFileId(u32);

impl ObjectFileId {
    pub const fn invalid() -> Self {
        ObjectFileId(u32::MAX)
    }

    pub const fn is_invalid(&self) -> bool {
        self.0 == ObjectFileId::invalid().0
    }

    pub fn new(idx: usize) -> Self {
        let idx: u32 = u32::try_from(idx).unwrap_or_else(|_| panic!("object file ID overflowed"));
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
struct ObjectFileContext<'a> {
    machine: ImageFileMachine,
    id: ObjectFileId,
    file: InputFile<'a>,
    lazy: bool,
    reachable: AtomicBool,
}

#[derive(Debug)]
pub struct ObjectFile<'a> {
    context: ObjectFileContext<'a>,
    variant: ObjectFileVariant<'a>,
}

impl<'a> ObjectFile<'a> {
    pub fn new(id: ObjectFileId, file: InputFile<'a>, lazy: bool) -> ObjectFile<'a> {
        let u16le = |offset| {
            file.data
                .read_at::<U16Bytes<_>>(offset)
                .map(|v| v.get(object::LittleEndian))
                .ok()
        };

        let read_machine = |offset| Some(ImageFileMachine(u16le(offset)?));
        let read_sig2 = || u16le(2);
        let read_version = || u16le(4);

        let sentinel = ImageFileMachine(u16::MAX);
        let machine = read_machine(0).unwrap_or(sentinel);

        let is_import_header = || {
            machine == ImageFileMachine::Unknown
                && read_sig2().is_some_and(|sig2| sig2 == 0xffff)
                && read_version().is_some_and(|version| version == 0)
        };

        let mut context = ObjectFileContext {
            id,
            machine,
            file,
            lazy,
            reachable: AtomicBool::new(!lazy),
        };

        let variant = if is_import_header() {
            context.machine = read_machine(6).unwrap_or(sentinel);
            ObjectFileVariant::Import(ImportObjectFile::default())
        } else {
            ObjectFileVariant::Coff(CoffObjectFile::default())
        };

        Self { context, variant }
    }

    pub const fn machine(&self) -> ImageFileMachine {
        self.context.machine
    }

    pub fn source(&self) -> InputFileSource<'a> {
        self.context.file.source()
    }

    pub fn parse(&mut self, ctx: &LinkContext<'a>) -> crate::Result<()> {
        debug_assert_ne!(
            self.machine(),
            ImageFileMachine(u16::MAX),
            "Machine value should have been detected during ObjectFile::new(). This sentinel value means the data from the passed input file is not large enough for parsing the COFF headers."
        );

        self.variant
            .parse(ctx, &self.context)
            .with_context(|| format!("cannot parse {}", self.context.file.source()))
    }

    pub fn resolve_symbols(&self, ctx: &LinkContext<'a>) {
        self.variant.resolve_symbols(ctx, &self.context);
    }
}

#[derive(Debug)]
pub enum ObjectFileVariant<'a> {
    Coff(CoffObjectFile<'a>),
    Import(ImportObjectFile<'a>),
}

impl<'a> ObjectFileVariant<'a> {
    fn parse(&mut self, ctx: &LinkContext<'a>, obj: &ObjectFileContext<'a>) -> crate::Result<()> {
        match self {
            Self::Coff(coff) => coff.parse(ctx, obj),
            Self::Import(import) => import.parse(ctx, obj),
        }
    }

    fn resolve_symbols(&self, ctx: &LinkContext<'a>, obj: &ObjectFileContext<'a>) {
        match self {
            Self::Coff(coff) => coff.resolve_symbols(ctx, obj),
            Self::Import(import) => import.resolve_symbols(ctx, obj),
        }
    }
}

#[derive(Debug, Default)]
pub struct CoffObjectFile<'a> {
    coff_sections: SectionTable<'a>,
    coff_symbols: SymbolTable<'a>,
    sections: Vec<Option<Section<'a>>>,
    symbols: Vec<Option<(Symbol<'a>, SymbolId)>>,
    has_idata: bool,
    directives: &'a [u8],
}

impl<'a> CoffObjectFile<'a> {
    fn parse(&mut self, ctx: &LinkContext<'a>, obj: &ObjectFileContext<'a>) -> crate::Result<()> {
        let coff = self.parse_coff_data(obj)?;
        self.initialize_sections(ctx, &coff)?;
        self.initialize_symbols(ctx, obj, &coff)?;
        Ok(())
    }

    fn parse_coff_data(&mut self, obj: &ObjectFileContext<'a>) -> crate::Result<CoffFile<'a>> {
        let coff: CoffFile = CoffFile::parse(obj.file.data)?;
        self.coff_sections = coff.coff_section_table();
        let header = coff.coff_header();
        self.coff_symbols = header.symbols(obj.file.data).unwrap();
        Ok(coff)
    }

    fn initialize_sections(
        &mut self,
        ctx: &LinkContext<'a>,
        coff: &CoffFile<'a>,
    ) -> crate::Result<()> {
        self.sections.reserve_exact(self.coff_sections.len());
        self.sections.resize_with(self.coff_sections.len(), || None);
        ctx.stats
            .parsed_coff_sections
            .fetch_add(self.coff_sections.len(), Ordering::Relaxed);

        for (i, coff_section) in coff.sections().enumerate() {
            let name = coff_section
                .name_bytes()
                .with_context(|| format!("section at index {i}"))?;

            if name == b".drectve" {
                self.directives = coff_section.data().map_err(|_| {
                    error!("section at index {i}: section data size exceeds file bounds")
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

            self.sections[i] = Some(Section {
                name,
                data: coff_section
                    .data()
                    .with_context(|| format!("section at index {i}"))?,
                length: 0,
                checksum: 0,
                characteristics,
                coff_relocs: relocs,
                associative: None,
                live: AtomicBool::new(!ctx.options.gc_sections),
            });

            if name == b".idata" || name.starts_with(b".idata$") {
                self.has_idata = true;
            }
        }

        Ok(())
    }

    fn initialize_symbols(
        &mut self,
        ctx: &LinkContext<'a>,
        obj: &ObjectFileContext<'a>,
        coff: &CoffFile<'a>,
    ) -> crate::Result<()> {
        self.symbols.reserve_exact(self.coff_symbols.len());
        self.symbols.resize_with(self.coff_symbols.len(), || None);
        ctx.stats
            .parsed_coff_symbols
            .fetch_add(self.coff_symbols.len(), Ordering::Relaxed);

        let mut comdat_aux: Vec<Option<&'a ImageAuxSymbolSection>> = Vec::new();
        comdat_aux.reserve_exact(self.coff_sections.len() + 1);
        comdat_aux.resize_with(self.coff_sections.len() + 1, || None);

        let mut pending_weak = Vec::new();

        let bump = ctx.bump_pool.get();

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
                            IMAGE_SYM_UNDEFINED => SymbolSectionNumber::Undefined,
                            IMAGE_SYM_DEBUG => SymbolSectionNumber::Debug,
                            IMAGE_SYM_ABSOLUTE => SymbolSectionNumber::Absolute,
                            o => SymbolSectionNumber(o as u16),
                        },
                        storage_class: StorageClass(symbol.coff_symbol().storage_class()),
                        typ: symbol.coff_symbol().typ(),
                        owner: obj.id,
                        table_index: symbol.index(),
                        selection: None,
                    },
                    SymbolId::invalid(),
                ));

                let Some(obj_symbol) = &mut self.symbols[symbol.index().0] else {
                    unreachable!();
                };
                obj_symbol
            };

            if symbol.is_global() {
                *external_id = ctx.symbol_map.get_or_default(&bump, name);
            }

            if symbol.is_weak() {
                let weak_aux = self
                    .coff_symbols
                    .aux_weak_external(symbol.index())
                    .with_context(|| format!("symbol at index {}", symbol.index()))?;

                let default_idx = weak_aux.default_symbol();

                let weak_default = coff
                    .symbol_by_index(default_idx)
                    .with_context(|| format!("symbol at index {}", default_idx,))?;

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
                    error!(
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
                        ComdatSelection::try_from_primitive(aux_section.selection)
                            .with_context(|| format!("symbol at index {}", symbol.index()))?,
                    );
                }
            }

            symbol.is_common();
        }

        for (default_idx, weak_aux) in pending_weak {
            let Some((weak_default, external_id)) = &mut self.symbols[default_idx] else {
                unreachable!();
            };

            let weak_search = weak_aux.weak_search_type.get(object::LittleEndian);
            if weak_default.storage_class == StorageClass::External
                && weak_search == IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY
            {
                *external_id = SymbolId::invalid();
            } else if weak_default.storage_class != StorageClass::External
                && (weak_search == IMAGE_WEAK_EXTERN_SEARCH_LIBRARY
                    || weak_search == IMAGE_WEAK_EXTERN_SEARCH_ALIAS)
            {
                *external_id = ctx.symbol_map.get_or_default(&bump, weak_default.name);
            }
        }

        Ok(())
    }

    fn resolve_symbols(&self, ctx: &LinkContext<'a>, obj: &ObjectFileContext<'a>) {}
}

#[derive(Debug)]
struct Section<'a> {
    name: &'a [u8],
    data: &'a [u8],
    checksum: u32,
    length: u32,
    characteristics: SectionFlags,
    coff_relocs: &'a [pe::ImageRelocation],
    associative: Option<SectionIndex>,
    live: AtomicBool,
}

#[derive(Debug)]
pub struct ImportObjectFile<'a> {
    kind: ImportType,
    dll: &'a [u8],
    name: ImportName<'a>,
    public_symbol: &'a [u8],
    symbols: [(Symbol<'a>, SymbolId); 2],
}

impl<'a> ImportObjectFile<'a> {
    fn parse(&mut self, ctx: &LinkContext<'a>, obj: &ObjectFileContext<'a>) -> crate::Result<()> {
        let file = ImportFile::parse(obj.file.data)?;
        self.kind = file.import_type();
        self.dll = file.dll();
        self.public_symbol = file.symbol();
        self.name = file.import();
        self.initialize(ctx, obj);
        Ok(())
    }

    fn initialize(&mut self, ctx: &LinkContext<'a>, obj: &ObjectFileContext<'a>) {
        let name = if let ImportName::Name(name) = self.name {
            name
        } else {
            log::warn!(
                "{}: using public symbol name {} for resolving ordinal import",
                obj.file.source(),
                String::from_utf8_lossy(self.public_symbol),
            );

            let mut name = self.public_symbol;
            if obj.machine == ImageFileMachine::I386 {
                name = name.strip_prefix(&[b'_']).unwrap_or(name);
            }
            name
        };

        let bump = ctx.bump_pool.get();
        self.symbols[0] = (
            Symbol {
                name,
                value: 0,
                section: if self.kind == ImportType::Code {
                    SymbolSectionNumber(1)
                } else {
                    SymbolSectionNumber::Undefined
                },
                storage_class: StorageClass::External,
                typ: 0,
                owner: obj.id,
                table_index: SymbolIndex(0),
                selection: None,
            },
            ctx.symbol_map.get_or_default(&bump, name),
        );

        let name = bump.alloc_bytes(&[b"__imp_", name].concat());
        self.symbols[1] = (
            Symbol {
                name,
                value: 0,
                section: SymbolSectionNumber::Undefined,
                storage_class: StorageClass::External,
                typ: 0,
                owner: obj.id,
                table_index: SymbolIndex(1),
                selection: None,
            },
            ctx.symbol_map.get_or_default(&bump, name),
        );
    }

    fn resolve_symbols(&self, ctx: &LinkContext<'a>, obj: &ObjectFileContext<'a>) {}
}

impl<'a> std::default::Default for ImportObjectFile<'a> {
    fn default() -> Self {
        Self {
            kind: ImportType::Const,
            dll: Default::default(),
            public_symbol: Default::default(),
            name: ImportName::Name(Default::default()),
            symbols: [
                (Symbol::default(), SymbolId::invalid()),
                (Symbol::default(), SymbolId::invalid()),
            ],
        }
    }
}
