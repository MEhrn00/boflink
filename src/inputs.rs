use std::{
    ffi::OsStr,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use bitflags::Flags;
use object::{
    ReadRef, U16Bytes, U32Bytes,
    coff::{CoffHeader, ImageSymbol as _, ImportFile, ImportName, ImportType},
    pe::{
        self, IMAGE_SCN_LNK_REMOVE, IMAGE_SYM_CLASS_FILE, IMAGE_SYM_DEBUG, ImageAuxSymbolSection,
    },
};

use crate::{
    ErrorContext,
    coff::{
        ComdatSelection, ImageFileMachine, SectionFlags, SectionIndex, StorageClass, StringTable,
        SymbolSectionNumber,
    },
    context::LinkContext,
    error,
    syncpool::{BumpBox, BumpRef},
};

#[derive(Debug)]
pub struct InputFile<'a> {
    pub data: &'a [u8],
    pub path: &'a Path,
    pub parent: Option<&'a InputFile<'a>>,
    pub offset: u64,
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
        // TODO: Change this to [`OsStr::display()`] when MSRV is bumped to
        // 1.87.0.
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

#[derive(Debug)]
pub struct ObjectFile<'a> {
    machine: ImageFileMachine,
    id: u32,
    pub file: InputFile<'a>,
    pub lazy: bool,
    pub variant: ObjectFileVariant<'a>,
}

impl<'a> ObjectFile<'a> {
    pub fn new(id: u32, file: InputFile<'a>, lazy: bool) -> ObjectFile<'a> {
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

        if is_import_header() {
            Self {
                id,
                machine: read_machine(6).unwrap_or(sentinel),
                file,
                lazy,
                variant: ObjectFileVariant::Import(ImportObjectFile::default()),
            }
        } else {
            Self {
                id,
                machine,
                file,
                lazy,
                variant: ObjectFileVariant::Coff(CoffObjectFile::default()),
            }
        }
    }

    pub const fn machine(&self) -> ImageFileMachine {
        self.machine
    }

    pub const fn is_coff_import(&self) -> bool {
        matches!(self.variant, ObjectFileVariant::Import(_))
    }

    pub fn parse(&mut self, ctx: &LinkContext<'a>) -> crate::Result<()> {
        debug_assert_ne!(
            self.machine,
            ImageFileMachine(u16::MAX),
            "Machine value should have been detected during ObjectFile::new(). This sentinel value means the data from the passed input file is not large enough for parsing the COFF headers."
        );

        self.variant
            .parse(ctx, &self.file, self.lazy)
            .with_context(|| format!("cannot parse {}", self.file.source()))
    }
}

#[derive(Debug)]
pub enum ObjectFileVariant<'a> {
    Coff(CoffObjectFile<'a>),
    Import(ImportObjectFile<'a>),
}

impl<'a> ObjectFileVariant<'a> {
    fn parse(
        &mut self,
        ctx: &LinkContext<'a>,
        file: &InputFile<'a>,
        lazy: bool,
    ) -> crate::Result<()> {
        match self {
            Self::Coff(coff) => coff.parse(ctx, file, lazy),
            Self::Import(import) => import.parse(ctx, file, lazy),
        }
    }
}

#[derive(Debug, Default)]
pub struct CoffObjectFile<'a> {
    coff_sections: &'a [pe::ImageSectionHeader],
    coff_symbols: &'a [pe::ImageSymbolBytes],
    coff_strtab: StringTable<'a>,
    sections: Vec<Option<BumpBox<'a, CoffObjectSection<'a>>>>,
    symbols: Vec<Option<BumpBox<'a, CoffObjectSymbol<'a>>>>,
    has_idata: bool,
    directives: &'a [u8],
}

impl<'a> CoffObjectFile<'a> {
    fn parse(
        &mut self,
        ctx: &LinkContext<'a>,
        file: &InputFile<'a>,
        _lazy: bool,
    ) -> crate::Result<()> {
        self.parse_coff_data(ctx, file)?;
        let bump = ctx.bump_pool.get();
        self.initialize_sections(ctx, &bump, file)?;
        self.initialize_symbols(ctx, &bump, file)?;
        Ok(())
    }

    fn parse_coff_data(
        &mut self,
        ctx: &LinkContext<'a>,
        file: &InputFile<'a>,
    ) -> crate::Result<()> {
        let mut offset = 0;
        let header = pe::ImageFileHeader::parse(file.data, &mut offset)?;
        self.parse_coff_sections(ctx, header, file)?;
        self.parse_coff_symbols(ctx, header, file)?;
        self.parse_strtab(header, file)?;
        Ok(())
    }

    fn parse_coff_sections(
        &mut self,
        ctx: &LinkContext<'a>,
        header: &pe::ImageFileHeader,
        file: &InputFile<'a>,
    ) -> crate::Result<()> {
        let scnhdrs_offset = std::mem::size_of_val(header) as u64
            + header.size_of_optional_header.get(object::LittleEndian) as u64;

        self.coff_sections = file
            .data
            .read_slice_at(scnhdrs_offset, header.number_of_sections() as usize)
            .map_err(|_| error!("COFF section headers size exceeds size of data"))?;
        ctx.stats
            .parsed_coff_sections
            .fetch_add(self.coff_sections.len(), Ordering::Relaxed);
        Ok(())
    }

    fn parse_coff_symbols(
        &mut self,
        ctx: &LinkContext<'a>,
        header: &pe::ImageFileHeader,
        file: &InputFile<'a>,
    ) -> crate::Result<()> {
        if header.number_of_symbols() > 0 && header.pointer_to_symbol_table() > 0 {
            self.coff_symbols = file
                .data
                .read_slice_at(
                    header.pointer_to_symbol_table() as u64,
                    header.number_of_symbols() as usize,
                )
                .map_err(|_| error!("COFF symbol table size exceeds size of data"))?;
            ctx.stats
                .parsed_coff_symbols
                .fetch_add(self.coff_symbols.len(), Ordering::Relaxed);
        }
        Ok(())
    }

    fn parse_strtab(
        &mut self,
        header: &pe::ImageFileHeader,
        file: &InputFile<'a>,
    ) -> crate::Result<()> {
        let strtab_offset = {
            let offset = header.pointer_to_symbol_table() as u64;
            let symtab_size = header.number_of_symbols() as u64
                * std::mem::size_of::<pe::ImageSymbolBytes>() as u64;
            offset + symtab_size
        };

        let length = file
            .data
            .read_at::<U32Bytes<_>>(strtab_offset)
            .map(|v| v.get(object::LittleEndian))
            .map_err(|_| error!("COFF string table offset exceeds size of data"))?;

        let strtab_end = strtab_offset
            .checked_add(length as u64)
            .context("COFF string table length too large")?;

        self.coff_strtab = StringTable::new(file.data, strtab_offset, strtab_end);
        Ok(())
    }

    fn initialize_sections(
        &mut self,
        ctx: &LinkContext<'a>,
        bump: &BumpRef<'a>,
        file: &InputFile<'a>,
    ) -> crate::Result<()> {
        self.sections.reserve_exact(self.coff_sections.len());
        self.sections.resize_with(self.coff_sections.len(), || None);

        for (i, coff_section) in self.coff_sections.iter().enumerate() {
            let name = coff_section
                .name(self.coff_strtab)
                .with_context(|| format!("section at index {i}"))?;

            if name == b".drectve" {
                self.directives = coff_section.coff_data(file.data).map_err(|_| {
                    error!("section at index {i}: section data size exceeds file bounds")
                })?;
                continue;
            } else if name == b".llvm_addrsig" || name == b".llvm.call-graph-profile" {
                continue;
            }

            if coff_section.characteristics.get(object::LittleEndian) & IMAGE_SCN_LNK_REMOVE != 0 {
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

            let relocs = if coff_section.number_of_relocations.get(object::LittleEndian) > 0
                && coff_section
                    .pointer_to_relocations
                    .get(object::LittleEndian)
                    > 0
            {
                coff_section.coff_relocations(file.data).map_err(|_| {
                    error!("section at index {i}: relocation data exceeds file bounds")
                })?
            } else {
                &[]
            };

            self.sections[i] = Some(bump.alloc_boxed(CoffObjectSection {
                name,
                data: coff_section.coff_data(file.data).map_err(|_| {
                    error!("section at index {i}: section data size exceeds file bounds")
                })?,
                length: 0,
                checksum: 0,
                characteristics: SectionFlags::from_bits_truncate(
                    coff_section.characteristics.get(object::LittleEndian),
                ),
                coff_relocs: relocs,
                associative: None,
                live: AtomicBool::new(!ctx.options.gc_sections),
            }));

            if name == b".idata" || name.starts_with(b".idata$") {
                self.has_idata = true;
            }
        }

        Ok(())
    }

    fn initialize_symbols(
        &mut self,
        ctx: &LinkContext<'a>,
        bump: &BumpRef<'a>,
        file: &InputFile<'a>,
    ) -> crate::Result<()> {
        self.symbols.reserve_exact(self.coff_symbols.len());
        self.symbols.resize_with(self.coff_symbols.len(), || None);

        let mut comdat_aux: Vec<Option<&'a ImageAuxSymbolSection>> = Vec::new();
        comdat_aux.reserve_exact(self.coff_sections.len() + 1);
        comdat_aux.resize_with(self.coff_sections.len() + 1, || None);

        let mut aux_num = 0u8;
        for (i, coff_symbol_bytes) in self.coff_symbols.iter().enumerate() {
            if aux_num > 0 {
                aux_num -= 1;
                continue;
            }

            let coff_symbol = coff_symbol_bytes
                .0
                .read_at::<pe::ImageSymbol>(0)
                .map_err(|_| error!("symbol at index {i}: data is invalid"))?;

            aux_num = coff_symbol.number_of_aux_symbols();

            if coff_symbol.storage_class() == IMAGE_SYM_CLASS_FILE
                && coff_symbol.section_number() == IMAGE_SYM_DEBUG
            {
                continue;
            }

            let name = coff_symbol
                .name(self.coff_strtab)
                .with_context(|| format!("symbol at index {i}"))?;
        }

        Ok(())
    }
}

#[derive(Debug)]
struct CoffObjectSection<'a> {
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
struct CoffObjectSymbol<'a> {
    name: &'a [u8],
    value: u32,
    section: SymbolSectionNumber,
    typ: u16,
    storage_class: StorageClass,
    selection: Option<ComdatSelection>,
}

#[derive(Debug)]
pub struct ImportObjectFile<'a> {
    kind: ImportType,
    dll: &'a [u8],
    symbol: &'a [u8],
    name: ImportName<'a>,
}

impl<'a> ImportObjectFile<'a> {
    fn parse(
        &mut self,
        _ctx: &LinkContext<'a>,
        file: &InputFile<'a>,
        _lazy: bool,
    ) -> crate::Result<()> {
        let file = ImportFile::parse(file.data)?;
        self.kind = file.import_type();
        self.dll = file.dll();
        self.symbol = file.symbol();
        self.name = file.import();
        Ok(())
    }
}

impl<'a> std::default::Default for ImportObjectFile<'a> {
    fn default() -> Self {
        Self {
            kind: ImportType::Const,
            dll: Default::default(),
            symbol: Default::default(),
            name: ImportName::Name(Default::default()),
        }
    }
}
