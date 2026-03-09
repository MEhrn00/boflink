use object::{SymbolIndex, pe};

use super::ImageFileMachine;

/// Trait for handling relocations
pub trait Relocation {
    /// Returns the virtual address of the relocation inside the section.
    fn virtual_address(&self) -> u32;

    /// Returns the value of the `SymbolTableIndex` field in the relocation.
    fn symbol_table_index(&self) -> u32;

    /// Returns the relocation type.
    fn typ(&self) -> u16;

    /// Returns the index of the target symbol for this relocation.
    #[inline]
    fn symbol(&self) -> SymbolIndex {
        SymbolIndex(self.symbol_table_index() as usize)
    }

    /// Returns `true` if this is a PC-relative relocation variant for the
    /// specified machine
    #[inline]
    fn is_pcrel(&self, machine: ImageFileMachine) -> bool {
        match machine {
            ImageFileMachine::Amd64 => Amd64RelType(self.typ()).is_pcrel(),
            ImageFileMachine::I386 => I386RelType(self.typ()).is_pcrel(),
            _ => unimplemented!("Relocation::is_pcrel() for '{machine}'"),
        }
    }

    /// Returns `true` if this is an `ADDR` relocation variant for the specified
    /// machine
    #[inline]
    fn is_addr(&self, machine: ImageFileMachine) -> bool {
        match machine {
            ImageFileMachine::Amd64 => Amd64RelType(self.typ()).is_addr(),
            ImageFileMachine::I386 => I386RelType(self.typ()).is_addr(),
            _ => unimplemented!("Relocation::is_addr() for '{machine}'"),
        }
    }
}

impl Relocation for &pe::ImageRelocation {
    #[inline]
    fn virtual_address(&self) -> u32 {
        self.virtual_address.get(object::LittleEndian)
    }

    #[inline]
    fn symbol_table_index(&self) -> u32 {
        self.symbol_table_index.get(object::LittleEndian)
    }

    #[inline]
    fn typ(&self) -> u16 {
        self.typ.get(object::LittleEndian)
    }
}

trait RelType {
    fn is_addr(&self) -> bool;
    fn is_rel32(&self) -> bool;

    #[inline]
    fn is_pcrel(&self) -> bool {
        self.is_rel32()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct Amd64RelType(u16);

impl RelType for Amd64RelType {
    #[inline]
    fn is_addr(&self) -> bool {
        self.0 >= pe::IMAGE_REL_AMD64_ADDR64 && self.0 <= pe::IMAGE_REL_AMD64_ADDR32NB
    }

    #[inline]
    fn is_rel32(&self) -> bool {
        self.0 >= pe::IMAGE_REL_AMD64_REL32 && self.0 <= pe::IMAGE_REL_AMD64_REL32_5
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct I386RelType(u16);

impl RelType for I386RelType {
    #[inline]
    fn is_addr(&self) -> bool {
        self.0 == pe::IMAGE_REL_I386_DIR32 || self.0 == pe::IMAGE_REL_I386_DIR32NB
    }

    #[inline]
    fn is_rel32(&self) -> bool {
        self.0 == pe::IMAGE_REL_I386_REL32
    }
}
