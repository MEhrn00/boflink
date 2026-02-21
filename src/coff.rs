//! Low-level COFFhandling module.
//!
//! This acts as a supplement to the [object](https://github.com/gimli-rs/object)
//! crate.

pub mod file;
pub mod relocs;
pub mod section;
pub mod symbol;

pub use file::{CoffFlags, ImageFileMachine};
pub use relocs::Relocation;
pub use section::{Section, SectionFlags, SectionTable};
pub use symbol::{Feat00Flags, Symbol, SymbolTable};
