//! Low-level COFFhandling module.
//!
//! This acts as a supplement to the [object](https://github.com/gimli-rs/object)
//! crate.

mod file;
mod machine;
mod relocs;
mod section;
mod symbol;

pub use file::*;
pub use machine::*;
pub use relocs::*;
pub use section::*;
pub use symbol::*;
