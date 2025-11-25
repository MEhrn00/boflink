//! Parser for Windows [Module-Definition (.Def) Files](https://learn.microsoft.com/en-us/cpp/build/reference/module-definition-dot-def-files)
//!
//! These files contain plaintext export information of a DLL.
//!
//! An example module definition file looks like this.
//! ```text
//! LIBRARY mylibrary
//! EXPORTS
//!    MyLibraryCreate
//!    MyLibraryHelloWorld
//!    MyLibraryGlobalData                    DATA
//!    MyLibraryInternal=MyLibraryExternal
//!    MyLibraryForward=forwarded_dll.func1
//!    MyLibraryOrdinalThree                  @3
//!    MyLibraryPrivate                       PRIVATE
//!    MyLibraryNoName                        NONAME
//! ```
//!
//! Module definition files are useful when needing to build an import library
//! for linking with a DLL. The "modern" way of creating import libraries for
//! a DLL is by annotating exported functions with `__declspec(dllexport)` and
//! letting the linker handle creating the import library with the DLL.
//!
//! In situations where the DLL source code is not available, module-definition
//! can also be used with tools such as `dlltool, lib.exe, llvm-dlltool` to
//! create an import library from scratch.

//! Rules
//!
//! The file statement rules are outlined [here](https://learn.microsoft.com/en-us/cpp/build/reference/rules-for-module-definition-statements)
//!
//! Summary:
//! - Statements, attribute keywords, and user-specified identifiers are case sensitive.
//! - Long file names containing spaces or semicolons (;) must be enclosed in quotation marks (").
//! - Statements and their arguments are separated by one or more spaces, tabs, or newline characters.
//! - A colon (:) or equal sign (=) that designates an argument is surrounded by zero or more spaces, tabs, or newline characters.
//! - A NAME or LIBRARY statement, if used, must precede all other statements.
//! - NAME and LIBRARY statements are optional.
//! - SECTIONS and EXPORTS statements can appear multiple times.
//! - SECTIONS and EXPORTS statements can take multiple specifications.
//! - SECTIONS and EXPORTS statement specifications must be separated by one or more spaces, tabs or newline characters.
//! - The statement keyword must appear once before the first specification and can be repeated before each additional specification.
//! - Comments in the .def file are designated by a semicolon (;) at the beginning of each comment line.
//! - A comment cannot share a line with a statement, but it can appear between specifications in a multiline statement. (SECTIONS and EXPORTS are multiline statements.)
//! - Numeric arguments are specified in base 10 or hexadecimal.
//! - If a string argument matches a reserved word, it must be enclosed in double quotation marks (").
//!
//! Reserved words:
//! - APPLOADER1
//! - BASE
//! - CODE
//! - CONFORMING
//! - DATA
//! - DESCRIPTION
//! - DEV386
//! - DISCARDABLE
//! - DYNAMIC
//! - EXECUTE-ONLY
//! - EXECUTEONLY
//! - EXECUTEREAD
//! - EXETYPE
//! - EXPORTS
//! - FIXED1
//! - FUNCTIONS2
//! - HEAPSIZE
//! - IMPORTS
//! - IMPURE1
//! - INCLUDE2
//! - INITINSTANCE2
//! - IOPL
//! - LIBRARY1
//! - LOADONCALL1
//! - LONGNAMES2
//! - MOVABLE1
//! - MOVEABLE1
//! - MULTIPLE
//! - NAME
//! - NEWFILES2
//! - NODATA1
//! - NOIOPL1
//! - NONAME
//! - NONCONFORMING1
//! - NONDISCARDABLE
//! - NONE
//! - NONSHARED
//! - NOTWINDOWCOMPAT1
//! - OBJECTS
//! - OLD1
//! - PRELOAD
//! - PRIVATE
//! - PROTMODE2
//! - PURE1
//! - READONLY
//! - READWRITE
//! - REALMODE1
//! - RESIDENT
//! - RESIDENTNAME1
//! - SECTIONS
//! - SEGMENTS
//! - SHARED
//! - SINGLE
//! - STACKSIZE
//! - STUB
//! - VERSION
//! - WINDOWAPI
//! - WINDOWCOMPAT
//! - WINDOWS

mod base;
mod error;
mod exports;
mod file;
mod heapsize;
mod keyword;
mod library;
mod name;
mod parsers;
mod sections;
mod stacksize;
mod stub;
mod version;

pub use error::Error;
pub use exports::{DefinitionAttribute, DefinitionOrdinal, ExportedName, ExportsDefinition};
pub use file::*;
