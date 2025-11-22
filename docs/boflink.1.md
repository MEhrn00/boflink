---
title: BOFLINK
section: 1
header: User Manual
footer: boflink
---

# NAME
boflink - Linker for Beacon Object Files.

# SYNOPSIS
boflink [OPTIONS] [files]...

# DESCRIPTION
**boflink** is a tool for linking multiple compiler-generated COFFs into a single BOF more
suitable for loading at runtime with a COFF loader.

# OPTIONS
**`-l, --libraries <LIBNAME>`**
: Adds the specified library to search for undefined symbols. This can be specified multiple
  times.

**`--whole-archive`**
: Include all objects from following archives

**`--no-whole-archive`**
: Turn off **`--whole-archive`**

**`-o, --output <FILE>`**
: Set the output file name [default: a.bof]

**`-L, --library-path <DIRECTORY>`**
: Add the directory to the list of paths to search for libraries

**`--sysroot <DIRECTORY>`**
: Set the sysroot path

**`-m, --machine <EMULATION>`**
: Set the target machine emulation [possible values: i386pep, i386pe]

**`-e, --entry <SYMBOL>`**
: Name of the BOF entrypoint symbol [default: go]

**`--dump-link-graph <FILE>`**
: Dump the link graph to the specified file

**`--custom-api <LIBRARY>`**
: Custom API to use instead of the Beacon API [aliases: --api]

**`--merge-bss`**
: Initialize the .bss section and merge it with the .data section

**`--no-merge-groups`**
: Do not merge grouped sections

**`--gc-sections`**
: Enable garbage collection of unused sections

**`--keep-symbol <SYMBOL>`**
: Ensure that the specified symbols are kept during **`--gc-sections`**

**`--print-gc-sections`**
: Print sections discarded during **`--gc-sections`**

**`--warn-unresolved-symbols`**
: Report unresolved symbols as warnings

**`--ignore-unresolved-symbol <SYMBOL>`**
: Unresolved `<SYMBOL>` will not cause an error or warning

**`--mingw64`**
: Query x86_64-w64-mingw32-gcc for its list of library search paths

**`--mingw32`**
: Query i686-w64-mingw32-gcc for its list of library search paths

**`--ucrt64`**
: Query x86_64-w64-mingw32ucrt-gcc for its list of library search paths

**`--ucrt32`**
: Query i686-w64-mingw32ucrt-gcc for its list of library search paths

**`--color <COLOR>`**
: Print colored output [default: auto] [possible values: never, auto, always, ansi]

**`-v, --verbose...`**
: Increasing logging verbosity

**`--print-timing`**
: Print timing information

**`--Bdynamic`**
: Ignored for compatibility with GCC

**`--out-implib <FILE>`**
: Ignored for compatibility with GCC

**`--major-image-version <NUMBER>`**
: Ignored for compatibility with GCC

**`--minor-image-version <NUMBER>`**
: Ignored for compatibility with GCC

**`-h, --help`**
: Print help

**`-V, --version`**
: Print version

# BUGS
Issues can be reported at https://github.com/MEhrn00/boflink/issues

# HOMEPAGE
https://github.com/MEhrn00/boflink
