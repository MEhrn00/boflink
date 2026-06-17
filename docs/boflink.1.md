---
title: BOFLINK
section: 1
header: User Manual
footer: boflink
---

# NAME
boflink - Linker for Beacon Object Files.

# SYNOPSIS
boflink [options] files...

# DESCRIPTION
**boflink** is a tool for linking multiple compiler-generated COFFs into a single BOF more
suitable for loading at runtime with a COFF loader.

# OPTIONS
**`--color[=<color>]`**
: Deprecated alias for **`--color-diagnostics`**

**`--color-diagnostics[=<color>]`**
: Use colors in diagnostic messages [default: auto] [possible values: auto, always, never]

**`--custom-api=<libname>`**
: Custom API to use for the Beacon API [aliases: --api]

**`--dump-link-graph=<file>`**
: Write the link graph to <file>

**`-e <symbol>, --entry=<symbol>`**
: Name of the entrypoint symbol [default: go]

**`--error-limit=<number>`**
: Number of errors to print before exiting [default: 20]

**`--[no-]gc-sections`**
: Garbage collect unused sections

**`--ignore-unresolved-symbol=<symbol>`**
: Unresolved <symbol> will not cause an error or warning

**`--keep-symbol=<symbol>`**
: Alias for **`--require-defined`**

**`-l <libname>, --library=<libname>`**
: Search for the library <libname>

**`-L <dir>, --library-path=<dir>`**
: Add <dir> to the list of library search paths

**`-m <emulation>`**
: Set the target emulation [possible values: i386pep, i386pe]

**`--[no-]merge-bss`**
: Initialize the .bss section and merge it with the .data section

**`--[no-]merge-groups`**
: Combine grouped sections (default)

**`--mingw64`**
: Query x86_64-w64-mingw32-gcc for its list of library search paths (deprecated)

**`--mingw32`**
: Query i686-w64-mingw32-gcc for its list of library search paths (deprecated)

**`-o <file>, --output=<file>`**
: Path to write the output file [default: a.bof]

**`--print-gcc-specs`**
: Print out a GCC spec file for using boflink with GCC

**`--print-gc-sections`**
: Print sections discarded during **`--gc-sections`**

**`--print-timing`**
: Print timing information

**`--require-defined=<symbol>`**
: Ensure <symbol> is defined in the final output

**`--sysroot=<dir>`**
: Set the sysroot path

**`--ucrt64`**
: Query x86_64-w64-mingw32ucrt-gcc for its list of library search paths (deprecated)

**`--ucrt32`**
: Query i686-w64-mingw32ucrt-gcc for its list of library search paths (deprecated)

**`--[no-]warn-unresolved-symbols`**
: Report unresolved symbols as warnings

**`--[no-]whole-archive`**
: Include all objects from following archives

**`-v, --verbose...`**
: Increase logging verbosity

**`-h, --help[=ignored]`**
: Print help and exit

**`-V, --version`**
: Print version and exit

# IGNORED OPTIONS
**`--Bdynamic`**
: Ignored for GCC compatibility

**`--Bstatic`**
: Ignored for GCC compatibility

**`--[disable-]dynamicbase`**
: Ignored for Rust compatibility

**`--[enable|disable]-auto-image-base`**
: Ignored for Rust compatibility

**`-f[no-]lto`**
: Ignored for GCC LTO option compatibility

**`--high-entropy-va`**
: Ignored for Rust compatibility

**`--majory-image-version=<number>`**
: Ignored for CMake compatibility

**`--minor-image-version=<number>`**
: Ignored for CMake compatibility

**`--nxcompat`**
: Ignored for Rust compatibility

**`--out-implib=<file>`**
: Ignored for CMake compatibility

**`-plugin <plugin>`**
: Ignored for GCC plugin compatibility

**`-plugin-opt=<arg>`**
: Ignored for GCC plugin compatibility

# BUGS
Issues can be reported at https://github.com/MEhrn00/boflink/issues

# HOMEPAGE
https://github.com/MEhrn00/boflink
