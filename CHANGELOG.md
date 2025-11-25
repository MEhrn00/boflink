# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2025-11-25

### Added

- The new `BeaconDownload` API symbol released in CS 4.12 is now included in the list of
  builtin Beacon API symbols during symbol resolution. [#34](https://github.com/MEhrn00/boflink/pull/34)

- Basic man page with command line option descriptions.
  This requires the [pandoc](https://pandoc.org/) executable to build. Can be built by running `cargo xtask docs-man`. (71908bd)

### Changed

- Version updates for external dependencies.
  - cpp_demangle 0.4.4 -> 0.5.0 [#31](https://github.com/MEhrn00/boflink/pull/31)
  - zip 5.0.0 -> 6.0.0 [#32](https://github.com/MEhrn00/boflink/pull/32)
  - object 0.37.4 -> 0.38.0 [#33](https://github.com/MEhrn00/boflink/pull/33)


## [0.5.0] - 2025-09-18

### Added

- Support for handling COFF `IMAGE_SYM_CLASS_WEAK_EXTERNAL` symbols (#30).

### Changed

- Demangled C++ symbols in log messages also include the mangled name (1ef0007).

## [0.4.0] - 2025-07-14

### Fixed

- Parsing error when attempting to parse `DATA` imports from legacy MinGW import libraries (#25).

### Added

- Include git commit short hash of built binary in `--version` string (0be92f1).
- Support for demangling C++ symbol names in diagnostic output messages (#24).
- `--warn-unresolved-symbols` flag for reporting unresolved symbols as warnings instead of errors.
  These will show up as regular undefined symbols in the output COFF without any library prefix added (#26).
- `--ignore-unresolved-symbol` flag for allowing select symbols to remain undefined (#27).

## [0.3.1] - 2025-06-28

### Fixed

- Link libraries from the `.drectve` section not being parsed properly (58f0f2d).

## [0.3.0] - 2025-06-27

### Added

- Additional ignored command line arguments for better GCC compatibility (f3d02e2).
- `--no-merge-groups` flag to not merge grouped sections (#19).
- Whole archive linking using `--whole-archive/--no-whole-archive` (#20).
- Debug logging header with the entire command line used to invoke boflink when the `-v/--verbose` flag is passed (e8e8d47).
- Support for including MinGW link library search paths using the `--mingw[64|32]/--ucrt[64|32]` flag (#23).

### Changed

- Relax requirements on undefined external symbols (#18).

## [0.2.0] - 2025-06-09

### Added

- GC sections (`--gc-sections`) support for discarding unreferenced sections (#10).

### Fixed

- Incorrect checksum value calculation for GCC `.rdata$zzz` metadata sections (#7).
- Entrypoint symbol from the command line not being validated (#8).
- Relocations not being applied correctly when compiling with  `-ffunction-sections` (#9).

## [0.1.1] - 2025-06-07

### Added

- Github dependabot.yml configuration file for tracking dependency updates [`d649273`](https://github.com/MEhrn00/boflink/commit/d6492734b6f8df84f0cffebf69ac1522632ce658).
- Enable dependency graph in Github https://github.com/MEhrn00/boflink/network/dependencies.

### Fixed

- Issues with COMMON symbols not being allocated properly (#6).

### Changed

- Update object crate to 0.37.0 (#4).

## [0.1.0] - 2025-05-30

- Initial release

[unreleased]: https://github.com/MEhrn00/boflink/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/MEhrn00/boflink/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/MEhrn00/boflink/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/MEhrn00/boflink/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/MEhrn00/boflink/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/MEhrn00/boflink/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/MEhrn00/boflink/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/MEhrn00/boflink/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/MEhrn00/boflink/releases/tag/v0.1.0
