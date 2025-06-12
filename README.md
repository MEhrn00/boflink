# Boflink

[![GitHub License](https://img.shields.io/github/license/MEhrn00/boflink)](https://github.com/MEhrn00/boflink/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/MEhrn00/boflink)](https://github.com/MEhrn00/boflink/releases/latest)

Linker for Beacon Object Files.

- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)

## Installation
Requires: [Rust](https://www.rust-lang.org/tools/install) >=1.85.0
```bash
rustc --version
```

### From Source
```bash
git clone https://github.com/MEhrn00/boflink.git
cd boflink
cargo xtask install

# For an LTO build
cargo xtask install -p release-lto
```

## Usage
### Standalone
```bash
boflink [-o <output>] [options] <files>...
boflink -o mybof.bof -L/path/to/windows/libs -lkernel32 -ladvapi32 source.c object.o
```

### Using MinGW GCC on Linux
MinGW GCC can be used to invoke boflink using its configured link libraries and library search paths.

```bash
x86_64-w64-mingw32-gcc -B ~/.local/libexec/boflink -fno-lto -nostartfiles <args>...
x86_64-w64-mingw32-gcc -B ~/.local/libexec/boflink -fno-lto -nostartfiles -o mybof.bof source.c object.o
```

### Using Clang  on Linux
Clang can be used to invoke boflink using its configured link libraries and library search paths.

```bash
clang --ld-path=/path/to/boflink --target=x86_64-windows-gnu -nostartfiles <args>...
clang --ld-path=/path/to/boflink --target=x86_64-windows-gnu -nostartfiles -o mybof.bof source.c object.o
```

### Using MSVC on Windows
Windows requires running the boflink executable in a Visual Studio Developer Console.

```powershell
boflink <args>...
boflink -o mybof.bof object1.o object2.o -lkernel32 -ladvapi32
```

## Examples
Additional examples can be found in the [examples/](examples/) directory.

## Blog Post
https://blog.cybershenanigans.space/posts/boflink-a-linker-for-beacon-object-files/
