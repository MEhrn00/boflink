# Custom API Example
Example project which uses a custom Beacon API implementation instead of the default
Cobalt Strike Beacon API functions.

Source files are located in the [`src/`](src/) directory.
Files for the custom API are located in the `custom-api/` directory.

## Compiling

### MinGW GCC (Linux)
```bash
# Build the custom API import library
x86_64-w64-mingw32-dlltool -l libcustom-api.dll.a -d custom-api/custom-api.def

# Generate a GCC spec file for GCC
boflink --print-gcc-specs > boflink.specs

# Compile the source files and use the custom API import library
x86_64-w64-mingw32-gcc -specs=boflink.specs -I. -Wall -Os -Wl,--custom-api=libcustom-api.dll.a -o example.bof src/example.c
```

Using the provided [`GNUmakefile`](GNUmakefile).
```bash
make
```

### Clang (Linux)
```bash
# Build the custom API import library
llvm-dlltool -l libcustom-api.dll.a -d custom-api/custom-api.def

# Compile the source files and use the custom API import library
clang --target=x86_64-w64-mingw32 --ld-path=$(which boflink) -nostartfiles -Wall -Os -Wl,--custom-api=libcustom-api.dll.a -o example.bof src/example.c
```

Using the provided [`GNUmakefile-clang.mk`](GNUmakefile-clang.mk).
```bash
make -f GNUmakefile-clang.mk
```

### MSVC
Needs to run in a Visual Studio developer command shell.

```powershell
lib -machine:x64 -out:custom-api.lib -def:custom-api\custom-api.def
cl -nologo -I. -GS- -W4 -Os -c src\example.c
boflink --custom-api=custom-api.lib -o example.bof example.obj -lkernel32 -ladvapi32
```

Using the provided [`makefile`](makefile).
```powershell
nmake
```

### Clang-Cl (Windows)

```bash
llvm-lib -machine:x64 -out:custom-api.lib -def:custom-api\custom-api.def
clang-cl -I. -GS- -W4 -Os -c src\example.c
boflink --custom-api=custom-api.lib -o example.bof example.obj -lkernel32 -ladvapi32 -lvcruntime
```

Using the provided [`makefile-clangcl.mk`](makefile-clangcl.mk).
```powershell
nmake -f .\makefile-clangcl.mk
```
