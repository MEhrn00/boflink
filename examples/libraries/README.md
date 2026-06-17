# Libraries Example
Example project which compiles a static library and links to it.

Source files are located in the [`src/`](src/) directory.
Library files are located in the `mylib/` directory.

## Compiling

### MinGW GCC (Linux)
```bash
# Build the libmylib.a library
x86_64-w64-mingw32-gcc -I. -Wall -Os -c -o mylib.o mylib/mylib.c
x86_64-w64-mingw32-ar rcs libmylib.a mylib.o

# Generate a GCC spec file for GCC
boflink --print-gcc-specs > boflink.specs

# Compile the source files and link with the libmylib.a static library
x86_64-w64-mingw32-gcc -specs=boflink.specs -I. -Wall -Os -o example.bof src/example.c libmylib.a
```

Using the provided [`GNUmakefile`](GNUmakefile).
```bash
make
```

### Clang (Linux)
```bash
# Build the libmylib.a library
clang --target=x86_64-w64-mingw32 -I. -Wall -Os -c -o mylib.o mylib/mylib.c
llvm-ar rcs libmylib.a mylib.o

# Compile the source files and link with the libmylib.a static library
clang --target=x86_64-w64-mingw32 --ld-path=$(which boflink) -nostartfiles -I. -Wall -Os -o example.bof src/example.c libmylib.a
```

Using the provided [`GNUmakefile-clang.mk`](GNUmakefile-clang.mk).
```bash
make -f GNUmakefile-clang.mk
```

### MSVC
Needs to run in a Visual Studio developer command shell.

```powershell
# Build the libmylib.lib library
cl -nologo -I. -GS- -W4 -Os -c mylib\mylib.c
lib -out:libmylib.lib mylib.obj

# Compile the source files and link with the libmylib.lib static library
cl -nologo -I. -GS- -W4 -Os -c src\example.c
boflink -o example.bof example.obj libmylib.lib -lkernel32 -ladvapi32
```

Using the provided [`makefile`](makefile).
```powershell
nmake
```

### Clang-Cl (Windows)

```bash
# Build the libmylib.lib library
clang-cl -I. -GS- -W4 -Os -c mylib\mylib.c
llvm-lib -out:libmylib.lib mylib.obj

# Compile the source files and link with the libmylib.lib static library
clang-cl -I. -GS- -W4 -Os -c src\example.c
boflink -o example.bof example.obj libmylib.lib -lkernel32 -ladvapi32 -lvcruntime
```

Using the provided [`makefile-clangcl.mk`](makefile-clangcl.mk).
```powershell
nmake -f .\makefile-clangcl.mk
```
