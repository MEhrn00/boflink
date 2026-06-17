# Hello World Example
Example project which compiles and links two source files together into a Beacon Object File.

Source files are located in the [`src/`](src/) directory.

## Compiling

### MinGW GCC (Linux)
```bash
# Generate a GCC spec file for GCC
boflink --print-gcc-specs > boflink.specs

# Compile the source files
x86_64-w64-mingw32-gcc -specs=boflink.specs -Wall -Os -o hello-world.bof src/go.c src/hello.c
```

Using the provided [`GNUmakefile`](GNUmakefile).
```bash
make
```

### Clang (Linux)
```bash
# Uses $(which boflink) to get the full path to the boflink executable
clang --target=x86_64-w64-mingw32 --ld-path=$(which boflink) -nostartfiles -Wall -Os -o hello-world.bof src/go.c src/hello.c
```

Using the provided [`GNUmakefile-clang.mk`](GNUmakefile-clang.mk).
```bash
make -f GNUmakefile-clang.mk
```

### MSVC
Needs to run in a Visual Studio developer command shell.

```powershell
cl -nologo -GS- -W4 -Os -c src\go.c src\hello.c
boflink -o hello-world.bof go.obj hello.obj -lkernel32 -ladvapi32
```

Using the provided [`makefile`](makefile).
```powershell
nmake
```

### Clang-Cl (Windows)

```bash
clang-cl -GS- -W4 -Os -c src\go.c src\hello.c
boflink -o hello-world.bof go.obj hello.obj -lkernel32 -ladvapi32 -lvcruntime
```

Using the provided [`makefile-clangcl.mk`](makefile-clangcl.mk).
```powershell
nmake -f .\makefile-clangcl.mk
```
