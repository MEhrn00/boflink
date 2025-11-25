# moduledef
Parser for Windows [Module-Definition (.Def) Files](https://learn.microsoft.com/en-us/cpp/build/reference/module-definition-dot-def-files?view=msvc-170).

An example module definition file looks something like this.
```text
LIBRARY MYLIBRARY.DLL
EXPORTS
  MyLibraryVersion
  MyLibraryHello
  MyLibraryPrint
  MyLibraryOrdinal
```

These tools will take module definition files and convert them into an import library
(`.lib` file) that can be used for linking with a DLL.
- [GNU dlltool](https://sourceware.org/binutils/docs/binutils/dlltool.html)
- [LLVM dlltool](https://github.com/llvm/llvm-project/tree/dfc0abd325962bfef7b18fbc13db9776ee63647f/llvm/lib/ToolDrivers/llvm-dlltool)
- [lib.exe](https://learn.microsoft.com/en-us/cpp/build/reference/overview-of-lib?view=msvc-170)

Some linkers (link.exe, llvm-link) support linking directly with module definition files
instead of needing to create an intermediate import library for it.


The common way for creating an import library from DLL source code is by using `__decspec(dllexport)`
and having the linker output the import library alongside the DLL.

The issue with this is that Windows system DLLs are not open source.
[gendef](https://www.mingw-w64.org/tools/gendef/) is a tool that can create a module definition
file for a DLL or a small script can be used instead. https://stackoverflow.com/a/9946390


MinGW maintains a set of module definition files for many Windows system DLLs.
- [mingw-w64/mingw-w64-crt/lib-common/](https://github.com/mingw-w64/mingw-w64/tree/8d02d610f707b5f6af74653c6ebb0cdfa4df9212/mingw-w64-crt/lib-common)
- [mingw-w64/mingw-w64-crt/lib64/](https://github.com/mingw-w64/mingw-w64/tree/8d02d610f707b5f6af74653c6ebb0cdfa4df9212/mingw-w64-crt/lib64)
- [mingw-w64/mingw-w64-crt/lib32/](https://github.com/mingw-w64/mingw-w64/tree/8d02d610f707b5f6af74653c6ebb0cdfa4df9212/mingw-w64-crt/lib32)

When building or installing a MinGW toolchain, import libraries for these module definition
files are built and installed in the MinGW sysroot lib path `/usr/x86_64-w64-mingw32/lib`.
