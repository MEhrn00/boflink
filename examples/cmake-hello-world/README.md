# CMake Hello World Example
Example CMake project using boflink as the linker.

This only works on Linux.

## Compiling

Use one of the supplied [`toolchains/`](toolchains/) for cross compiling.

```bash
# MinGW
cmake --toolchain toolchains/x86_64-w64-mingw32-gcc.cmake -B build
cmake --build build

# Clang
cmake --toolchain toolchains/clang-mingw64.cmake -B build
cmake --build build
```
