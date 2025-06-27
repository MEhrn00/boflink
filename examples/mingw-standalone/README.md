# MinGW Standalone
Uses the `--mingw64/--ucrt64` command line flags to query MinGW GCC for its list of search
paths instead of having MinGW GCC invoke boflink.

## Compiling
A minimal compile script is provided for compiling using MinGW GCC or Clang.

These compile scripts are intended to be used as a reference for the command line flags
needed to run boflink correctly and not as a project build script template.

MinGW GCC (Linux)
```bash
./compile-mingw.sh
```

MinGW UCRT GCC (Linux)
```bash
./compile-mingwucrt.sh
```

Clang (Linux)
```bash
./compile-clang.sh
```
