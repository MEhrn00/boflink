#!/bin/sh

command="clang --target=x86_64-windows-gnu -c -o mingw-standalone.o mingw-standalone.c"
echo $command
eval $command

command="boflink --mingw64 -o mingw-standalone.bof mingw-standalone.o -lkernel32 -ladvapi32 -lucrt"
echo $command
eval $command
