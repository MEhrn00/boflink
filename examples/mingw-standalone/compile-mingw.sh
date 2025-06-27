#!/bin/sh

command="x86_64-w64-mingw32-gcc -c -o mingw-standalone.o mingw-standalone.c"
echo $command
eval $command

command="boflink --mingw64 -o mingw-standalone.bof mingw-standalone.o -lkernel32 -ladvapi32"
echo $command
eval $command
