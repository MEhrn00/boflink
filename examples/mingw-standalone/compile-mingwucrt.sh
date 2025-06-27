#!/bin/sh

command="x86_64-w64-mingw32ucrt-gcc -c -o mingw-standalone.o mingw-standalone.c"
echo $command
eval $command

command="boflink --ucrt64 -o mingw-standalone.bof mingw-standalone.o -lkernel32 -ladvapi32"
echo $command
eval $command
