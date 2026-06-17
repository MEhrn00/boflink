CC = clang-cl
BOFLINK = ..\..\target\debug\boflink.exe

CFLAGS = -GS- -W4 -Os -I.
LDLIBS = -lkernel32 -ladvapi32 -lvcruntime

all: example.bof libmylib.lib

example.bof : example.obj libmylib.lib
	$(BOFLINK) $(LDFLAGS) $** -o $@ $(LDLIBS)

example.obj : src\example.c src\beacon.h mylib\mylib.h

libmylib.lib : mylib.obj
	llvm-lib -nologo -out:$@ $?

mylib.obj : mylib\mylib.c mylib\mylib.h

clean:
	del -f example.bof libmylib.lib example.obj mylib.obj 2>nul

{src\}.c.obj::
	$(CC) $(CFLAGS) -c $<

{mylib\}.c.obj::
	$(CC) $(CFLAGS) -c $<
