BOFLINK = ..\..\target\debug\boflink.exe

CFLAGS = -nologo -GS- -W4 -Os
LDLIBS = -lkernel32 -ladvapi32

all: hello-world.bof

hello-world.bof : go.obj hello.obj
	$(BOFLINK) $(LDFLAGS) $** -o $@ $(LDLIBS)

go.obj : src\go.c src\beacon.h src\hello.h
hello.obj : src\hello.c src\hello.h src\beacon.h

clean:
	del -f hello-world.bof go.obj hello.obj 2>nul

{src\}.c.obj::
	$(CC) $(CFLAGS) -c $<
