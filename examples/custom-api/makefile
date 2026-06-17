BOFLINK = ..\..\target\debug\boflink.exe

CFLAGS = -nologo -GS- -W4 -Os -I.
LDLIBS = -lkernel32 -ladvapi32

all: example.bof

example.bof : example.obj custom-api.lib
	$(BOFLINK) --custom-api=custom-api.lib $(LDFLAGS) $** -o $@ $(LDLIBS)

custom-api.lib : custom-api\custom-api.def
	lib -nologo -machine:x64 -out:$@ -def:$**

example.obj : src\example.c src\beacon.h custom-api\custom-api.h

clean:
	del -f example.bof custom-api.lib custom-api.exp example.obj 2>nul

{src\}.c.obj::
	$(CC) $(CFLAGS) -c $<
