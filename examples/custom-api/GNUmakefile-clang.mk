CC = clang
TARGET = x86_64-w64-mingw32
DLLTOOL = llvm-dlltool
BOFLINK ?= ../../target/debug/boflink

RM = rm -f
MKDIR = mkdir

CFLAGS ?= -Wall -Os
ALL_CFLAGS := --target=$(TARGET) -I. $(CFLAGS)

LDLIBS ?=
LDFLAGS ?=
ALL_LDFLAGS := --target=$(TARGET) $(LDFLAGS)

VPATH += src/ custom-api/

.PHONY : all
all : example.bof

example.bof : example.o libcustom-api.dll.a
	$(CC) --ld-path=$(BOFLINK) -nostartfiles -Wl,--custom-api=libcustom-api.dll.a $(ALL_LDFLAGS) $^ -o $@ $(LDLIBS)

libcustom-api.dll.a : custom-api.def
	$(DLLTOOL) -l $@ -d $<

example.o : example.c beacon.h custom-api.h

.PHONY : clean
clean:
	$(RM) example.bof libcustom-api.dll.a example.o

%.o : %.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<
