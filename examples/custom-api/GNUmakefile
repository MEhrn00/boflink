CROSS_COMPILE ?= x86_64-w64-mingw32-
CC = $(CROSS_COMPILE)gcc
DLLTOOL = $(CROSS_COMPILE)dlltool
BOFLINK ?= ../../target/debug/boflink

RM = rm -f
MKDIR = mkdir

CFLAGS ?= -Wall -Os
ALL_CFLAGS := -I. $(CFLAGS)

VPATH += src/ custom-api/

.PHONY : all
all : example.bof

example.bof : example.o libcustom-api.dll.a | boflink.specs
	$(CC) -specs=boflink.specs -Wl,--custom-api=libcustom-api.dll.a $^ -o $@

libcustom-api.dll.a : custom-api.def
	$(DLLTOOL) -l $@ -d $<

example.o : example.c beacon.h custom-api.h

.PHONY : clean
clean:
	$(RM) example.bof libcustom-api.dll.a example.o

boflink.specs: $(BOFLINK)
	$(BOFLINK) --print-gcc-specs > $@

%.o : %.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<
