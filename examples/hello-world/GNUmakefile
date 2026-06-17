CROSS_COMPILE ?= x86_64-w64-mingw32-
CC = $(CROSS_COMPILE)gcc
BOFLINK ?= ../../target/debug/boflink

RM = rm -f
MKDIR = mkdir

CFLAGS ?= -Wall -Os

LDLIBS ?=
LDFLAGS ?=

VPATH += src/

.PHONY : all
all : hello-world.bof

hello-world.bof : go.o hello.o | boflink.specs
	$(CC) -specs=boflink.specs $(LDFLAGS) $^ -o $@ $(LDLIBS)

go.o : go.c beacon.h hello.h
hello.o : hello.c hello.h beacon.h

.PHONY : clean
clean:
	$(RM) hello-world.bof go.o hello.o

boflink.specs: $(BOFLINK)
	$(BOFLINK) --print-gcc-specs > $@

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<
