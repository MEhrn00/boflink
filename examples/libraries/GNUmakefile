CROSS_COMPILE ?= x86_64-w64-mingw32-
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
BOFLINK ?= ../../target/debug/boflink

RM = rm -f
MKDIR = mkdir

CFLAGS ?= -Wall -Os
ALL_CFLAGS := -I. $(CFLAGS)

ARFLAGS ?=
ALL_ARFLAGS := rcs

VPATH += src/ mylib/

.PHONY : all
all : example.bof libmylib.a

example.bof : example.o libmylib.a | boflink.specs
	$(CC) -specs=boflink.specs $^ -o $@

example.o : example.c beacon.h mylib.h

libmylib.a : mylib.o
	$(AR) $(ALL_ARFLAGS) $@ $?

mylib.o : mylib.c mylib.h

.PHONY : clean
clean:
	$(RM) example.bof libmylib.a example.o mylib.o

boflink.specs: $(BOFLINK)
	$(BOFLINK) --print-gcc-specs > $@

%.o : %.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<
