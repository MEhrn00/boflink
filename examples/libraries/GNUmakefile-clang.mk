CC = clang
TARGET = x86_64-w64-mingw32
AR = llvm-ar
BOFLINK ?= ../../target/debug/boflink

RM = rm -f
MKDIR = mkdir

CFLAGS ?= -Wall -Os
ALL_CFLAGS := --target=$(TARGET) -I. $(CFLAGS)

LDLIBS ?=
LDFLAGS ?=
ALL_LDFLAGS := --target=$(TARGET) $(LDFLAGS)

ARFLAGS ?=
ALL_ARFLAGS := rcsU

VPATH += src/ mylib/

.PHONY : all
all : example.bof libmylib.a

example.bof : example.o libmylib.a
	$(CC) --ld-path=$(BOFLINK) -nostartfiles $(ALL_LDFLAGS) $^ -o $@ $(LDLIBS)

example.o : example.c beacon.h mylib.h

libmylib.a : mylib.o
	$(AR) $(ALL_ARFLAGS) $@ $?

mylib.o : mylib.c mylib.h

.PHONY : clean
clean:
	$(RM) example.bof libmylib.a example.o mylib.o

%.o : %.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<
