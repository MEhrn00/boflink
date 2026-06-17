CC = clang
TARGET = x86_64-w64-mingw32
BOFLINK ?= ../../target/debug/boflink

RM = rm -f
MKDIR = mkdir

CFLAGS ?= -Wall -Os
ALL_CFLAGS := --target=$(TARGET) $(CFLAGS)

LDLIBS ?=
LDFLAGS ?=
ALL_LDFLAGS := --target=$(TARGET) $(LDFLAGS)

VPATH += src/

.PHONY : all
all : hello-world.bof

hello-world.bof : go.o hello.o
	$(CC) --ld-path=$(BOFLINK) -nostartfiles $(ALL_LDFLAGS) $^ -o $@ $(LDLIBS)

go.o : go.c beacon.h hello.h
hello.o : hello.c hello.h beacon.h

.PHONY : clean
clean:
	$(RM) hello-world.bof go.o hello.o

%.o : %.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<
