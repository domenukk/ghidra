# Makefile for GNU Demangler Shared Library

CC = gcc
CFLAGS = -fPIC -Wall -O2 -I../headers -DHAVE_STDLIB_H -DHAVE_STRING_H
LDFLAGS = -shared


# Source files
LIB_SRCS = cplus-dem.c cp-demangle.c d-demangle.c rust-demangle.c safe-ctype.c xexit.c xstrdup.c alloca.c dyn-string.c missing.c
LIB_OBJS = $(LIB_SRCS:.c=.o)

EXEC_SRCS = cxxfilt.c getopt.c getopt1.c argv.c
EXEC_OBJS = $(EXEC_SRCS:.c=.o)

TARGET_LIB = libgnudemangler.so
TARGET_EXEC = demangler_gnu_v2_41

all: $(TARGET_LIB) $(TARGET_EXEC)

$(TARGET_LIB): $(LIB_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(LIB_OBJS)

$(TARGET_EXEC): $(LIB_OBJS) $(EXEC_OBJS)
	$(CC) $(CFLAGS) -o $@ $(LIB_OBJS) $(EXEC_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET_LIB) $(TARGET_EXEC)
