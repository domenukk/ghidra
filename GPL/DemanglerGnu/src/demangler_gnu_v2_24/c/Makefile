CC = gcc
CFLAGS = -Wall -O2 -I../headers -DHAVE_STDLIB_H -DHAVE_STRING_H

SRCS = cplus-dem.c cp-demangle.c cxxfilt.c getopt.c getopt1.c safe-ctype.c xexit.c xstrdup.c alloca.c argv.c dyn-string.c xmalloc.c
OBJS = $(SRCS:.c=.o)
TARGET = demangler_gnu_v2_24

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
