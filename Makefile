.PHONY: all clean

# use 'make EXTERNFLAGS=...' to specify additional compiler flags

CC = cc
CFLAGS = -xc -std=c23 -Wall -Wextra -Wpedantic -I./include
LDFLAGS = -lpcap

SOURCES ::= $(wildcard src/*.c)
HEADERS ::= $(wildcard include/*.h)

all: p2nprobe

p2nprobe: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(EXTERNFLAGS) -o $@ $(SOURCES)

clean:
	rm -f p2nprobe
