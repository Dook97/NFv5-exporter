.PHONY: all clean

# use 'make EXTERNFLAGS=...' to specify additional compiler flags

CXX = g++
CFLAGS = -xc++ -std=c++23 -Wall -Wextra -Wpedantic -I./include
LDFLAGS = -lpcap

SOURCES ::= $(wildcard src/*.cpp)
HEADERS ::= $(wildcard include/*.hpp)

all: p2nprobe

p2nprobe: $(SOURCES) $(HEADERS)
	$(CXX) $(CFLAGS) $(LDFLAGS) $(EXTERNFLAGS) -o $@ $(SOURCES)

clean:
	rm -f p2nprobe
