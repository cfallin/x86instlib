OBJECTS = inst.o

CFLAGS = -O3 -g -fPIC -I. -Idecoder/
CXXFLAGS = -O3 -g -fPIC -I. -Idecoder/
CXX = g++

ifeq ($(shell uname),Linux)
CXXFLAGS := $(CXXFLAGS) -std=c++0x -DLINUX
else
ifeq ($(shell uname),Darwin)
CXXFLAGS := $(CXXFLAGS) -DDARWIN
endif
endif

.PHONY: all
all: libinstlib.a inst

libinstlib.a: $(OBJECTS) decoder
	$(AR) rcs libinstlib.a $(OBJECTS) $(wildcard decoder/*.o)

inst: inst.cc decoder
	$(CXX) $(CXXFLAGS) -D__TEST__ inst.cc $(wildcard decoder/*.o) -o inst

.PHONY: decoder
decoder:
	$(MAKE) -C decoder

.PHONY: clean
clean:
	rm -f *.o *~ inst *.a
	$(MAKE) -C decoder clean
