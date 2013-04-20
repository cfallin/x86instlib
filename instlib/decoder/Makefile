
SOURCES=$(wildcard *.cpp)
OBJECTS=$(patsubst %.cpp,%.o,$(SOURCES))

FLAGS=-O3 -g -fPIC
INCLUDES=-I.

ifeq ($(shell uname),Linux)
FLAGS := $(FLAGS) -std=c++0x -DLINUX
else
ifeq ($(shell uname),Darwin)
FLAGS := $(FLAGS) -DDARWIN
endif
endif

.PHONY: all

all: $(OBJECTS) libdecoder.a

libdecoder.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

%.o: %.cpp
	g++ $(FLAGS) $(INCLUDES) -c $< -o $@

.PHONY: clean
clean:
	rm -f *.o *~ libdecoder.a
