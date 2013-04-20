O=itrace.o itrace_lib.o sha1.o
OBJS = $(foreach obj,$(O),obj/$(obj))

# Pin settings
PIN_KIT := $(PIN)
TARGET_COMPILER=gnu
export PIN_KIT
export TARGET_COMPILER
include $(PIN_KIT)/source/tools/makefile.gnu.config

CXXFLAGS=$(PIN_CXXFLAGS) -g -I$(PIN_KIT)/source/tools/InstLib -I$(PIN_KIT)/extras/xed2-intel64/include
LDFLAGS = -L$(PIN_KIT)/extras/xed2-intel64/lib -lxed

.PHONY: all
all: itrace.so

itrace.so: $(OBJS)
	$(CXX) $(PIN_LDFLAGS) $(LDFLAGS) -o $@ $^ $(PIN_LPATHS) $(PIN_LIBS) -lz -L../instlib -linstlib

DEPS = $(OBJS:.o=.d)
-include $(DEPS)

.SUFFIXES:
.SUFFIXES: .cc .o .d

obj/%.d: %.cc
	$(CXX) $(CXXFLAGS) -MM -o $@ $^
obj/%.d: %.c
	$(CXX) $(CXXFLAGS) -MM -o $@ $^
obj/%.o: %.cc
	$(CXX) $(CXXFLAGS) -o $@ -c $<
obj/%.o: %.c
	$(CXX) $(CXXFLAGS) -o $@ -c $<

.PHONY: clean
clean: 
	rm -f obj/*.o obj/*.d *~ itrace.so pin.log
