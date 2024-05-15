PROG = $(patsubst %.cpp,%,$(wildcard *Test.cpp))

REQUIRES =configpp

include $(shell echo $${PREFIX-/usr})/share/smartmet/devel/makefile.inc
CFLAGS = -DUNIX -O0 -g $(FLAGS) -Wno-write-strings

INCLUDES += \
	-I../authentication \
	-I/usr/include/smartmet \
	-I/usr/include/smartmet/newbase

LIBS += \
	../authentication.so \
	-lsmartmet-spine \
	-lsmartmet-gis \
	-lsmartmet-newbase \
	-lboost_iostreams \
	-lboost_filesystem \
	-lboost_regex \
	-lboost_thread \
	-lboost_timer \
	-lboost_system \
	$(CONFIGPP_LIBS) \
	-lbz2 -ljpeg -lpng -lz \
	-lpthread

all: $(PROG)
clean:
	rm -f $(PROG) *~

test: $(PROG)
	@echo Running tests:
	@for prog in $(PROG); do \
	./$$prog; \
	done

$(PROG) : % : %.cpp ../authentication.so
	$(CXX) $(CFLAGS) -o $@ $@.cpp $(INCLUDES) $(LIBS)
