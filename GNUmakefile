# Common
prefix= /usr/local
libdir= $(prefix)/lib
incdir= $(prefix)/include
bindir= $(prefix)/bin

CC=   clang

CFLAGS+= -std=c99
CFLAGS+= -Wall -Wextra -Werror -Wsign-conversion
CFLAGS+= -Wno-unused-parameter -Wno-unused-function
CFLAGS+= -Isrc

LDFLAGS+= -L.

LDLIBS+= -lio -lcore -lutest

PANDOC_OPTS= -s --toc --email-obfuscation=none

# Platform specific
platform= $(shell uname -s)

ifeq ($(platform), Linux)
	CFLAGS+= -DIO_PLATFORM_LINUX
	CFLAGS+= -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
endif

ifeq ($(platform), FreeBSD)
	CFLAGS+= -DIO_PLATFORM_FREEBSD
	CFLAGS+= -I/usr/local/include
	LDFLAGS+= -L/usr/local/lib
endif

# Debug
debug=0
ifeq ($(debug), 1)
	CFLAGS+= -g -ggdb -DIO_DEBUG
else
	CFLAGS+= -O2 -DNDEBUG
endif

# Coverage
coverage?= 0
ifeq ($(coverage), 1)
	CC= gcc
	CFLAGS+= -fprofile-arcs -ftest-coverage
	LDFLAGS+= --coverage
endif

# Target: libio
libio_LIB= libio.a
libio_SRC= $(wildcard src/*.c)
libio_INC= $(wildcard src/*.h)
libio_PUBINC= src/io.h
libio_OBJ= $(subst .c,.o,$(libio_SRC))

# Target: tests
tests_SRC= $(wildcard tests/*.c)
tests_OBJ= $(subst .c,.o,$(tests_SRC))
tests_BIN= $(subst .o,,$(tests_OBJ))

# Target: utils
utils_SRC= $(wildcard utils/*.c)
utils_OBJ= $(subst .c,.o,$(utils_SRC))
utils_BIN= $(subst .o,,$(utils_OBJ))

# Target: examples
examples_SRC= $(wildcard examples/*.c)
examples_OBJ= $(subst .c,.o,$(examples_SRC))
examples_BIN= $(subst .o,,$(examples_OBJ))

# Target: doc
doc_SRC= $(wildcard doc/*.mkd)
doc_HTML= $(subst .mkd,.html,$(doc_SRC))

# Rules
all: lib tests utils examples doc

lib: $(libio_LIB)

tests: lib $(tests_BIN)

utils: lib $(utils_BIN)

examples: lib $(examples_BIN)

doc: $(doc_HTML)

$(libio_LIB): $(libio_OBJ)
	$(AR) cr $@ $(libio_OBJ)

$(tests_OBJ): $(libio_LIB) $(libio_INC)
tests/%: tests/%.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(utils_OBJ): $(libio_LIB) $(libio_INC)
utils/%: utils/%.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(examples_OBJ): $(libio_LIB) $(libio_INC)
examples/%: examples/%.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

doc/%.html: doc/*.mkd
	pandoc $(PANDOC_OPTS) -t html5 -o $@ $<

clean:
	$(RM) $(libio_LIB) $(wildcard src/*.o)
	$(RM) $(tests_BIN) $(wildcard tests/*.o)
	$(RM) $(examples_BIN) $(wildcard examples/*.o)
	$(RM) $(utils_BIN) $(wildcard utils/*.o)
	$(RM) $(wildcard **/*.gc??)
	$(RM) -r coverage
	$(RM) -r $(doc_HTML)

coverage:
	lcov -o /tmp/libio.info -c -d . -b .
	genhtml -o coverage -t libio /tmp/libio.info
	rm /tmp/libio.info

install: lib
	mkdir -p $(libdir) $(incdir) $(bindir)
	install -m 644 $(libio_LIB) $(libdir)
	install -m 644 $(libio_PUBINC) $(incdir)
	#install -m 755 $(utils_BIN) $(bindir)

uninstall:
	$(RM) $(addprefix $(libdir)/,$(libio_LIB))
	$(RM) $(addprefix $(incdir)/,$(libio_PUBINC))
	#$(RM) $(addprefix $(bindir)/,$(utils_BIN))

tags:
	ctags -o .tags -a $(wildcard src/*.[hc])

.PHONY: all lib tests utils examples doc clean coverage install uninstall tags
