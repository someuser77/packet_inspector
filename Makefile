CFLAGS=-g -Wall -Wextra -Isrc/lib -Isrc/modules $(OPTFLAGS)
LIBS=-ldl

# all .c files in source and below
SOURCES=$(filter-out $(wildcard src/modules/*.c src/modules/**/*.c src/$(TARGET).c), $(wildcard src/**/*.c src/*.c))
SOURCES += src/modules/packet_filter.c
OBJECTS=$(SOURCES:.c=.o)
PARSERS_SRC=$(wildcard src/parsers/*.c)
PARSERS=$(PARSERS_SRC:.c=)

TEST_PARSERS_SRC=$(wildcard tests/parsers/*.c)
TEST_SRC=$(filter-out $(TEST_PARSERS_SRC), $(wildcard tests/*.c tests/**/*.c))

TEST_PARSERS=$(TEST_PARSERS_SRC:.c=)
TESTS=$(TEST_SRC:.c=)

TARGET=packet_inspector
TARGET_SRC=src/$(TARGET).c

all: $(TARGET)

# changing options for just the developer build (-Wextra is useful for finding bugs)
#dev: CFLAGS=-g -Wall -Isrc -Wall -Wextra $(OPTFLAGS)
#dev: all

# makes the target, first the .a file (ar) and then the library via ranlib
$(TARGET): $(OBJECTS) $(PARSERS)
	$(CC) $(OBJECTS) $(TARGET_SRC) -o $@ $(LIBS)
	mkdir -p parsers
	cp src/parsers/*.so parsers
	
test: tests
	sh ./tests/runtests.sh

tests: $(OBJECTS) $(TESTS) $(TEST_PARSERS)

$(TESTS):
	$(CC) $(CFLAGS) $(OBJECTS) $@.c -o $@ $(LIBS)

$(TEST_PARSERS) $(PARSERS):
	$(CC) -c $(CFLAGS) src/lib/parser_repository.o $@.c -o $@.o -fpic $(LIBS)
	$(CC) -o $@.so $@.o -shared
	
clean:
	rm -rf $(OBJECTS) $(TESTS) $(TARGET) $(TEST_PARSERS_SRC:.c=.so) $(PARSERS_SRC:.c=.so)
	rm -f tests/tests.log
	rm -rf parsers
.PHONY: all dev tests 
