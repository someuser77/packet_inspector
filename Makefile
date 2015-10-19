CFLAGS=-g -Wall -Wextra -Isrc/lib -Isrc/modules $(OPTFLAGS)
LIBS=-ldl

# all .c files in source and below
SOURCES=$(filter-out $(wildcard src/modules/*.c src/modules/**/*.c src/$(TARGET).c), $(wildcard src/**/*.c src/*.c))
SOURCES += src/modules/packet_filter.c
OBJECTS=$(SOURCES:.c=.o)

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
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(TARGET_SRC) -o $@ $(LIBS)

#tests: CFLAGS += $(OBJECTS)
test: $(TESTS) $(TEST_PARSERS)
	# $(CC) $(CFLAGS) $(TEST_SRC) -o $(TESTS)
	sh ./tests/runtests.sh

tests: $(TESTS) $(TEST_PARSERS)

$(TESTS):
	$(CC) $(CFLAGS) $(OBJECTS) $@.c -o $@ $(LIBS)

$(TEST_PARSERS):
	$(CC) -c $(CFLAGS) src/lib/parser_repository.o $@.c -o $@.o -fpic $(LIBS)
	$(CC) -o $@.so $@.o -shared
	
clean:
	rm -rf $(OBJECTS) $(TESTS) $(TARGET)
	rm -f tests/tests.log

.PHONY: all dev tests 
