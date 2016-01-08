CFLAGS=-g -Wall -Wextra -Werror -Isrc/lib -Isrc/modules -Isrc $(OPTFLAGS)
LIBS=-ldl

# all .c files in source and below
SOURCES=$(filter-out $(wildcard src/modules/*.c src/modules/**/*.c src/$(TARGET).c src/parsers/*.c), $(wildcard src/**/*.c src/*.c))
SOURCES += src/modules/packet_filter.c
OBJECTS=$(SOURCES:.c=.o)
PARSERS_SRC=$(wildcard src/parsers/*.c)
PARSERS=$(PARSERS_SRC:.c=)

TEST_PARSERS_SRC=$(wildcard tests/parsers/*.c)
TEST_SRC=$(filter-out $(TEST_PARSERS_SRC) $(TEST_OBJS:.o=.c), $(wildcard tests/*.c tests/**/*.c))
TEST_OBJS=tests/lib/filter_options_tests_utils.o

TEST_PARSERS=$(TEST_PARSERS_SRC:.c=)
TESTS=$(filter-out $(TEST_OBJS:.o=.c), $(TEST_SRC:.c=))

TARGET=packet_inspector
TARGET_SRC=src/$(TARGET).c

all: $(TARGET)

# changing options for just the developer build (-Wextra is useful for finding bugs)
#dev: CFLAGS=-g -Wall -Isrc -Wall -Wextra $(OPTFLAGS)
#dev: all

# makes the target, first the .a file (ar) and then the library via ranlib
$(TARGET): $(OBJECTS) $(PARSERS)
	$(CC) $(CFLAGS) $(OBJECTS) $(TARGET_SRC) -o $@ $(LIBS)
	mkdir -p parsers
	cp src/parsers/*.so parsers
	
test: tests
	sh ./tests/runtests.sh

tests: $(OBJECTS) $(TEST_OBJS) $(TESTS) $(TEST_PARSERS) 

$(TEST_OBJS):
	$(CC) -c $(CFLAGS) $(@:.o=.c) -o $@

$(TESTS): $(TEST_OBJS)
	$(CC) $(CFLAGS) $(OBJECTS) $(TEST_OBJS) $@.c -o $@ $(LIBS)

$(TEST_PARSERS) $(PARSERS):
	$(CC) -c $(CFLAGS) $@.c -o $@.o -fpic $(LIBS)
	$(CC) -o $@.so $@.o -shared
	
clean:
	rm -rf $(OBJECTS) $(TESTS) $(TARGET) $(TEST_PARSERS_SRC:.c=.o) $(TEST_PARSERS_SRC:.c=.so) $(PARSERS_SRC:.c=.so) $(PARSERS_SRC:.c=.o)
	rm -f tests/tests.log
	rm -rf parsers
	
.PHONY: all dev tests 
