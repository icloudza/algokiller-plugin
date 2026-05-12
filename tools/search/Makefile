CC ?= cc
# -pthread enables POSIX threads on both Linux (links libpthread) and macOS
# (no-op since pthread is in libSystem). Required for constscan / cryptoinstr
# data-parallel line scans.
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -Wpedantic -pthread
LDFLAGS ?= -pthread

TARGET := ak_search
SRC := search.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)
