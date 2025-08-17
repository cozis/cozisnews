ifeq ($(OS),Windows_NT)
    EXT = .exe
	LFLAGS = -lws2_32 -lbcrypt
else
	EXT = .out
	LFLAGS =
endif

CFLAGS = -Wall -Wextra -O0 -g3 -I3p -fsanitize=address,undefined

HFILES = $(shell find src 3p -name "*.h")
CFILES = $(filter-out 3p/sqlite3.c, $(shell find src 3p -name "*.c"))

all: cozisnews$(EXT)

cozisnews$(EXT): $(CFILES) $(HFILES) sqlite3.o
	gcc -o $@ $(CFILES) sqlite3.o $(CFLAGS) $(LFLAGS)

sqlite3.o: 3p/sqlite3.c
	gcc -o $@ -c $<

clean:
	rm *.o *.out *.exe
