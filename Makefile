FLAGS = -Wall -Wextra -O0 -g3 -I.

ifeq ($(OS),Windows_NT)
    EXT = .exe
	FLAGS += -lws2_32 -lbcrypt
else
	EXT = .out
	FLAGS += -lssl -lcrypto -fno-omit-frame-pointer -gdwarf-3 -DHTTPS_ENABLED
endif

all: cozisnews$(EXT)

sqlite3.o: src/sqlite3.c
	gcc -c -o $@ $<

cozisnews$(EXT): src/main.c sqlite3.o
	gcc -o $@ src/main.c sqlite3.o $(FLAGS) -I3p

clean:
	rm *.o *.out *.exe
