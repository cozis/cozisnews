
all: sqlite3.o
	gcc main.c variadic.c sqlite3utils.c chttp.c WL.c sqlite3.o -o main -Wall -Wextra -g3 -O0 -lws2_32

sqlite3.o:
	gcc -c sqlite3.c -o sqlite3.o
