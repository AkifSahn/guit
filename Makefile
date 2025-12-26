.PHONY: all
all: build/app

build/app:src/main.c src/parser.c src/parser.h
	gcc -o build/app src/main.c src/parser.c -Wall -Wextra `pkg-config --cflags --libs gtk4`

.PHONY: debug
debug:src/main.c src/parser.c src/parser.h
	gcc -g src/main.c src/parser.c -o build/app -Wall -Wextra `pkg-config --cflags --libs gtk4`

.PHONY: clean
clean:
	rm build/*
