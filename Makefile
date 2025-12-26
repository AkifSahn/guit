.PHONY: all
all: build/guit

build/guit:src/guit.c src/parser.c src/parser.h src/ui.h
	gcc -o build/guit src/guit.c src/parser.c src/ui.c -Wall -Wextra `pkg-config --cflags --libs gtk4`

.PHONY: debug
debug:src/guit.c src/parser.c src/parser.h src/ui.h
	gcc -o build/guit -g src/guit.c src/parser.c src/ui.c -Wall -Wextra `pkg-config --cflags --libs gtk4`

.PHONY: clean
clean:
	rm build/*
