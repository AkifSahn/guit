CFLAGS=-Wall -Wextra
LIBS=`pkg-config --cflags --libs gtk4`

.PHONY: all
all: build/guit

build/guit:src/guit.c src/ipt.c src/ui.h src/ipt.h
	gcc $(CFLAGS) -o build/guit src/guit.c src/ui.c src/ipt.c $(LIBS)

.PHONY: debug
debug:src/guit.c src/ipt.c src/ui.h src/ipt.h
	gcc $(CFLAGS) -g -o build/guit src/guit.c src/ui.c src/ipt.c $(LIBS)

.PHONY: clean
clean:
	rm build/*
