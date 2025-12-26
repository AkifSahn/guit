build/app:main.c parser.c
	gcc -o build/app main.c parser.c -Wall -Wextra `pkg-config --cflags --libs gtk4`

.PHONY: debug
debug:main.c parser.c
	gcc -g main.c parser.c -o build/app -Wall -Wextra `pkg-config --cflags --libs gtk4`

.PHONY: clean
clean:
	rm build/*
