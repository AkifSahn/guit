build/app:main.c
	gcc -o build/app main.c `pkg-config --cflags --libs gtk4` 
