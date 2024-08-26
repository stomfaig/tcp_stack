make: main.c ip.c reassembly_store.c
	gcc -o main main.c ip.c reassembly_store.c -I.

test: test.c ip.c reassembly_store.c
	gcc -g  -DDEBUG_INFO_ENABLED -o test test.c ip.c reassembly_store.c -I. -g