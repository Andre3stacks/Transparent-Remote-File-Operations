all: mylib.so server

mylib.o: mylib.c
	gcc -Wall -fPIC -DPIC -I../include -c mylib.c

mylib.so: mylib.o
	ld -shared -L../lib -o mylib.so mylib.o -ldl -I../include

server: server.o
	gcc server.o -L../lib -ldirtree -o server -I../include

server.o: server.c
	gcc -Wall -fPIC -DPIC -c server.c -I../include

clean:
	rm -f *.o *.so server

