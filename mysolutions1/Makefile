all: mylib.so server

mylib.o: mylib.c
	gcc -Wall -fPIC -DPIC -I./include -c mylib.c

mylib.so: mylib.o
	ld -shared -L./lib -o mylib.so mylib.o -ldl

server: server.o
	gcc server.o -o server

server.o: server.c
	gcc -Wall -fPIC -DPIC -c server.c

clean:
	rm -f *.o *.so server

