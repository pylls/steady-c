.PHONY: test clean

all: demo

demo: demo.c lib
	gcc -std=c11 -Wall -O3 -o demo demo.c libsteady.a liblz4.a -lm -lpthread -lsodium

test: test.c crypto.o memory.o policy.o block.o liblz4.a compress.o
	gcc -std=c11 -Wall -O3 -o test test.c libsteady.a liblz4.a -lm -lpthread -lsodium
	./test

valgrind: demo
	valgrind --leak-check=yes ./demo < demo.c

valgrind-test: liblz4.a lib
	gcc -std=c11 -Wall -O3 -o test test.c libsteady.a liblz4.a -lm -lpthread -lsodium
	valgrind --leak-check=yes ./test

lib: memory.o liblz4.a compress.o crypto.o policy.o block.o device.o
	ar rcs libsteady.a memory.o compress.o crypto.o policy.o block.o device.o

device.o: steady/steady.h steady/device.h steady/device.c memory.o crypto.o policy.o block.o compress.o
	gcc -std=c11 -Wall -O3 -c steady/device.c

block.o: steady/steady.h steady/block.c memory.o crypto.o
	gcc -std=c11 -Wall -O3 -c steady/block.c

policy.o: steady/steady.h steady/policy.c memory.o crypto.o
	gcc -std=c11 -Wall -O3 -c steady/policy.c

crypto.o: steady/steady.h steady/crypto.c memory.o
	gcc -std=c11 -Wall -O3 -c steady/crypto.c

compress.o: steady/steady.h steady/compress.c memory.o
	gcc -std=c11 -Wall -O3 -c steady/compress.c

memory.o: steady/steady.h steady/memory.c
	gcc -std=c11 -Wall -O3 -c steady/memory.c

LZ4SRCFILES := $(sort $(wildcard steady/lz4/*.c))
liblz4.a: $(LZ4SRCFILES)
	gcc -DXXH_NAMESPACE=LZ4_ -std=c11 -Wall -O3 -c $(LZ4SRCFILES)
	ar rcs liblz4.a lz4.o lz4frame.o lz4hc.o xxhash.o

clean:
	rm *.o *.a
