CC = gcc
CFLAGS = -g

all: resolver

resolver: resolver.c
	$(CC) $(CFLAGS) -o resolver resolver.c

clean:
	rm -f resolver
