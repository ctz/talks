
CFLAGS += -g -O3 -Wall -Werror -std=gnu99 -Icifra/src -I cifra/src/ext
VPATH = cifra/src

all: test
	for x in 1 2 3 4 5 ; do time ./test >result.$$x 2>timing.$$x ; done

test: test.o pbkdf2.o hmac.o sha1.o blockwise.o chash.o

ext:
	rm -rf cifra
	git clone https://github.com/ctz/cifra.git

clean:
	rm -rf *.o test
