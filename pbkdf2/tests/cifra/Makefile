
CFLAGS += -g -O3 -Wall -Werror -std=gnu99 -Icifra/src -I cifra/src/ext
VPATH = cifra/src

all: test
	time ./test >result 2>timing

test: test.o pbkdf2.o hmac.o sha1.o blockwise.o chash.o

ext:
	rm -rf cifra
	git clone https://github.com/ctz/cifra.git

clean:
	rm -rf *.o test
