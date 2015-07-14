
CFLAGS += -g -O3 -Wall -Werror -std=gnu99
LDLIBS += -lcrypto

all: test
	for x in 1 2 3 4 5 ; do time ./test >result.$$x 2>timing.$$x ; done

test: test.o fastpbkdf2/fastpbkdf2.o

clean:
	rm -rf *.o test
