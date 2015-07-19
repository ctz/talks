
CFLAGS += -Wall -Werror -std=gnu99 -O3
LDLIBS += -lcrypto

all: test
	for x in 1 2 3 4 5 ; do \time ./test >result.$$x 2>timing.$$x ; done

test: test.o

debian:
	apt-get install libssl-dev

clean:
	rm -rf *.o test
