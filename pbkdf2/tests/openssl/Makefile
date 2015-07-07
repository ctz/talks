
CFLAGS += -Wall -Werror -std=gnu99 -O3
LDLIBS += -lcrypto

all: test
	time ./test >result 2>timing

test: test.o

debian:
	apt-get install libssl-dev

clean:
	rm -rf *.o test
