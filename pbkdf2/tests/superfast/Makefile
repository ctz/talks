
CFLAGS += -g -O3 -Wall -Werror -std=gnu99
LDLIBS += -lcrypto

all: test
	time ./test >result 2>timing

test: test.o

clean:
	rm -rf *.o test
