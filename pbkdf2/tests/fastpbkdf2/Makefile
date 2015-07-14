
CFLAGS += -g -O3 -Wall -Werror -std=gnu99
LDLIBS += -lcrypto

all: test
	time ./test >result 2>timing

test: test.o fastpbkdf2/fastpbkdf2.o

clean:
	rm -rf *.o test
