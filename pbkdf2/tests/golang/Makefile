all: test.go
	GOPATH=`pwd`/pkg go build
	for x in 1 2 3 4 5 ; do time ./golang >result.$$x 2>timing.$$x ; done

ext:
	rm -rf ext
	GOPATH=`pwd`/pkg go get
