all: test.go
	GOPATH=`pwd`/pkg go build
	time ./golang >result 2>timing

ext:
	rm -rf ext
	GOPATH=`pwd`/pkg go get
