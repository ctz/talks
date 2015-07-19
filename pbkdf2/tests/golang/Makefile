all: test.go
	go build
	for x in 1 2 3 4 5 ; do \time ./golang >result.$$x 2>timing.$$x ; done

ext:
	rm -rf ext
	go get
