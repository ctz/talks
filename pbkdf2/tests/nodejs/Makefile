all: test.js
	for x in 1 2 3 4 5 ; do time nodejs test.js >result.$$x 2>timing.$$x ; done

debian:
	apt-get install nodejs
