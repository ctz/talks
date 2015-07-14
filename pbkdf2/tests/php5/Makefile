all: test.php
	for x in 1 2 3 4 5 ; do time php5 test.php >result.$$x 2>timing.$$x ; done

debian:
	apt-get install php5-cli
