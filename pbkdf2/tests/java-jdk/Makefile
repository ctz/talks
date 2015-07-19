all: Test.java
	javac Test.java
	for x in 1 2 3 4 5 ; do \time java Test >result.$$x 2>timing.$$x ; done

debian:
	apt-get install openjdk-7-jdk
