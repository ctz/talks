all: test.cs
	mcs test.cs
	time mono test.exe >result 2>timing

debian:
	apt-get install mono-complete
