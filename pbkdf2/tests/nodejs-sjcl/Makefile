all: test.js
	time nodejs test.js >result 2>timing

ext:
	rm -rf sjcl
	git clone https://github.com/bitwiseshiftleft/sjcl.git
	cd sjcl && ./configure --with-sha1 && make

debian:
	apt-get install nodejs
