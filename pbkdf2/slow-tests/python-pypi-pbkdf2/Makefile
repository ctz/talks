all: script.py
	time python3 script.py >result 2>timing

clean:
	rm -rf *.pyc __pycache__

ext:
	rm -rf pbkdf2.py *.pyc __pycache__
	wget https://raw.githubusercontent.com/dlitz/python-pbkdf2/0d434eb4be0a60a69f0ead78a61c75c3ab08fc03/pbkdf2.py
