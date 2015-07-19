all: ../php5/test.php
	for x in 1 2 3 4 5 ; do \time ~/php-pbkdf/rel/php-5.6.10/sapi/cli/php $^ >result.$$x 2>timing.$$x ; done
