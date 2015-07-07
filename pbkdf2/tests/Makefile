DIRS = $(wildcard */)

all:
	for x in $(DIRS); do $(MAKE) -C $$x ; done

clean:
	rm -f */timing */result
	for x in $(DIRS); do $(MAKE) -C $$x clean ; done

results:
	for x in $(DIRS); do \
	  echo $$x ; \
	  grep -oE '[0-9\.]+user' $$x/timing ; \
	  cat $$x/result ; \
	done
