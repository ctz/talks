DIRS = $(wildcard */)

all:
	for x in $(DIRS); do $(MAKE) -C $$x ; done

clean:
	rm -f */timing */result */timing.* */result.*
	for x in $(DIRS); do $(MAKE) -C $$x clean ; done

results:
	python results.py $(DIRS)
