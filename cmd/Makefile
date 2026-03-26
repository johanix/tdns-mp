.PHONY: default all clean install mpsigner mpcombiner mpcli

default: all

all: mpsigner mpcombiner mpcli

mpsigner:
	$(MAKE) -C ./mpsigner/

mpcombiner:
	$(MAKE) -C ./mpcombiner/

mpcli:
	$(MAKE) -C ./mpcli/

clean:
	$(MAKE) -C ./mpsigner/ clean
	$(MAKE) -C ./mpcombiner/ clean
	$(MAKE) -C ./mpcli/ clean

install:
	$(MAKE) -C ./mpsigner/ install
	$(MAKE) -C ./mpcombiner/ install
	$(MAKE) -C ./mpcli/ install
