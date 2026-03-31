.PHONY: default all clean install mpsigner mpcombiner mpagent mpcli

default: all

all: mpsigner mpcombiner mpagent mpcli

mpsigner:
	$(MAKE) -C ./mpsigner/

mpcombiner:
	$(MAKE) -C ./mpcombiner/

mpagent:
	$(MAKE) -C ./mpagent/

mpcli:
	$(MAKE) -C ./mpcli/

clean:
	$(MAKE) -C ./mpsigner/ clean
	$(MAKE) -C ./mpcombiner/ clean
	$(MAKE) -C ./mpagent/ clean
	$(MAKE) -C ./mpcli/ clean

install:
	$(MAKE) -C ./mpsigner/ install
	$(MAKE) -C ./mpcombiner/ install
	$(MAKE) -C ./mpagent/ install
	$(MAKE) -C ./mpcli/ install
