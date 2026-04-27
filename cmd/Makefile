.PHONY: default all version clean install mpsigner mpcombiner mpagent mpauditor mpcli

default: all

all: mpsigner mpcombiner mpagent mpauditor mpcli

version:
	$(MAKE) -C ./mpsigner/ version
	$(MAKE) -C ./mpcombiner/ version
	$(MAKE) -C ./mpagent/ version
	$(MAKE) -C ./mpauditor/ version
	$(MAKE) -C ./mpcli/ version

mpsigner:
	$(MAKE) -C ./mpsigner/

mpcombiner:
	$(MAKE) -C ./mpcombiner/

mpagent:
	$(MAKE) -C ./mpagent/

mpauditor:
	$(MAKE) -C ./mpauditor/

mpcli:
	$(MAKE) -C ./mpcli/

clean:
	$(MAKE) -C ./mpsigner/ clean
	$(MAKE) -C ./mpcombiner/ clean
	$(MAKE) -C ./mpagent/ clean
	$(MAKE) -C ./mpauditor/ clean
	$(MAKE) -C ./mpcli/ clean

install:
	$(MAKE) -C ./mpsigner/ install
	$(MAKE) -C ./mpcombiner/ install
	$(MAKE) -C ./mpagent/ install
	$(MAKE) -C ./mpauditor/ install
	$(MAKE) -C ./mpcli/ install
