.PHONY: default all clean install

default: all

all:
	$(MAKE) -C ./cmd/mpagent/
	$(MAKE) -C ./cmd/mpsigner/
	$(MAKE) -C ./cmd/mpcombiner/
	$(MAKE) -C ./cmd/mpcli/

clean:
	$(MAKE) -C ./cmd/mpagent/ clean
	$(MAKE) -C ./cmd/mpsigner/ clean
	$(MAKE) -C ./cmd/mpcombiner/ clean
	$(MAKE) -C ./cmd/mpcli/ clean

install:
	$(MAKE) -C ./cmd/mpagent/ install
	$(MAKE) -C ./cmd/mpsigner/ install
	$(MAKE) -C ./cmd/mpcombiner/ install
	$(MAKE) -C ./cmd/mpcli/ install
