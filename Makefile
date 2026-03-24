.PHONY: default all clean install

default: all

all:
	$(MAKE) -C ./cmd/mpsigner/
	$(MAKE) -C ./cmd/mpcli/

clean:
	$(MAKE) -C ./cmd/mpsigner/ clean
	$(MAKE) -C ./cmd/mpcli/ clean

install:
	$(MAKE) -C ./cmd/mpsigner/ install
	$(MAKE) -C ./cmd/mpcli/ install
