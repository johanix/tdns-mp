.PHONY: default all clean install

default: all

all:
	$(MAKE) -C ./cmd/ version
	$(MAKE) -C ./cmd/

clean:
	$(MAKE) -C ./cmd/ clean

install:
	$(MAKE) -C ./cmd/ install
