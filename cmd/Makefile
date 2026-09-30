.PHONY: default all version clean install pkg check-root install-dirs mpsigner mpcombiner mpagent mpauditor mpcli

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

check-root:
	@if [ "$$(id -u)" -ne 0 ]; then echo "Must run as root"; exit 1; fi

install-dirs: check-root
	mkdir -p /usr/local/bin /usr/local/libexec

# NetBSD binary packages, one per component. Each app's "pkg" target builds,
# installs and packs its own binary, so this needs root for the same reason
# "install" does. The .tgz files are left in the app directories; publishing
# is deliberately not a target here, as in tdns: they go into a per-osrelease
# tree on whichever host serves the packages.
pkg: check-root install-dirs
	$(MAKE) -C ./mpsigner/ pkg
	$(MAKE) -C ./mpcombiner/ pkg
	$(MAKE) -C ./mpagent/ pkg
	$(MAKE) -C ./mpauditor/ pkg
	$(MAKE) -C ./mpcli/ pkg
