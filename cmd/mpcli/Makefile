PROG:=tdns-mpcli

GO:= CGO_ENABLED=1 go

include ../../utils/Makefile.common

.PHONY: clean install pkg

install:
	install -s -b -c ${PROG} /usr/local/bin/

# NetBSD binary package; rule and rationale in ../../utils/Makefile.common.
pkg:	pkg_tdns_mpcli

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
