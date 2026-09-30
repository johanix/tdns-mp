PROG:=tdns-mpagent

GO:= CGO_ENABLED=1 go

include ../../utils/Makefile.common

.PHONY: clean install pkg

install:
	install -s -b -c ${PROG} /usr/local/libexec/

# NetBSD binary package; rule and rationale in ../../utils/Makefile.common.
pkg:	pkg_tdns_mpagent

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
