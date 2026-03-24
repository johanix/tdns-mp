PROG:=tdns-mpcli

GO:= CGO_ENABLED=1 go

include ../../utils/Makefile.common

.PHONY: clean install

install:
	install -s -b -c ${PROG} /usr/local/bin/

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
