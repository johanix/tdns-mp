.PHONY: default all clean install bump-johanix-deps

default: all

all:
	$(MAKE) -C ./cmd/ version
	$(MAKE) -C ./cmd/

clean:
	$(MAKE) -C ./cmd/ clean

install:
	$(MAKE) -C ./cmd/ install

# bump-johanix-deps: in every go.mod under this repo, refresh every
# github.com/johanix/* require line to its current proxy 'latest'
# (default-branch HEAD of the corresponding repo). Third-party deps
# are not touched. Runs `go mod tidy` per-module afterwards.
#
# Caveat: some johanix sub-modules (notably tdns/v2/cli) currently
# have unresolved pseudo-versions for their sibling sub-modules and
# will fail to fetch externally. The target prints the failure and
# moves on; rerun once the underlying structural issue is fixed.
bump-johanix-deps:
	@for mod in $$(find . -name go.mod -not -path './.git/*'); do \
	   dir=$$(dirname $$mod); \
	   deps=$$(awk '/^require \(/,/^\)/ { if ($$1 ~ /^github\.com\/johanix\//) print $$1 }' $$mod | sort -u); \
	   if [ -z "$$deps" ]; then \
	      continue; \
	   fi; \
	   echo "=== $$dir ==="; \
	   for dep in $$deps; do \
	      echo "  $$dep"; \
	      (cd $$dir && go get $$dep@latest) || echo "  ! $$dep@latest failed (likely unresolved sub-module pin)"; \
	   done; \
	   (cd $$dir && go mod tidy) || echo "  ! go mod tidy failed in $$dir"; \
	done
