.PHONY: default all clean install bump-johanix-deps test test-race

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
# Within-repo dependencies (those covered by a `replace` directive
# pointing to a local relative path like ../../v2) are SKIPPED — the
# replace directive already routes them to the working copy on disk,
# so there's no point fetching a proxy version. The require-line
# version remains in go.mod for go.sum verification, but bumping it
# would just churn the file without affecting builds.
#
# Caveat: some johanix sub-modules (notably tdns/v2/cli) currently
# have unresolved pseudo-versions for their sibling sub-modules and
# will fail to fetch externally. The target prints the failure and
# moves on; rerun once the underlying structural issue is fixed.
bump-johanix-deps:
	@for mod in $$(find . -name go.mod -not -path './.git/*'); do \
	   dir=$$(dirname $$mod); \
	   local_replaces=$$(awk '/^replace / { for (i=1; i<=NF; i++) if ($$i == "=>") { tgt=$$(i+1); if (tgt ~ /^\.\.?\//) print $$2 } }' $$mod | sort -u); \
	   deps=$$(awk '/^require \(/,/^\)/ { if ($$1 ~ /^github\.com\/johanix\//) print $$1 }' $$mod | sort -u); \
	   if [ -z "$$deps" ]; then \
	      continue; \
	   fi; \
	   echo "=== $$dir ==="; \
	   for dep in $$deps; do \
	      if echo "$$local_replaces" | grep -qx "$$dep"; then \
	         echo "  $$dep (skipped — covered by local replace)"; \
	         continue; \
	      fi; \
	      echo "  $$dep"; \
	      (cd $$dir && go get $$dep@latest) || echo "  ! $$dep@latest failed (likely unresolved sub-module pin)"; \
	   done; \
	   (cd $$dir && go mod tidy) || echo "  ! go mod tidy failed in $$dir"; \
	done

# Run the Go test suite (transport-boundary harness + SDE/API regression
# tests). GOROOT is taken from the environment, as with the build.
test:
	cd v2 && CGO_ENABLED=1 go test -cover ./...

# Same, with the race detector. Slower, but catches concurrency
# regressions in the engines/handlers.
test-race:
	cd v2 && CGO_ENABLED=1 go test -race ./...
