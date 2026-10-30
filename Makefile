.PHONY: default all clean install pkg bump-johanix-deps test test-race

default: all

all:
	$(MAKE) -C ./cmd/ version
	$(MAKE) -C ./cmd/

clean:
	$(MAKE) -C ./cmd/ clean

install:
	$(MAKE) -C ./cmd/ install

# NetBSD binary packages of the five daemons and the CLI (root; see cmd/Makefile).
pkg:
	$(MAKE) -C ./cmd/ pkg

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
test: check
	cd v2 && CGO_ENABLED=1 go test -cover ./...

# Same, with the race detector. Slower, but catches concurrency
# regressions in the engines/handlers.
test-race: check
	cd v2 && CGO_ENABLED=1 go test -race ./...

# check-no-mutators is tdns's gate over this tree: no direct write into a
# zone's owner store outside the staging API. The served zone is a projection
# of the combiner's state, written through tdns.StageBatch; a Set that lands
# in zone data any other way is lost or serves half a change. The sites that
# write MP-private stores (agent repos, SDE node records, CombinerData,
# UpstreamData) carry a trailing "mp-private:" comment naming what they write,
# per site rather than per file so a new Set in the same file is not covered
# by accident.
check-no-mutators:
	@violations=$$(grep -RnE '\.(RRtypes\.Set|Data\.Set)\(' v2 cmd --include='*.go' \
		| grep -v '_test\.go' \
		| grep -v 'mp-private:' || true); \
	if [ -n "$$violations" ]; then \
		echo "mutator Set() calls outside the staging API:"; \
		echo "$$violations"; \
		exit 1; \
	fi

# check-names keeps DNS names compared and folded by the DNS rule (RFC 4343:
# US-ASCII case only), through core.EqualNames and core.CanonicalizeName
# (canonicalName and sameName in v2), never by hand (#287). Three parts:
#  - tdns's namecheck (tools/namecheck in tdns), the parser tdns gates its
#    own tree with, at the tdns commit v2/go.mod pins: no map key built by a
#    lossy fold, no strings.EqualFold on a name, no name tested folded and
#    then used unfolded. Its first run fetches it; later runs take it from
#    the module cache.
#  - no dns.CanonicalName at all, tests included: it is only ever applied to
#    a name, and it rewrites any octet that is not valid UTF-8, so two names
#    can share one key. canonicalName replaces it.
#  - every strings.ToLower and strings.EqualFold outside the tests carries a
#    trailing "not-a-name:" comment saying what it folds (a keyword, an RR
#    type, an option), per site as with "mp-private:" above. namecheck does
#    not see a name folded by hand behind a helper's return; this does.
NAMECHECK_VERSION = $(shell awk '$$1 == "github.com/johanix/tdns/v2" { sub(/^v2\.0\.0-/, "v0.0.0-", $$2); print $$2 }' v2/go.mod)

check-names:
	@go run github.com/johanix/tdns/tools/namecheck@$(NAMECHECK_VERSION) v2 cmd
	@violations=$$(grep -RnE 'dns\.CanonicalName\(' v2 cmd --include='*.go' || true); \
	if [ -n "$$violations" ]; then \
		echo "dns.CanonicalName rewrites non-UTF-8 octets; use canonicalName:"; \
		echo "$$violations"; \
		exit 1; \
	fi
	@violations=$$(grep -RnE 'strings\.(ToLower|EqualFold)\(' v2 cmd --include='*.go' \
		| grep -v '_test\.go' \
		| grep -v 'not-a-name:' || true); \
	if [ -n "$$violations" ]; then \
		echo "hand-folding: use canonicalName or sameName for a DNS name, or mark the site not-a-name: <what it folds>:"; \
		echo "$$violations"; \
		exit 1; \
	fi

check: check-no-mutators check-names

.PHONY: check check-no-mutators check-names
