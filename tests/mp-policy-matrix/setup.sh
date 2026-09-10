#!/bin/sh
# Seed the mp-policy-matrix rig into $RIG (default /var/tmp/mp-policy-matrix).
#
# Copies the binaries in, generates every config and zone from cells.tsv,
# mints API keys, TLS certificates and JOSE keypairs. Nothing secret is in
# the repo; everything whose value changes per issuance is made here.
#
# Re-running is destructive to state (db, logs, keys). Pass -k to keep the
# existing keys and certificates.
#
#   RIG=      work root (absolute)                default /var/tmp/mp-policy-matrix
#   MP=       tdns-mp checkout with cmd/*/tdns-mp* built   default: this repo
#   TDNS=     tdns checkout at the commit tdns-mp PINS, with cmdv2/auth and
#             cmdv2/cli built. Default: $MP/../tdns.pinned. The pin is
#             checked, because the HSYNCPARAM wire keys changed in tdns
#             after the pin: a world server from tdns tip would pack
#             servers= where the daemons unpack nsmgmt=.
#   CELLS=    space-separated subset of cells.tsv zones (default: all)
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
RIG="${RIG:-/var/tmp/mp-policy-matrix}"
MP="${MP:-$(cd "$SRC/../.." && pwd)}"
TDNS="${TDNS:-$(cd "$MP/.." && pwd)/tdns.pinned}"
KEEP=0
[ "$1" = "-k" ] && KEEP=1

case "$RIG" in /*) ;; *) echo "RIG must be absolute: $RIG" >&2; exit 1 ;; esac
for tool in python3 openssl dig lsof; do
	command -v "$tool" >/dev/null || { echo "need $tool on PATH" >&2; exit 1; }
done

# --- binaries: the mp daemons from this checkout, tdns-auth from the pin ----
for b in mpagent mpcombiner mpsigner mpauditor mpcli; do
	[ -x "$MP/cmd/$b/tdns-$b" ] || { echo "need $MP/cmd/$b/tdns-$b (build cmd/ first, or set MP=)" >&2; exit 1; }
done
[ -x "$TDNS/cmdv2/auth/tdns-auth" ] || { echo "need $TDNS/cmdv2/auth/tdns-auth (set TDNS= to a tdns checkout at the pinned commit, built)" >&2; exit 1; }
pin=$(grep -E '^\s*github.com/johanix/tdns/v2 v' "$MP/cmd/mpcli/go.mod" | sed -E 's/.*-([0-9a-f]{12}).*/\1/')
have=$(git -C "$TDNS" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
if [ "$pin" != "$have" ]; then
	echo "tdns checkout $TDNS is at $have but tdns-mp pins $pin -- refusing (HSYNCPARAM wire keys differ across that gap)" >&2
	exit 1
fi

echo "rig root:   $RIG"
echo "tdns-mp:    $MP"
echo "tdns (pin): $TDNS @ $have"

if [ "$KEEP" = 1 ] && [ -d "$RIG/p1/keys" ]; then
	rm -rf "$RIG/world/tdns-auth.db" "$RIG"/p?/*.db "$RIG"/auditor/*.db "$RIG/log" "$RIG/zones"
else
	rm -rf "$RIG"
fi
mkdir -p "$RIG/bin" "$RIG/log" "$RIG/zones"
for b in mpagent mpcombiner mpsigner mpauditor mpcli; do cp "$MP/cmd/$b/tdns-$b" "$RIG/bin/"; done
cp "$TDNS/cmdv2/auth/tdns-auth" "$RIG/bin/"
[ -x "$TDNS/cmdv2/cli/tdns-cli" ] && cp "$TDNS/cmdv2/cli/tdns-cli" "$RIG/bin/"

# --- configs and zones from cells.tsv -----------------------------------
# shellcheck disable=SC2086
python3 "$SRC/gen.py" "$RIG" "$SRC/cells.tsv" "$RIG" $CELLS
# shellcheck disable=SC1091
. "$RIG/ports.env"

# --- API keys: one per daemon, substituted into every generated yaml -----
subst() { # name
	key=$(openssl rand -hex 16)
	for f in "$RIG"/world/*.yaml "$RIG"/p?/*.yaml "$RIG"/auditor/*.yaml "$RIG"/tdns-mpcli.yaml; do
		[ -f "$f" ] || continue
		sed -i.bak "s|@APIKEY_$1@|$key|g" "$f" && rm -f "$f.bak"
	done
}
subst world; subst auditor
for p in $providers; do subst "${p}_agent"; subst "${p}_combiner"; subst "${p}_signer"; done
if grep -rl '@APIKEY_' "$RIG"/*.yaml "$RIG"/*/*.yaml >/dev/null 2>&1; then
	echo "unsubstituted placeholder left:" >&2; grep -rn '@APIKEY_' "$RIG"/*.yaml "$RIG"/*/*.yaml >&2; exit 1
fi

# --- TLS certificates for the management APIs (self-signed, CN = identity)
cert() { # dir name cn
	mkdir -p "$1/certs"
	[ "$KEEP" = 1 ] && [ -f "$1/certs/$2.crt" ] && return
	openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$3" \
		-keyout "$1/certs/$2.key" -out "$1/certs/$2.crt" >/dev/null 2>&1
}
cert "$RIG/world" world "world.rig.test"
cert "$RIG/auditor" auditor "auditor.rig.test"
for p in $providers; do
	for k in agent combiner signer; do cert "$RIG/$p" "$k" "$k.$p.rig.test"; done
done

# --- JOSE keypairs for CHUNK signing/encryption -----------------------------
jose() { # dir name
	mkdir -p "$1/keys"
	[ "$KEEP" = 1 ] && [ -f "$1/keys/$2.jose.priv.json" ] && return
	"$RIG/bin/tdns-mpcli" --config "$RIG/tdns-mpcli.yaml" signer keys generate --jose \
		--jose-outfile "$1/keys/$2.jose.priv.json" --jose-pubfile "$1/keys/$2.jose.pub.json" >/dev/null
}
jose "$RIG/auditor" auditor
for p in $providers; do for k in agent combiner signer; do jose "$RIG/$p" "$k"; done; done

echo
echo "seeded: $(grep -vc '^#' "$RIG/cells.tsv") cells, providers: $providers, auditor, world"
echo "next:   sh $SRC/run.sh redirect   (once per boot: 127.0.0.1:53 -> world, needs sudo)"
echo "        sh $SRC/run.sh start && sh $SRC/run.sh converge && sh $SRC/run.sh verify"
