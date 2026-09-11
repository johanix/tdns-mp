#!/bin/sh
# Shared helpers for the mp-policy-matrix rig. Sourced by run.sh; not a
# program. Every assertion prints exactly one PASS/FAIL line.
#
# Two words matter throughout: a PROVIDER (p1, p2, p3) is one agent +
# combiner + signer; what a provider SERVES is what its signer answers on
# its DNS port, exactly as the testbed's signers answer on port 53.

RIG="${RIG:-/var/tmp/mp-policy-matrix}"
DIG="${DIG:-dig}"
CONVERGE_TIMEOUT="${CONVERGE_TIMEOUT:-240}"
OP_TIMEOUT="${OP_TIMEOUT:-120}"

pass=0
fail=0
PASS() { pass=$((pass + 1)); printf '  PASS  %s\n' "$*"; }
FAIL() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$*"; }
note() { printf '        %s\n' "$*"; }
die()  { printf 'mp-policy-matrix: %s\n' "$*" >&2; exit 1; }

need_seeded() {
	[ -f "$RIG/ports.env" ] || die "not seeded -- run setup.sh first (RIG=$RIG)"
	# shellcheck disable=SC1091
	. "$RIG/ports.env"
}

# port <provider|world|auditor> <role> -> port number, from ports.env
port() {
	case "$1" in
	world)   eval "echo \$world_$2" ;;
	auditor) eval "echo \$auditor_$2" ;;
	*)       eval "echo \$${1}_${2}" ;;
	esac
}

# mp <instance word> <args...> : tdns-mpcli against the rig config
mp() { "$RIG/bin/tdns-mpcli" --config "$RIG/tdns-mpcli.yaml" "$@"; }

# ---- cells.tsv access -------------------------------------------------
cells()          { grep -v '^#' "$RIG/cells.tsv" | cut -f1; }
cell_field()     { grep -v '^#' "$RIG/cells.tsv" | awk -F'\t' -v z="$1" -v c="$2" '$1==z{print $c}'; }
cell_providers() { cell_field "$1" 5 | tr ',' ' '; }
cell_signers()   { s=$(cell_field "$1" 6); [ "$s" = "-" ] || echo "$s" | tr ',' ' '; }
cell_nsmgmt()    { cell_field "$1" 4; }
# upstream of provider $2 in cell $1, or empty
cell_upstream()  { cell_field "$1" 7 | tr ',' '\n' | awk -F: -v p="$2" '$1==p{print $2}'; }
is_signer()      { cell_signers "$1" | tr ' ' '\n' | grep -qx "$2"; }

# ---- DNS observation --------------------------------------------------
# rrset <server-port> <name> <type> : normalised RRset (owner/type/rdata,
# lower-cased, TTL dropped, sorted), empty on no answer
rrset() {
	$DIG +norec +noall +answer +time=2 +tries=1 @127.0.0.1 -p "$1" "$2" "$3" 2>/dev/null \
	  | awk 'NF>=5 && $4!="RRSIG" {printf "%s %s", tolower($1), $4; for(i=5;i<=NF;i++) printf " %s", $i; printf "\n"}' \
	  | sort
}
# served <provider> <zone> <type> : the RRset the provider serves
served() { rrset "$(port "$1" signer_dns)" "$2" "$3"; }
# rrsig_tags <port> <name> <type> : key tags of the RRSIGs over that RRset
rrsig_tags() {
	$DIG +norec +noall +answer +dnssec +time=2 +tries=1 @127.0.0.1 -p "$1" "$2" "$3" 2>/dev/null \
	  | awk '$4=="RRSIG"{print $11}' | sort -u
}
dnskey_tags() {
	$DIG +norec +noall +answer +time=2 +tries=1 @127.0.0.1 -p "$1" "$2" DNSKEY 2>/dev/null \
	  | awk '$4=="DNSKEY"' > "$RIG/.dnskeys.$$"
	# key tag via dig's own +multiline decoration is unreliable; ask the
	# server for RRSIGs instead where a tag is needed (rrsig_tags).
	awk '{print $5, $6, $7, $8}' "$RIG/.dnskeys.$$" | sort; rm -f "$RIG/.dnskeys.$$"
}
serial() { $DIG +norec +short +time=2 +tries=1 @127.0.0.1 -p "$1" "$2" SOA 2>/dev/null | awk '{print $3}'; }

# ---- assertions ---------------------------------------------------------
assert_eq() { # label expected actual
	if [ "$2" = "$3" ]; then PASS "$1"; else FAIL "$1"; note "want: $(echo "$2" | tr '\n' '|')"; note " got: $(echo "$3" | tr '\n' '|')"; fi
}
assert_has()   { if echo "$3" | grep -qF -- "$2"; then PASS "$1"; else FAIL "$1"; note "missing: $2"; note "in: $(echo "$3" | tr '\n' '|')"; fi; }
assert_lacks() { if echo "$3" | grep -qF -- "$2"; then FAIL "$1"; note "present: $2"; else PASS "$1"; fi; }
assert_nonempty() { if [ -n "$2" ]; then PASS "$1"; else FAIL "$1 (empty)"; fi; }
assert_empty()    { if [ -z "$2" ]; then PASS "$1"; else FAIL "$1"; note "got: $(echo "$2" | tr '\n' '|')"; fi; }

# wait_until <seconds> <cmd...> : poll every 2 s; 0 when cmd succeeds
wait_until() {
	secs=$1; shift
	end=$(( $(date +%s) + secs ))
	while :; do
		if "$@" >/dev/null 2>&1; then return 0; fi
		[ "$(date +%s)" -ge "$end" ] && return 1
		sleep 2
	done
}

# ---- processes ----------------------------------------------------------
rig_pids() { pgrep -f -- "--config $RIG/" 2>/dev/null; }
# listening <port>: something accepts TCP on 127.0.0.1:<port> (every rig
# daemon listens on TCP as well as UDP). nc, not lsof: lsof takes seconds
# per call on macOS.
listening() { nc -z -w 1 127.0.0.1 "$1" >/dev/null 2>&1; }

# daemon_start <label> <binary> <config> : nohup in the background
# The outer redirection matters: without it the subshell still holds the
# caller's stdout, and a run.sh piped into something (tail, tee) never sees
# EOF while the daemons live.
daemon_start() {
	label=$1; bin=$2; cfg=$3
	(cd "$RIG" && nohup "$bin" --config "$cfg" < /dev/null > "$RIG/log/$label.stdout" 2>&1 &) > /dev/null 2>&1 < /dev/null
}

# all_daemons: label binary config dns-port api-port, one per line, in
# start order
all_daemons() {
	printf 'world %s/bin/tdns-auth %s/world/tdns-auth.yaml %s %s\n' "$RIG" "$RIG" "$(port world dns)" "$(port world api)"
	for p in $providers; do
		printf '%s-combiner %s/bin/tdns-mpcombiner %s/%s/tdns-mpcombiner.yaml %s %s\n' "$p" "$RIG" "$RIG" "$p" "$(port "$p" combiner_dns)" "$(port "$p" combiner_api)"
		printf '%s-signer %s/bin/tdns-mpsigner %s/%s/tdns-mpsigner.yaml %s %s\n' "$p" "$RIG" "$RIG" "$p" "$(port "$p" signer_dns)" "$(port "$p" signer_api)"
		printf '%s-agent %s/bin/tdns-mpagent %s/%s/tdns-mpagent.yaml %s %s\n' "$p" "$RIG" "$RIG" "$p" "$(port "$p" agent_dns)" "$(port "$p" agent_api)"
	done
	printf 'aud %s/bin/tdns-mpauditor %s/auditor/tdns-mpauditor.yaml %s %s\n' "$RIG" "$RIG" "$(port auditor dns)" "$(port auditor api)"
}

# port53_ok: the IMRs dial 127.0.0.1:53 for rig.test.; is the world server
# reachable there (via the redirect, see run.sh redirect)?
port53_ok() {
	$DIG +norec +short +time=1 +tries=1 @127.0.0.1 -p 53 rig.test. SOA 2>/dev/null | grep -q '^world\.rig\.test\.'
}
