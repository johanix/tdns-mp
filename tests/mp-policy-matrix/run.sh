#!/bin/sh
# mp-policy-matrix rig: start | stop | status | converge | verify | clean | redirect
# Run setup.sh once first. See README.md.
SRC="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$SRC/lib.sh"

usage() { echo "usage: sh run.sh start|stop|restart|status|converge|verify|scenario <name>|clean|redirect [--do]|unredirect" >&2; exit 2; }

# ---------------------------------------------------------------- redirect
# The daemons' embedded resolvers look rig.test. up through a stub that is
# dialled on port 53 (the pinned tdns has no other way to name a server), so
# 127.0.0.1:53 must reach the world server, which runs unprivileged on
# port $world_dns. One privileged step: a packet redirect.
#
# The rig owns its redirect so it cannot be forgotten: `redirect --do`
# records what it installed in $RIG/.redirect (and, on macOS, whether pf
# was already enabled); `stop` and `clean` remove it again (KEEP_REDIRECT=1
# keeps it across a stop/start cycle); `status` shows it; `unredirect`
# removes it by hand. The rule lives in its own named anchor / chain
# position, and a reboot clears it in any case.
MARKER="$RIG/.redirect"

redirect() {
	need_seeded
	wp=$(port world dns)
	case "$(uname -s)" in
	Darwin)
		rule="rdr pass on lo0 inet proto { tcp, udp } from any to 127.0.0.1 port 53 -> 127.0.0.1 port $wp"
		echo "macOS: pf redirect of 127.0.0.1:53 to the world server ($wp), in anchor mp-policy-matrix:"
		echo "  echo '$rule' | sudo pfctl -a mp-policy-matrix -f -"
		echo "  sudo pfctl -e"
		echo "undo: sh run.sh unredirect   (or: sudo pfctl -a mp-policy-matrix -F all)"
		if [ "$1" = "--do" ]; then
			was=$(sudo pfctl -s info 2>/dev/null | grep -c 'Status: Enabled')
			echo "$rule" | sudo pfctl -a mp-policy-matrix -f - || return 1
			sudo pfctl -e 2>/dev/null; true
			printf 'os=Darwin\npf_was_enabled=%s\ninstalled=%s\nrule=%s\n' "$was" "$(date '+%Y-%m-%d %H:%M:%S')" "$rule" > "$MARKER"
			echo "installed; recorded in $MARKER"
		fi ;;
	Linux)
		echo "Linux: iptables redirect of 127.0.0.1:53 to the world server ($wp):"
		for proto in udp tcp; do
			echo "  sudo iptables -t nat -A OUTPUT -o lo -p $proto -d 127.0.0.1 --dport 53 -j REDIRECT --to-ports $wp"
		done
		echo "undo: sh run.sh unredirect   (the same rules with -D)"
		if [ "$1" = "--do" ]; then
			for proto in udp tcp; do
				sudo iptables -t nat -A OUTPUT -o lo -p "$proto" -d 127.0.0.1 --dport 53 -j REDIRECT --to-ports "$wp" || return 1
			done
			printf 'os=Linux\nport=%s\ninstalled=%s\n' "$wp" "$(date '+%Y-%m-%d %H:%M:%S')" > "$MARKER"
			echo "installed; recorded in $MARKER"
		fi ;;
	*) echo "no redirect recipe for $(uname -s); run the world server on port 53 instead" ;;
	esac
}

# unredirect: remove what redirect --do installed, per the marker. Needs
# sudo again; says what it runs.
unredirect() {
	[ -f "$MARKER" ] || { echo "no redirect recorded in $MARKER -- nothing to undo"; return 0; }
	# shellcheck disable=SC1090
	. "$MARKER"
	case "$os" in
	Darwin)
		echo "removing pf anchor mp-policy-matrix (sudo pfctl -a mp-policy-matrix -F all)"
		sudo pfctl -a mp-policy-matrix -F all >/dev/null 2>&1 || { echo "pfctl failed; the rule may still be in place -- check: sudo pfctl -a mp-policy-matrix -s nat" >&2; return 1; }
		if [ "$pf_was_enabled" = 0 ]; then echo "pf was disabled before the rig enabled it: sudo pfctl -d"; sudo pfctl -d 2>/dev/null; fi ;;
	Linux)
		for proto in udp tcp; do
			echo "sudo iptables -t nat -D OUTPUT -o lo -p $proto -d 127.0.0.1 --dport 53 -j REDIRECT --to-ports $port"
			sudo iptables -t nat -D OUTPUT -o lo -p "$proto" -d 127.0.0.1 --dport 53 -j REDIRECT --to-ports "$port" || { echo "iptables -D failed for $proto; check: sudo iptables -t nat -L OUTPUT -n" >&2; return 1; }
		done ;;
	esac
	rm -f "$MARKER"
	if port53_ok; then echo "WARNING: 127.0.0.1:53 still reaches the world server after the undo" >&2; return 1; fi
	echo "redirect removed"
}

redirect_status() {
	if [ -f "$MARKER" ]; then
		# shellcheck disable=SC1090
		. "$MARKER"
		if port53_ok; then echo "redirect: installed by this rig at $installed (stop or clean removes it; KEEP_REDIRECT=1 keeps it)"
		else echo "redirect: recorded at $installed but 127.0.0.1:53 does not reach the world server now (world down, or a reboot cleared the rule -- run redirect --do again)"; fi
	elif port53_ok; then echo "redirect: 127.0.0.1:53 reaches the world server, but not through this rig's marker (installed by hand?)"
	else echo "redirect: none (run: sh run.sh redirect --do)"; fi
}

# ---------------------------------------------------------------- start
start() {
	need_seeded
	if [ -n "$(rig_pids)" ]; then
		echo "rig daemons already running (pids: $(rig_pids | tr '\n' ' ')) -- refusing; use stop first" >&2
		exit 1
	fi
	held=$(all_daemons | while read -r label bin cfg dnsport apiport; do listening "$dnsport" && echo "$dnsport($label)"; done)
	[ -n "$held" ] && die "ports held by something else, refusing to start: $(echo "$held" | tr '\n' ' ')"
	mkdir -p "$RIG/log"

	# world first: every combiner and the auditor pull from it
	all_daemons | head -1 | while read -r label bin cfg dnsport apiport; do daemon_start "$label" "$bin" "$cfg"; done
	wait_until 20 sh -c "[ -n \"\$($DIG +norec +short +time=1 +tries=1 @127.0.0.1 -p $(port world dns) rig.test. SOA)\" ]" \
		|| { echo "world server did not come up; see $RIG/log/world.stdout and $RIG/world/tdns-auth.log" >&2; exit 1; }
	echo "world up on $(port world dns)"

	all_daemons | tail -n +2 | while read -r label bin cfg dnsport apiport; do
		daemon_start "$label" "$bin" "$cfg"
		if wait_until 20 listening "$dnsport"; then echo "$label up on $dnsport"; else echo "$label: no listener on $dnsport after 20 s (see $RIG/log/$label.stdout)"; fi
	done
	echo
	if port53_ok; then echo "127.0.0.1:53 reaches the world server: discovery can work"
	else echo "WARNING: 127.0.0.1:53 does not reach the world server -- agents cannot discover each other. Run: sh $SRC/run.sh redirect --do"; [ -f "$MARKER" ] && rm -f "$MARKER" && echo "(stale redirect marker removed)"; fi
}

stop() {
	need_seeded
	# a daemon whose API is gone (a failed start leaves the process alive
	# with its DNS listeners only) would cost the CLI's timeout each: ask
	# only the ones that answer, kill the rest
	all_daemons | tail -n +2 | while read -r label bin cfg dnsport apiport; do
		listening "$apiport" && { mp "$label" stop >/dev/null 2>&1 || true; }
	done
	sleep 2
	pids=$(rig_pids)
	[ -n "$pids" ] && kill $pids 2>/dev/null
	sleep 1
	pids=$(rig_pids)
	[ -n "$pids" ] && kill -9 $pids 2>/dev/null
	echo "stopped"
	if [ -f "$MARKER" ]; then
		if [ "${KEEP_REDIRECT:-0}" = 1 ]; then echo "redirect kept in place (KEEP_REDIRECT=1); undo with: sh run.sh unredirect"
		else unredirect; fi
	fi
}

status() {
	need_seeded
	printf '%-12s %-6s %-9s %-5s %s\n' daemon port listener api process
	all_daemons | while read -r label bin cfg dnsport apiport; do
		l=no; listening "$dnsport" && l=yes
		a=no; listening "$apiport" && a=yes
		p=$(pgrep -f -- "--config $cfg" | head -1)
		printf '%-12s %-6s %-9s %-5s %s\n' "$label" "$dnsport" "$l" "$a" "${p:-down}"
	done
	echo
	redirect_status
	echo
	printf '%-18s %-10s' zone world; for p in $providers; do printf ' %-10s' "$p"; done; echo
	for z in $(cells); do
		printf '%-18s %-10s' "$z" "$(serial "$(port world dns)" "$z")"
		for p in $providers; do
			if cell_providers "$z" | tr ' ' '\n' | grep -qx "$p"; then printf ' %-10s' "$(serial "$(port "$p" signer_dns)" "$z")"; else printf ' %-10s' -; fi
		done
		echo
	done
}

# ---------------------------------------------------------------- converge
# every provider's mplist has every cell it serves without ERROR, every
# provider serves every such cell, and every cell's gossip matrix is
# OPERATIONAL from every reporter.
converged() {
	for p in $providers; do
		out=$(mp "$p-agent" zone mplist 2>/dev/null) || return 1
		for z in $(cells); do
			cell_providers "$z" | tr ' ' '\n' | grep -qx "$p" || continue
			echo "$out" | grep -q "^$z " || return 1
			echo "$out" | grep "^$z " | grep -q ERROR && return 1
			[ -n "$(serial "$(port "$p" signer_dns)" "$z")" ] || return 1
		done
	done
	for z in $(cells); do
		[ "$(cell_field "$z" 2)" -ge 2 ] || continue
		for p in $(cell_providers "$z"); do
			m=$(mp "$p-agent" gossip state -z "$z" 2>/dev/null) || return 1
			echo "$m" | grep -q OPERATIONAL || return 1
			echo "$m" | grep -qE 'NEEDED|UNKNOWN|KNOWN|INTRODUCED|DEGRADED|INTERRUPTED|ERROR|\?' && return 1
		done
	done
	return 0
}

converge() {
	need_seeded
	echo "waiting up to ${CONVERGE_TIMEOUT}s for every cell to converge..."
	start_t=$(date +%s)
	if wait_until "$CONVERGE_TIMEOUT" converged; then
		echo "converged after $(( $(date +%s) - start_t ))s"
	else
		echo "NOT converged after ${CONVERGE_TIMEOUT}s; state now:"
		for p in $providers; do echo "--- $p-agent zone mplist"; mp "$p-agent" zone mplist 2>&1 | head -20; done
		for z in $(cells); do
			[ "$(cell_field "$z" 2)" -ge 2 ] || continue
			p=$(cell_providers "$z" | cut -d' ' -f1)
			echo "--- $p-agent gossip state -z $z"; mp "$p-agent" gossip state -z "$z" 2>&1 | head -8
		done
		return 1
	fi
}

# ---------------------------------------------------------------- verify
. "$SRC/verify.sh"

case "${1:-status}" in
	start)    start ;;
	stop)     stop ;;
	restart)  stop; start ;;
	status)   status ;;
	converge) converge ;;
	verify)   verify_all ;;
	scenario) shift; scenario "$@" ;;
	clean)    KEEP_REDIRECT=0 stop; rm -rf "$RIG"; echo "removed $RIG" ;;
	redirect) shift; redirect "$@" ;;
	unredirect) unredirect ;;
	*)        usage ;;
esac
