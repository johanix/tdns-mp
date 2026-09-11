#!/bin/sh
# The assertions the rig exists to make. Sourced by run.sh after lib.sh.
#
# verify_all: static invariants for every cell, then the scenarios in
# dependency order. Each assertion is one PASS/FAIL line; the exit status
# is non-zero if any failed.

# ---------------------------------------------------------------- static
# For each cell and each provider in it: the daemon's own reading of the
# zone's policy (agent zone mplist) matches cells.tsv; the provider serves
# the zone; the signed/unsigned shape matches the provider's role; the
# ordinary content passed through unchanged.
verify_static() {
	echo "A. static invariants (what each provider concluded from HSYNC3/HSYNCPARAM, and what it serves)"
	wp=$(port world dns)
	for z in $(cells); do
		P=$(cell_field "$z" 2); S=$(cell_field "$z" 3); nsmgmt=$(cell_nsmgmt "$z")
		want_servers=$(cell_field "$z" 5); want_signers=$(cell_field "$z" 6); [ "$want_signers" = "-" ] && want_signers="(none)"
		world_ns=$(rrset "$wp" "$z" NS); world_txt=$(rrset "$wp" "$z" TXT); world_www=$(rrset "$wp" "www.$z" A)
		for p in $(cell_providers "$z"); do
			row=$(mp "$p-agent" zone mplist 2>/dev/null | awk -v z="$z" '$1==z')
			assert_nonempty "$z $p: mplist row present" "$row"
			[ -n "$row" ] || continue
			assert_eq "$z $p: mplist servers=$want_servers signers=$want_signers nsmgmt=$nsmgmt" \
				"$want_servers $want_signers $nsmgmt" "$(echo "$row" | awk '{print $2, $3, $5}')"
			assert_lacks "$z $p: mplist row not ERROR" "ERROR" "$row"
			sp=$(port "$p" signer_dns)
			assert_nonempty "$z $p: serves the zone (SOA on $sp)" "$(serial "$sp" "$z")"
			assert_eq "$z $p: NS RRset as the owner published" "$world_ns" "$(rrset "$sp" "$z" NS)"
			assert_eq "$z $p: ordinary content passes through (TXT)" "$world_txt" "$(rrset "$sp" "$z" TXT)"
			assert_eq "$z $p: ordinary content passes through (www A)" "$world_www" "$(rrset "$sp" "www.$z" A)"
			if [ "$S" = 0 ]; then
				assert_empty "$z $p: unsigned cell serves no DNSKEY" "$(rrset "$sp" "$z" DNSKEY)"
			elif is_signer "$z" "$p"; then
				assert_nonempty "$z $p: signer serves a DNSKEY RRset" "$(rrset "$sp" "$z" DNSKEY)"
				assert_nonempty "$z $p: signer serves RRSIGs over SOA" "$(rrsig_tags "$sp" "$z" SOA)"
			else
				up=$(cell_upstream "$z" "$p"); upp=$(port "$up" signer_dns)
				assert_eq "$z $p: downstream of $up serves $up's DNSKEY RRset" "$(rrset "$upp" "$z" DNSKEY)" "$(rrset "$sp" "$z" DNSKEY)"
				assert_eq "$z $p: downstream of $up serves $up's RRSIG over SOA" "$(rrsig_tags "$upp" "$z" SOA)" "$(rrsig_tags "$sp" "$z" SOA)"
			fi
		done
		if [ "$S" -ge 2 ]; then
			# every signer's DNSKEY RRset is the union of all signers' keys
			first=""
			for p in $(cell_signers "$z"); do
				ks=$(rrset "$(port "$p" signer_dns)" "$z" DNSKEY)
				if [ -z "$first" ]; then first=$ks; else assert_eq "$z: signer $p serves the same DNSKEY RRset as the first signer" "$first" "$ks"; fi
			done
		fi
	done
	echo "B. gossip: every multi-provider cell OPERATIONAL from every reporter, auditor included"
	for z in $(cells); do
		[ "$(cell_field "$z" 2)" -ge 2 ] || continue
		for p in $(cell_providers "$z"); do
			m=$(mp "$p-agent" gossip state -z "$z" 2>&1)
			if ! echo "$m" | grep -q 'REPORTER'; then FAIL "$z: $p gossip state unavailable"; note "$(echo "$m" | head -1)"; continue; fi
			bad=$(echo "$m" | grep -E 'NEEDED|UNKNOWN|KNOWN|INTRODUCED|DEGRADED|INTERRUPTED|ERROR|\?' | head -2)
			assert_empty "$z: $p reporter sees every peer OPERATIONAL" "$bad"
		done
		m=$(mp aud gossip state -z "$z" 2>&1)
		bad=$(echo "$m" | grep -E 'NEEDED|UNKNOWN|KNOWN|INTRODUCED|DEGRADED|INTERRUPTED|ERROR|\?' | head -2)
		if echo "$m" | grep -q 'REPORTER'; then assert_empty "$z: auditor sees the group OPERATIONAL" "$bad"; else FAIL "$z: auditor gossip state unavailable"; note "$(echo "$m" | head -1)"; fi
	done
}

# ---------------------------------------------------------------- NS scenarios
# ns_target <provider> <n> : an NS name under the provider's own suffix
ns_target() { echo "ns$2.$1.rig.test."; }

# served_everywhere <zone> <expected-NS-rrset> : every provider of the zone
# serves exactly that NS RRset (the observation the NS scenarios wait on)
# (sh has no local variables: helpers must not reuse a caller's loop
# variable -- "p" belongs to the scenario loops)
served_everywhere() {
	for se_p in $(cell_providers "$1"); do
		[ "$(served "$se_p" "$1" NS)" = "$2" ] || return 1
	done
	return 0
}

scenario_ns_add_del() {
	echo "C. NS add/delete under the provider's own suffix"
	for z in $(cells); do
		nsmgmt=$(cell_nsmgmt "$z")
		before=$(served "$(cell_providers "$z" | cut -d' ' -f1)" "$z" NS)
		for p in $(cell_providers "$z"); do
			rr="$z 300 IN NS $(ns_target "$p" 2)"
			out=$(mp "$p-agent" zone addrr -z "$z" --rr "$rr" 2>&1); rc=$?
			if [ "$nsmgmt" = agent ]; then
				assert_eq "$z $p: addrr own NS accepted by the API" 0 "$rc"
				want=$(printf '%s\n%s %s %s\n' "$before" "$z" "NS" "$(ns_target "$p" 2)" | sort)
				if wait_until "$OP_TIMEOUT" served_everywhere "$z" "$want"; then PASS "$z $p: added NS served by every provider"
				else FAIL "$z $p: added NS not served everywhere within ${OP_TIMEOUT}s"
					for q in $(cell_providers "$z"); do note "$q serves: $(served "$q" "$z" NS | tr '\n' '|')"; done; fi
				sde=$(mp "$p-agent" zone edits list --zone "$z" 2>/dev/null)
				assert_has "$z $p: SDE lists the NS from $p" "$(ns_target "$p" 2)" "$sde"
				assert_lacks "$z $p: SDE shows no REJECTED for it" "REJECTED" "$(echo "$sde" | grep -A3 "$(ns_target "$p" 2)")"
				# delete it again
				out=$(mp "$p-agent" zone delrr -z "$z" --rr "$rr" 2>&1); rc=$?
				assert_eq "$z $p: delrr own NS accepted by the API" 0 "$rc"
				if wait_until "$OP_TIMEOUT" served_everywhere "$z" "$before"; then PASS "$z $p: deleted NS gone from every provider"
				else FAIL "$z $p: deleted NS still served somewhere after ${OP_TIMEOUT}s"
					for q in $(cell_providers "$z"); do note "$q serves: $(served "$q" "$z" NS | tr '\n' '|')"; done; fi
			else
				assert_eq "$z $p: addrr NS refused by the API (nsmgmt=owner)" 1 "$([ "$rc" -ne 0 ] && echo 1 || echo 0)"
				assert_has "$z $p: refusal names nsmgmt" "nsmgmt" "$out"
				sleep 3
				assert_eq "$z $p: served NS RRset unchanged (nsmgmt=owner)" "$before" "$(served "$p" "$z" NS)"
			fi
		done
	done
}

# ---------------------------------------------------------------- foreign / shared NS
scenario_ns_foreign() {
	echo "D. NS whose target belongs to another provider; deleting another provider's NS"
	for z in $(cells); do
		[ "$(cell_nsmgmt "$z")" = agent ] || continue
		[ "$(cell_field "$z" 2)" -ge 2 ] || continue
		set -- $(cell_providers "$z"); actor=$1; victim=$2
		before=$(served "$actor" "$z" NS)
		# delete an NS the owner published (not contributed by the actor)
		theirs=$(echo "$before" | grep "ns1.$victim.rig.test." | awk '{print $3}')
		out=$(mp "$actor-agent" zone delrr -z "$z" --rr "$z 300 IN NS $theirs" 2>&1); rc=$?
		assert_eq "$z $actor: delrr of $victim's NS refused (not owned by this agent)" 1 "$([ "$rc" -ne 0 ] && echo 1 || echo 0)"
		assert_has "$z $actor: refusal says not owned" "not owned" "$out"
		# add an NS under the other provider's suffix: no gate exists today
		# (design doc §10 F2); the rig records the served outcome
		foreign="$z 300 IN NS $(ns_target "$victim" 3)"
		out=$(mp "$actor-agent" zone addrr -z "$z" --rr "$foreign" 2>&1); rc=$?
		note "$z $actor: addrr NS under $victim's suffix -> API rc=$rc"
		sleep "$((OP_TIMEOUT / 6))"
		for q in $(cell_providers "$z"); do
			if served "$q" "$z" NS | grep -q "$(ns_target "$victim" 3)"; then FAIL "$z: $q serves $actor's NS under $victim's suffix (expected red until a suffix rule exists)"
			else PASS "$z: $q does not serve $actor's NS under $victim's suffix"; fi
		done
		[ "$rc" -eq 0 ] && mp "$actor-agent" zone delrr -z "$z" --rr "$foreign" >/dev/null 2>&1
		wait_until "$OP_TIMEOUT" served_everywhere "$z" "$before" || note "$z: NS RRset did not return to baseline"
	done
}

# ---------------------------------------------------------------- DNSKEY by non-signer
scenario_dnskey_gate() {
	echo "E. DNSKEY contributions by a non-signer are refused at the API"
	fake="$1"
	for z in $(cells); do
		for p in $(cell_providers "$z"); do
			is_signer "$z" "$p" && continue
			out=$(mp "$p-agent" zone addrr -z "$z" --rr "$z 300 IN DNSKEY 256 3 15 $fake" 2>&1); rc=$?
			assert_eq "$z $p: non-signer addrr DNSKEY refused" 1 "$([ "$rc" -ne 0 ] && echo 1 || echo 0)"
			assert_has "$z $p: refusal names the edit policy" "not allowed" "$out"
		done
	done
}

verify_all() {
	need_seeded
	pass=0; fail=0
	verify_static
	scenario_ns_add_del
	scenario_ns_foreign
	scenario_dnskey_gate "bpBab9QZnVpFGFZoBh5sCSUVbEKEVeXrOqTiUUl54CY="
	echo
	echo "$pass passed, $fail failed"
	[ "$fail" = 0 ]
}

scenario() {
	need_seeded
	pass=0; fail=0
	case "$1" in
		static)  verify_static ;;
		ns)      scenario_ns_add_del ;;
		foreign) scenario_ns_foreign ;;
		dnskey)  scenario_dnskey_gate "bpBab9QZnVpFGFZoBh5sCSUVbEKEVeXrOqTiUUl54CY=" ;;
		*) echo "scenarios: static ns foreign dnskey" >&2; exit 2 ;;
	esac
	echo; echo "$pass passed, $fail failed"; [ "$fail" = 0 ]
}
