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

# ---------------------------------------------------------------- signatures
# zone_validator: the first of dnssec-verify (BIND) and ldns-verify-zone on
# PATH; both check every RRSIG in a zone file against the DNSKEY RRset in
# the same file, which is what F asks.
zone_validator() {
	if command -v dnssec-verify >/dev/null 2>&1; then echo dnssec-verify
	elif command -v ldns-verify-zone >/dev/null 2>&1; then echo ldns-verify-zone
	fi
}
# axfr <port> <zone> <file> : the zone as the server transfers it; 0 when
# the transfer returned records
axfr() {
	$DIG +norec +noall +answer +onesoa +time=5 +tries=1 @127.0.0.1 -p "$1" "$2" AXFR 2>/dev/null > "$3"
	[ -s "$3" ] && grep -q 'SOA' "$3"
}
# validate_zone <zone> <file> : 0 when every RRSIG in the file validates
# against the DNSKEY RRset in the same file; 2 when no validator is on PATH.
# The validator's own words are left in $RIG/.validate.out for the note.
validate_zone() {
	case "$(zone_validator)" in
		dnssec-verify)    dnssec-verify -o "$1" "$2" > "$RIG/.validate.out" 2>&1 ;;
		ldns-verify-zone) ldns-verify-zone "$2" > "$RIG/.validate.out" 2>&1 ;;
		*) return 2 ;;
	esac
}
# signer_validates <zone> <provider> : the F check for one signer (sh has no
# local variables; sv_ prefixes keep the caller's loop variables intact)
signer_validates() {
	sv_port=$(port "$2" signer_dns); sv_f="$RIG/.axfr.$2.$$"
	if ! axfr "$sv_port" "$1" "$sv_f"; then FAIL "$1 $2: AXFR from the signer on port $sv_port"; rm -f "$sv_f"; return 1; fi
	validate_zone "$1" "$sv_f"; sv_rc=$?
	case "$sv_rc" in
		0) PASS "$1 $2: every RRSIG in the signer's AXFR validates against the DNSKEY RRset in it" ;;
		2) FAIL "$1 $2: no zone validator on PATH (dnssec-verify or ldns-verify-zone)" ;;
		*) FAIL "$1 $2: the signer's AXFR does not validate"; note "$(head -3 "$RIG/.validate.out" | tr '\n' '|')" ;;
	esac
	rm -f "$sv_f"; [ "$sv_rc" = 0 ]
}
scenario_signatures() {
	echo "F. signatures validate: every RRSIG in a signer's AXFR verifies against the DNSKEY RRset in the same transfer"
	for z in $(cells); do
		[ "$(cell_field "$z" 3)" -ge 1 ] || continue
		for p in $(cell_signers "$z"); do signer_validates "$z" "$p"; done
	done
}

# ---------------------------------------------------------------- DNSKEY roll
# dnskey_union <zone> : the union of every signer's served DNSKEY RRset
dnskey_union() { for du_p in $(cell_signers "$1"); do served "$du_p" "$1" DNSKEY; done | sort -u; }
# signers_serve_union <zone> : every signer serves that union
signers_serve_union() {
	ssu_u=$(dnskey_union "$1")
	for ssu_p in $(cell_signers "$1"); do [ "$(served "$ssu_p" "$1" DNSKEY)" = "$ssu_u" ] || return 1; done
	return 0
}
# has_standby_zsk <zone> <provider> : the signer's keystore lists a standby
# ZSK (flags 256) for the zone -- what a roll promotes. The key-state worker
# stages one, the peers confirm it, and it becomes standby after the
# propagation delay; the match on the listing is deliberately loose.
has_standby_zsk() { mp "$2-signer" keystore dnssec list 2>/dev/null | grep -F "$1" | grep -i standby | grep -qw 256; }
# rolled_sig <zone> <provider> <old tags> : www's A is signed by another key now
rolled_sig() { [ "$(rrsig_tags "$(port "$2" signer_dns)" "www.$1" A)" != "$3" ]; }
scenario_dnskey_roll() {
	echo "G. ZSK roll on a two-signer cell: the new key served and signing, the union of DNSKEYs on every signer"
	for z in $(cells); do
		[ "$(cell_field "$z" 3)" -ge 2 ] || continue
		[ "$(cell_nsmgmt "$z")" = agent ] || continue
		set -- $(cell_signers "$z"); roller=$1
		before_keys=$(served "$roller" "$z" DNSKEY)
		before_sig=$(rrsig_tags "$(port "$roller" signer_dns)" "www.$z" A)
		if ! wait_until "$OP_TIMEOUT" has_standby_zsk "$z" "$roller"; then
			FAIL "$z $roller: no standby ZSK to roll to within ${OP_TIMEOUT}s"
			note "$(mp "$roller-signer" keystore dnssec list 2>&1 | grep -F "$z" | tr '\n' '|')"
			continue
		fi
		out=$(mp "$roller-signer" keystore dnssec rollover -z "$z" --keytype ZSK 2>&1); rc=$?
		assert_eq "$z $roller: ZSK rollover accepted by the API" 0 "$rc"
		[ "$rc" = 0 ] || { note "$out"; continue; }
		if wait_until "$OP_TIMEOUT" rolled_sig "$z" "$roller" "$before_sig"; then PASS "$z $roller: www A signed by the new ZSK"
		else FAIL "$z $roller: www A still signed by the old ZSK after ${OP_TIMEOUT}s"; fi
		if [ "$(served "$roller" "$z" DNSKEY)" != "$before_keys" ]; then PASS "$z $roller: the served DNSKEY RRset changed with the roll"
		else FAIL "$z $roller: the served DNSKEY RRset is unchanged after the roll"; fi
		signer_validates "$z" "$roller"
		if wait_until "$OP_TIMEOUT" signers_serve_union "$z"; then PASS "$z: every signer serves the union of the signers' DNSKEYs after the roll"
		else FAIL "$z: the signers disagree on the DNSKEY RRset ${OP_TIMEOUT}s after the roll"
			for q in $(cell_signers "$z"); do note "$q serves: $(served "$q" "$z" DNSKEY | tr '\n' '|')"; done; fi
		for p in $(cell_signers "$z"); do [ "$p" = "$roller" ] || signer_validates "$z" "$p"; done
	done
}

verify_all() {
	need_seeded
	pass=0; fail=0
	verify_static
	scenario_ns_add_del
	scenario_ns_foreign
	scenario_dnskey_gate "bpBab9QZnVpFGFZoBh5sCSUVbEKEVeXrOqTiUUl54CY="
	scenario_signatures
	scenario_dnskey_roll
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
		sigs)    scenario_signatures ;;
		roll)    scenario_dnskey_roll ;;
		*) echo "scenarios: static ns foreign dnskey sigs roll" >&2; exit 2 ;;
	esac
	echo; echo "$pass passed, $fail failed"; [ "$fail" = 0 ]
}
