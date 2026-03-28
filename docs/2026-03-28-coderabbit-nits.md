# CodeRabbit Review Nits — tdns-mp

Date: 2026-03-28

Findings from automated CodeRabbit review of the big-bang-audit-1
PR. Each finding is categorized as Fix Now, Defer, or Disagree.

---

## Fix Now

### 1. Empty signer identity produces "." — DONE

- **File**: `v2/main_init.go:413-417`
- **Description**: `dns.Fqdn("")` returns `"."` when
  `mp.Signer.Identity` is empty. This gets used as `SignerID` in
  the transport config, causing incorrect peer routing.
- **Fix**: Guard `dns.Fqdn()` with non-empty check.

### 2. Infra beat error not recorded in peer state — DONE

- **File**: `v2/hsync_infra_beat.go:79-92`
- **Description**: Error path returns without updating
  `DnsDetails.LatestError`, so infra peers look healthy even when
  every beat is failing.
- **Fix**: Record error in `DnsDetails.LatestError` before
  returning on failure. Also handle NACK/nil response.

### 3. Combiner key load swallows errors + wrong ID — DONE

- **File**: `v2/main_init.go:540-549`
- **Description**: Both `os.ReadFile` and `ParsePublicKey` errors
  are silently swallowed. Key is registered under hardcoded
  `"combiner"` instead of `mp.Combiner.Identity`.
- **Fix**: Return errors. Use `dns.Fqdn(mp.Combiner.Identity)` as
  peer key ID.

### 4. HSYNC identity comparison lacks normalization — DONE

- **File**: `v2/agent_authorization.go:129-133`
- **Description**: `isInHSYNC` and `isInHSYNCAnyZone` compare
  HSYNC3 identities as raw strings without `dns.Fqdn()`. Fails if
  identities have different casing or trailing dots.
  `isAuthorizedPeer` is correct (already uses `dns.Fqdn`).
- **Fix**: Apply `dns.Fqdn()` to both sides in HSYNC comparisons.

### 5. CN comparison lacks trailing-dot normalization — DONE

- **File**: `v2/agent_setup.go:518-520`
- **Description**: `cert.Subject.CommonName` (no trailing dot)
  compared to `agent.Identity` (FQDN with trailing dot). Always
  mismatches for valid certificates.
- **Fix**: Normalize both sides before comparing.

### 6. JWK curve hardcoded to P-256 — DONE

- **File**: `v2/agent_setup.go:448-449`
- **Description**: `jwk.Crv` is parsed from JSON but ignored.
  Always uses `elliptic.P256()`. P-384 and P-521 keys would
  produce invalid public keys.
- **Fix**: Map `jwk.Crv` to the correct elliptic curve.

### 7. MergeGossip stores incoming pointers directly — DONE

- **File**: `v2/gossip.go:56-60`
- **Description**: Incoming `*MemberState` pointers stored directly
  into `gst.States`. External mutation or sender reuse affects
  stored state. Compare to election state which correctly copies
  (line 67-68).
- **Fix**: Deep-copy MemberState before storing.

### 8. Provider group duplicate identities — DONE

- **File**: `v2/provider_groups.go:97-105`
- **Description**: Duplicate HSYNC3 records for the same identity
  cause inconsistent group keys
  (`"a,a,b"` vs `"a,b"`) and mismatched hashes across peers.
- **Fix**: Deduplicate identities after collecting, before sorting.

---

## Defer

### 9. Only first DSYNC address tried

- **File**: `v2/parentsync_utils.go:49-55`
- **Description**: `c.Exchange` only tries
  `dsyncTarget.Addresses[0]`. If unreachable, fails immediately
  without trying other addresses.
- **Why defer**: Only matters with multi-homed parents (rare in
  current deployment).

### 10. Leader election OnFirstLoad missing on reload

- **File**: `v2/start_agent.go:43-45`
- **Description**: `PostParseZonesHook` only calls
  `RegisterMPRefreshCallbacks`, not the leader election OnFirstLoad
  loop. Zones added via reload don't get leader election callbacks.
- **Why defer**: Same pattern as the combiner OnFirstLoad fix
  (already done). Needs a `RegisterAgentOnFirstLoad` method.
  Not urgent — adding zones at runtime is uncommon.

### 11. combinerAgent registered as operational before checks

- **File**: `v2/combiner_peer.go:53-88`
- **Description**: `ar.S.Set` is called before key/transport/ping
  validation. If validation fails, agent remains in registry as
  operational.
- **Why defer**: Checks happen immediately after registration with
  no real window for misuse. Reordering is cleaner but not urgent.

### 12. Replace operation doesn't mark omitted RRs for deletion

- **File**: `v2/syncheddataengine.go:901-910`
- **Description**: "replace" only marks new records as pending adds.
  Old records not in the new set should be marked for removal but
  aren't.
- **Why defer**: "replace" is currently only used for DNSKEY where
  the combiner handles full replace semantics. Not an active bug.

### 13. MarkRRsPending before enqueue success known

- **File**: `v2/syncheddataengine.go:209-247`
- **Description**: RRs marked pending with distID before
  `EnqueueForCombiner`/`EnqueueForZoneAgents` succeed. Failed
  enqueues leave orphaned pending state.
- **Why defer**: Failed enqueues are extremely rare (transport
  buffer full) and logged. Reordering is cleaner but not urgent.

### 14. Peer state synced from ApiDetails only

- **File**: `v2/hsync_transport.go:1372-1378`
- **Description**: `SyncPeerFromAgent` syncs peer state only from
  `ApiDetails`, ignoring `DnsDetails`. DNS-only peers get wrong
  state.
- **Why defer**: `SyncPeerFromAgent` is a compatibility shim, not
  the primary state path. Transport peer state is managed
  independently.

### 15. Multi-agent sync error accumulation incomplete

- **File**: `v2/hsyncengine.go:751-760`
- **Description**: Later successful peer overwrites earlier NACK in
  `resp.Error`/`resp.ErrorMsg`. The `errstrs` array accumulates
  network errors but not application-level NACKs.
- **Why defer**: Partial — errors ARE accumulated for network
  failures. Application NACKs are rare and logged per-peer.

### 16. Hello beat updates ApiDetails only

- **File**: `v2/hsync_hello.go:226-231`
- **Description**: After `SendBeatWithFallback`, unconditionally
  sets `ApiDetails.State = Operational` regardless of which
  transport actually succeeded.
- **Why defer**: Same root cause as beat transport fix. Needs
  `SendBeatWithFallback` to return which transport was used.

---

## Disagree — No Fix Needed

### 17. start_combiner.go OnFirstLoad missing on reload

- **File**: `v2/start_combiner.go:82-85`
- **Why**: Already fixed by `RegisterCombinerOnFirstLoad` +
  `PostParseZonesHook`. The reviewer saw stale code.

### 18. AuthorizedPeers missing defaulted infra peer IDs

- **File**: `v2/main_init.go:438-449`
- **Why**: Code already includes combiner+signer identities when
  configured. No evidence of other missing peer types.

### 19. refreshRegistered misses new ZoneData on reload

- **File**: `v2/config.go:24-27`
- **Why**: `ParseZones` reuses existing `*ZoneData` on reload (not
  new allocation). The name-based key is correct.

### 20. agent_discovery verification-key fails non-JWK

- **File**: `v2/agent_discovery.go:241-275`
- **Why**: Legacy KEY discovery is a dead code path. All agents use
  JWK. No regression.

### 21. agent_policy local branch skips Operations

- **File**: `v2/agent_policy.go:136-220`
- **Why**: Operations ARE validated in earlier section (lines
  73-104). The local branch handles the legacy `RRs` path.

### 22. Nil cache check blocks non-cache commands

- **File**: `v2/apihandler_agent_distrib.go:83-88`
- **Why**: `query-agents` returns before the check. All remaining
  commands need cache. Not a current bug.

### 23. MessageType string conversion is raw byte

- **File**: `v2/hsyncengine.go:965-972`
- **Why**: `msg.MessageType` is already a string-like type.
  `string()` conversion is correct Go.

### 24. GetGroupForZone called before RecomputeGroups

- **File**: `v2/agent_utils.go:961-978`
- **Why**: Intentional — defer election with current groups, then
  recompute. Ordering is correct.

### 25. SVCB discovery triggered when UriRR is nil

- **File**: `v2/agent_utils.go:250-289`
- **Why**: Logic is correct — fetch SVCB when we lack both URI and
  cached addresses. Comment is misleading but harmless.

### 26. CleanupZoneRelationships is a stub

- **File**: `v2/agent_utils.go:809-812`
- **Why**: Known TODO (audit issue 4.5). Not a regression from the
  extraction. Tracked separately.

### 27. InsecureSkipVerify in API ping

- **File**: `v2/apihandler_agent.go:72-76`
- **Why**: Agent-to-agent ping within the trusted MP group. SIG(0)
  provides the actual authentication. TLSA verification integration
  doesn't exist yet.

### 28. APIbeat/APImsg no identity validation

- **File**: `v2/apihandler_agent.go:1548-1557`
- **Why**: Beats arrive over TLS with mutual cert auth. Identity in
  message is advisory. Adding EvaluateHello to every heartbeat
  would add latency for minimal security gain.

### 29. RR snapshot only copies slice header

- **File**: `v2/hsync_utils.go:917-923`
- **Why**: Code is correct. Copying the slice is sufficient — dns.RR
  objects are effectively immutable after creation.
