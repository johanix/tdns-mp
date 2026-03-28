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

---

## Batch 2

### Fix Now

### 30. RemoveRemoteAgent mutates agent.Zones without lock — DONE

- **File**: `v2/agent_utils.go:726-731`
- **Description**: `delete(agent.Zones, zonename)` without holding
  `agent.Mu`. Races with `sharedZonesForAgent` which holds
  `RLock`.
- **Fix**: Add `agent.Mu.Lock()` around the delete. Also removed
  redundant lock+delete at line 946-950 (caller did the same
  thing before calling `RemoveRemoteAgent`).

### 31. CheckState only inspects ApiDetails — DONE

- **File**: `v2/hsync_beat.go:168-199`
- **Description**: `CheckState` uses only `ApiDetails` timestamps
  for beat health. DNS-only agents get falsely degraded when API
  transport is idle.
- **Fix**: Use best-of-both transports: pick the most recent
  received/sent beat timestamp and largest beat interval from
  either transport.

### 32. sendHelloToAgent reads agent.Zones without lock — DONE

- **File**: `v2/hsync_hello.go:165-177`
- **Description**: Iterates `agent.Zones` without holding
  `agent.Mu`. Same race as `sharedZonesForAgent` (fixed earlier).
- **Fix**: Add `agent.Mu.RLock()` around the zone map access.

### 33. Redundant lock+delete before RemoveRemoteAgent — DONE

- **File**: `v2/agent_utils.go:946-951`
- **Description**: Lines 947-949 lock and delete `agent.Zones`,
  then call `RemoveRemoteAgent` which does the same. Redundant.
- **Fix**: Removed inline lock+delete. `RemoveRemoteAgent` now
  handles locking internally (fix 30).

### Defer

### 34. CleanupZoneRelationships stub

- **File**: `v2/agent_utils.go:809-812`
- **Description**: Function is a no-op placeholder. Suggested
  implementation: remove zone from RemoteAgents, delete from all
  agents' Zones maps, call RecomputeSharedZonesAndSyncState.
- **Why defer**: Known TODO (audit issue 4.5). Feature, not bug.

### 35. LocateAgent unbounded goroutines

- **File**: `v2/agent_utils.go:179-431`
- **Description**: Spawns goroutines for URI/SVCB/KEY/TLSA lookups
  that race to update the same agent.
- **Why disagree**: Fan-out is bounded (4 goroutines per agent).
  All writes hold `agent.Mu`. Adding WaitGroup/errgroup is
  over-engineering.

### Disagree

### 36. Transaction handler lock scope too wide

- **File**: `v2/apihandler_transaction.go:85-99`
- **Why**: Lock is held for microseconds over a tiny map (0-5
  entries). `formatDuration` is trivial. Premature optimization.

### 37. Nil checks for ApiDetails/DnsDetails under RLock

- **File**: `v2/hsync_beat.go:68-71`
- **Why**: `ApiDetails` and `DnsDetails` are initialized in agent
  constructors and never set to nil. Guards against impossible
  scenario.

---

## Batch 3

### Fix Now

### 38. MergeGossip shallow copy leaves PeerStates/Zones shared — DONE

- **File**: `v2/gossip.go:56-62`
- **Description**: `remoteCopy := *remote` copies the struct but
  `PeerStates` (map) and `Zones` (slice) still share backing
  data with the incoming message.
- **Fix**: Added `deepCopyMemberState` helper. Used in both
  MergeGossip and BuildGossipForPeer export path.

### 39. groupHash[:8] can panic on short hash — DONE

- **File**: `v2/gossip.go:264-274` (and other sites)
- **Description**: Multiple `groupHash[:8]` calls in log statements
  panic if hash is shorter than 8 chars.
- **Fix**: Added `shortHash()` helper. Replaced all occurrences.

### 40. BuildGossipForPeer lock ordering deadlock — DONE

- **File**: `v2/gossip.go:96-108`
- **Description**: Takes `gst.mu` then `pgm.mu`.
  `RefreshLocalStates` takes `pgm.mu` then `gst.mu` (via
  `UpdateLocalState`). Classic AB/BA deadlock.
- **Fix**: Snapshot pgm data under pgm.mu, release it, then take
  gst.mu. Consistent ordering: pgm first, gst second.

### 41. BuildGossipForPeer exports internal MemberState pointers — DONE

- **File**: `v2/gossip.go:134-139`
- **Description**: `msg.Members[id] = state` shares internal
  pointers in outgoing messages.
- **Fix**: Deep-copy via `deepCopyMemberState` on export.

### 42. Infra beat error paths missing LatestErrorTime — DONE

- **File**: `v2/hsync_infra_beat.go:83-92`
- **Description**: `LatestError` set but `LatestErrorTime` not
  updated, so timestamps are stale.
- **Fix**: Added `LatestErrorTime = time.Now()` in both error paths.

### 43. Infra beat state read without lock — DONE

- **File**: `v2/hsync_infra_beat.go:54-56`
- **Description**: Reads `DnsDetails.State` and `ApiDetails.State`
  without holding `agent.Mu`. Data race.
- **Fix**: Added `a.Mu.RLock()` / `a.Mu.RUnlock()` around reads.

### 44. initMPAgent mutates shared mp.AuthorizedPeers — DONE

- **File**: `v2/main_init.go:349-353`
- **Description**: `mp.AuthorizedPeers = append(...)` modifies the
  viper-parsed config struct. The `AuthorizedPeers` closure
  already includes combiner/signer dynamically.
- **Fix**: Removed the `append`. Combiner ID is already included
  via the closure at line 445.

### 45. FQDN normalization computed inside loop (nitpick) — DONE

- **File**: `v2/agent_authorization.go:153-203`
- **Description**: `dns.Fqdn(tm.LocalID)` and `dns.Fqdn(senderID)`
  computed on each loop iteration instead of once.
- **Fix**: Hoisted above the loop.
