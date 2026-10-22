# Peer discovery and DNSSEC: implementation plan

The design is `2026-10-21-peer-discovery-dnssec-status-design.md`. This plan
holds what is dated: what existed, what changed, where, and what is left.
Issue: #260 (the agreed design is in its comments).

## What existed, and what was new

Existed and reused:

- The resolver's verdict on every answer (`ImrResponse.ValidationState`),
  and `require-dnssec-validation` enforced on every discovery lookup
  (`requireValidated` in tdns-transport).
- The cache's lifetime rules: smallest TTL, and an entry held Secure no
  longer than its signatures (tdns `entry_lifetime.go`).
- The TLSA checker, which reads the TLSA set through the cache before every
  HTTPS request, and a TLSA withdrawal that makes the API mechanism NEEDED.
- The hsync engine's discovery retrier for NEEDED peers.

Wrong before this change:

- The four record lookups checked for records before validation, so a
  denial that was not validated read as "no records".
- `discoverAgent` dropped every lookup error but the last: "no contact
  endpoints found (no API or DNS URI records)".
- A refused DNS URI was logged at Debug as optional.
- Nothing kept the verdict of the URI, SVCB, JWK or KEY on the peer.
- Discovery data never expired: a known peer was not looked up again unless
  a mechanism still needed discovery, or a peer kept refusing us.

## Changes

### tdns (#947)

- `ImrResponse.Expiration`: the expiration of the cache entry that holds the
  answer or the denial, read after validation. Set on every return of
  `ImrQuery`/`ImrQueryFresh` and on the recursor's cache hits.
- `CommandResponse.Warnings`, printed first by `daemon status`, and
  `Config.DnssecValidationOff()`; `daemon status` warns while validation is
  off.

### tdns-transport (#37)

- `discovery_status.go`: `ChainStatus`, `DiscoveryFailure`,
  `DiscoveryLookup`, `DiscoveryError`, `DiscoveryStatus` (with
  `MechanismChain` and `MechanismReason`), `Peer.DiscoveryStatus()`.
- `imr.go`: one `discoveryQuery` for every record lookup. It judges
  validation before records, and returns the lookup. The TLSA answer
  carries its verdict and expiry.
- `discovery.go`: the lookups go on `DiscoveryResult.Lookups` and the
  peer's status; a mechanism refused for want of validation is demoted
  (`DiscoveryResult.refused`, `Peer.demoteMechanism`); the failure is a
  `*DiscoveryError`.
- `tlsa.go`: the checker's answers replace the TLSA lookup on the peer.
- `discovery_refresh.go`: `StartDiscoveryRefresh`, the loop that looks a
  peer up again when its data expires.
- The import boundary admits `tdns/v2/cache`.

### tdns-mp (#263)

- `PeerInfo` carries `DNSSEC`, `DiscoveryReason` and `DiscoveryExpires` per
  mechanism (`setDiscovery`); the peer-list response carries them, and
  `dnssec_validation_off` at the top.
- Gossip: `MemberState.DnssecValidationOff` and `MemberState.PeerChains`
  (both omitted when empty). The table sets our own row's from
  `SetDnssecValidationOff` (agent and auditor init) and from the transport
  peers (`RefreshLocalStates`, `AgentRegistry.peerChain`). The copies copy
  them, and the matrix rows return them.
- CLI: `chainMark`, `printDnssecNotes`; `peer list` (compact and `-v`) and
  `gossip state` (`printGossipMatrix`, split out of `runGossipZoneState`).
- The agent and the auditor start the transport's refresh loop, and warn at
  start and hourly while validation is off
  (`warnWhileDnssecValidationOff`).
- Pins: tdns at #947's head and tdns-transport at #37's head, in every
  module. To be re-pinned to the merge commits.

## Steps

| step | what | state |
|------|------|-------|
| 1 | tdns #947 | open |
| 2 | tdns-transport #37, pinned to #947's head | open |
| 3 | tdns-mp, pinned to both heads | open |
| 4 | merge #947; re-pin #37 to its merge commit; merge #37 | waiting |
| 5 | re-pin tdns-mp to both merge commits; merge | waiting |
| 6 | rig run, below | not run |

## Rig cases

Go tests cover each rule. Before merging, the rig should run these on a
fleet, since this is a security path:

1. Validation required, a peer's identity zone under an unsigned
   delegation: `peer list` shows the peer `NEEDED(-)` with
   `answer insecure, DNSSEC validation required`, at the default log level.
2. Validation off, the same zone: the peer is `OPERATIONAL(-)` in
   `peer list` and in every member's `gossip state`. The warning names the
   node, `daemon status` starts with the OFF line, and the log repeats it.
3. Validation required, the chain secure, then broken while the peer is
   OPERATIONAL (the DS removed from the parent): once the TTLs run out, the
   peer goes to `NEEDED(-)`. It comes back when the DS is restored.
4. A control run on a secure fleet: no marks, no legend, no warning, no
   Discovery notes.

## Open

- The auditor's web matrix (`gossip_matrix.html`) shows no marks yet.
- A validated withdrawal of a URI does not take the mechanism out of use.
  It is a separate question from #260.
- The refresh loop runs one peer at a time with a 30 s bound per peer. A
  large fleet with short TTLs may need it to run in parallel.
