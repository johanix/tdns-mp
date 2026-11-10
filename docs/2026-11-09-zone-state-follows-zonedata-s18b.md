# Zone state follows the ZoneData: the S18b part (tdns-mp #396)

2026-11-09. Refs #396.

The general rule and the main-branch fix are in
`2026-11-09-zone-state-follows-zonedata.md`. A zone's tdns-mp state
belongs to the ZoneData it was made for. When tdns holds another ZoneData
under the zone's name, the zone starts over as it does at a start.

This note covers what that means for the signer's role turn on the #211
stack (plan S18b).

## What RA1 hit

1. A reload removed a provider's zone from its signer's config, and a
   later reload added it back with its DNSSEC policy.
2. `signerRoleTurn` takes its wrapper from `Zones.Get`, which handed out
   the removed zone's wrapper.
3. `StartSigning` therefore ran on the removed ZoneData. That zone's
   stanza had named no policy, so `StartSigning` failed with "names no
   DNSSEC policy", although the live ZoneData had the policy.

Main's fix makes `Zones.Get` return the live ZoneData. With it, the turn
acts on the zone that was added back:

- The key machine's take on the old ZoneData no longer counts, so the turn
  does not wait for the machine's first keys (`firstKeysThere`).
- `StartSigning` runs on the live ZoneData.
- The engine takes the zone again once the zone's policy is bound
  (`tookRole`).

## The role book

`signerRoleBook` filed two things by zone name:

- `provisional`: the agent's word that it has no copy.
- `said`: the last failure logged.

A stale `provisional` entry does more harm than a stale log line.
`signerAgentHasNoCopy` returns early while the entry is set, so the agent's
next word never reaches the rebuilt wrapper.

Both entries now record the ZoneData they were said for.
`agentHasNoCopy(mpzd)` holds only for that ZoneData. A failure is logged
again for a new ZoneData. The signer's reload hook prunes the entries of
ZoneData that tdns no longer holds.

Nothing is lost by dropping `provisional`. The agent sends its no-copy word
with every inventory that says the zone is withheld while the agent has
nothing published (`mp_s5_leader_sync.go`). The word therefore comes back
and acts on the live wrapper.

## Kept by name on purpose

Each of these describes the zone or the world outside it, not the
ZoneData. A restart keeps or rebuilds each of them the same way:

| state | why it stays |
|---|---|
| `actingHeld` | Persisted. The re-added zone's first load reads it, as after a restart. |
| `Withheld` | Lives on `tdns.ZoneData`, so it is already per ZoneData. |
| `servedKeysBook` | Records what the zone's nameservers and caches served. |
| `signerAddBook`, `transferBook`, `keyPollBook` | The agent's view of the parent, the nameservers and published keys. |
| `handoverTracker` | Learned from the parts' confirmations and inventories. |
| `pending` | Holds names only; the turn looks the zone up itself. |

## Tests (`signer_role_readded_test.go`)

- `TestASignerZoneAddedBackStartsSigningItsLiveZoneData` covers the RA1
  path with tdns's real `StartSigning`:
  - the zone the signer started with names no policy and is withheld;
  - the zone is removed and added back with its policy, without
    invalidating the cache by hand;
  - the agent hands the zone its keys' step;
  - the role turn signs the live ZoneData once, and serves a signed SOA;
  - the removed ZoneData is never switched on.

  On the stack without main's fix, this test fails with RA1's error.
- `TestTheAgentsNoCopyWordIsAskedAgainForAZoneAddedBack`:
  - after the re-add, the zone waits for its agent's word instead of acting
    on the word given about the removed ZoneData;
  - the next word reaches the live wrapper, and the zone starts on the live
    ZoneData.
- `TestTheRoleBookPruneKeepsOnlyLiveZoneData`: the reload's prune drops the
  entries of a removed zone and of a replaced ZoneData, and keeps the live
  zone's entries.
