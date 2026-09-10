# chunk_notify_handler.go: Split Cut-Line Spec

Date: 2026-04-30
Status: SPEC — pre-work for Phase 4 of the transport interface
        redesign (chunk_notify_handler split).

Companion to:
[2026-04-15-transport-interface-redesign.md](./2026-04-15-transport-interface-redesign.md)
[2026-04-25-transport-refactor-early-bites.md](./2026-04-25-transport-refactor-early-bites.md)
[2026-04-30-transport-refactor-semi-easy-bites.md](./2026-04-30-transport-refactor-semi-easy-bites.md)
(Bite B)

## Purpose

[chunk_notify_handler.go](../../tdns-transport/v2/transport/chunk_notify_handler.go)
is ~580 lines and conflates several concerns:

- QNAME parsing (extract distribution ID + sender)
- CHUNK reassembly (EDNS0 inline, or query-mode multi-chunk fetch)
- Pre-crypto authz (sender is a known peer at all)
- Decryption (SecureWrapper, with discovery trigger on missing key)
- JSON parsing (extract MessageType, OriginatorID, Zone, Nonce)
- Zone-peer authz (post-crypto, scope-aware)
- Router dispatch (middleware + handler invocation)

Phase 4 splits this into a generic CHUNK reassembly handler that
stays in transport, and an MP-specific message dispatcher that moves
to MP. The split is non-trivial because crypto, parse, and authz are
interleaved.

This document specifies the cut line. Once approved, Phase 4 becomes
a mechanical extraction. Closes parent-plan open item **I**.

## Sequence diagram of the current `RouteViaRouter` flow

The 12 numbered steps below trace one CHUNK NOTIFY through
[RouteViaRouter](../../tdns-transport/v2/transport/chunk_notify_handler.go#L409)
end to end. Each is annotated with where it lives today and where it
goes after the split: **T** (stays in transport) or **M** (moves to
MP).

| # | Step | Lives at | Disposition |
|---|---|---|---|
| 1 | Capture source addr from `dns.ResponseWriter` | [L415-418](../../tdns-transport/v2/transport/chunk_notify_handler.go#L415) | **T** |
| 2 | Parse QNAME → `(distributionID, senderHint)` | [L423](../../tdns-transport/v2/transport/chunk_notify_handler.go#L423) → [extractDistributionIDAndSender](../../tdns-transport/v2/transport/chunk_notify_handler.go#L121) | **T** (transport-layer naming convention) |
| 3 | Pre-crypto authz: `IsPeerAuthorized(senderHint, "")` | [L434-448](../../tdns-transport/v2/transport/chunk_notify_handler.go#L434) | **T** (DoS-mitigation, pre-crypto, scope-free; protects the expensive crypto step) |
| 4 | Try EDNS0 CHUNK extraction | [L451](../../tdns-transport/v2/transport/chunk_notify_handler.go#L451) → [extractChunkPayload](../../tdns-transport/v2/transport/chunk_notify_handler.go#L143) | **T** |
| 5 | Fall back to query-mode reassembly (manifest-first, fetch chunks 1..N) | [L454](../../tdns-transport/v2/transport/chunk_notify_handler.go#L454) → [fetchChunkViaQuery](../../tdns-transport/v2/transport/chunk_notify_handler.go#L191) | **T** |
| 6 | Decrypt via `SecureWrapper.UnwrapIncomingFromPeer(payload, senderHint)` | [L464-486](../../tdns-transport/v2/transport/chunk_notify_handler.go#L464) | **T** (the wrapper is owned by transport; key discovery callback `OnPeerDiscoveryNeeded` is application-supplied but invoked here) |
| 7 | Parse JSON payload → `IncomingMessage` (MessageType, OriginatorID, MyIdentity, SenderID, Zone, Nonce) | [L489](../../tdns-transport/v2/transport/chunk_notify_handler.go#L489) → [parsePayload](../../tdns-transport/v2/transport/chunk_notify_handler.go#L255) | **M** (knows MP-specific message-shape conventions: legacy `type`/`zone` aliases, `MyIdentity` vs `OriginatorID` per-msg-type rules) |
| 8 | Build `MessageContext` (PeerID, ChunkPayload, transport refs, callback hooks) | [L502-529](../../tdns-transport/v2/transport/chunk_notify_handler.go#L502) | **M** (knows which callbacks to wire — gossip, confirmation, secure_wrapper) |
| 9 | Extract zone for authz (Zone field directly, or `Zones[0]` from beat payload) | [L530-546](../../tdns-transport/v2/transport/chunk_notify_handler.go#L530) | **M** (beat-payload re-unmarshal knows the MP `AgentBeatPost` shape) |
| 10 | Post-crypto zone-peer authz: `IsPeerAuthorized(senderHint, zone)` | [L548-565](../../tdns-transport/v2/transport/chunk_notify_handler.go#L548) | **M** (zone-peer relationship is an MP concept; HSYNC check) |
| 11 | Route through `Router.Route(ctx, msgType)` wrapped in `SendResponseMiddleware` | [L567-577](../../tdns-transport/v2/transport/chunk_notify_handler.go#L567) | **M** (router is registered with MP-specific handlers; SendResponseMiddleware encrypts using SecureWrapper which is transport-owned, but the orchestration sits in MP) |
| 12 | DNS response (NOERROR / FORMERR / REFUSED / SERVFAIL) | sprinkled across all of the above via `sendResponse` | **mixed** — see "Cut-line and DNS response handling" below |

## The cut line

**Between step 6 (decryption) and step 7 (JSON parse).**

After step 6, transport hands MP a tuple of:

- `ctx context.Context` — request context
- `sender string` — pre-crypto QNAME-extracted sender FQDN
- `distributionID string` — pre-crypto QNAME-extracted distribution ID
- `payload []byte` — decrypted plaintext (or original payload if no
  SecureWrapper)
- `req *dns.Msg` — original request (needed for response)
- `w dns.ResponseWriter` — for sending the DNS response

MP owns parse, zone-authz, ctx-build, and router dispatch. MP is also
responsible for sending the DNS response.

## Callback contract

```go
// DecryptedChunkHandler is invoked by ChunkNotifyHandler after CHUNK
// reassembly, pre-crypto authz, and decryption have succeeded.
//
// The callback owns DNS response delivery via w. ChunkNotifyHandler
// will NOT send a response after the callback returns; if the
// callback returns an error, ChunkNotifyHandler sends SERVFAIL on
// its behalf only as a last-resort fallback.
//
// payload is the decrypted plaintext (or the original payload if
// no SecureWrapper is configured). sender is the QNAME-extracted
// sender FQDN — pre-crypto, but already authorized at the
// known-peer level by step 3.
type DecryptedChunkHandler func(
    ctx context.Context,
    sender string,
    distributionID string,
    payload []byte,
    req *dns.Msg,
    w dns.ResponseWriter,
) error
```

The handler is registered on `ChunkNotifyHandler` at construction
time alongside the other application-supplied callbacks
(`OnPeerDiscoveryNeeded`, `OnConfirmationReceived`, etc.).

### When does the callback fire?

After **all** of the following have completed:

1. QNAME parsed successfully (FORMERR if not)
2. Pre-crypto authz passed (REFUSED if not — callback never fires)
3. Payload obtained via EDNS0 OR query-mode reassembly (FORMERR if
   both fail)
4. Decryption succeeded (REFUSED for forgery; missing-key triggers
   discovery and the message is dropped — callback never fires in
   that path)

If any of those fails, transport sends the DNS response itself and
the callback never fires. The callback is invoked exactly once per
incoming NOTIFY that survives the transport-layer pipeline.

### Error semantics

- Returning `nil` → transport assumes the callback handled the DNS
  response; transport does nothing further.
- Returning `error` → transport logs the error and sends SERVFAIL as
  a safety net (the callback should always send its own response,
  even on error; the SERVFAIL fallback exists only to guard against
  a callback that crashes before sending).

This is asymmetric with the pre-callback failures: pre-callback
failures consume the response slot themselves and return `nil` to
the upstream NOTIFY handler. The callback is expected to do the
same.

## Authorization placement decision

**Pre-crypto authz (step 3): stays in transport.**
- Reasoning: it's a DoS-mitigation gate. Without it, every NOTIFY
  forces an expensive `UnwrapIncomingFromPeer` call. Transport owns
  the crypto and therefore the cost — it owns the gate that
  protects it.
- Scope: `IsPeerAuthorized(senderHint, "")`. The empty zone signals
  "is this sender known at all?". The callback is supplied by the
  application but invoked at the transport boundary.
- Not negotiable: the gate must run before decryption.

**Post-crypto zone-peer authz (step 10): moves to MP.**
- Reasoning: the zone-peer relationship is an MP concept (HSYNC
  records, ProviderGroups, ZoneRelation). Transport has no business
  knowing what a "zone" means.
- Scope: `IsPeerAuthorized(senderHint, zone)`. After parse, the
  zone is in hand and MP can apply zone-specific policy.
- Side effect: MP becomes the sole owner of the
  `IsPeerAuthorized(senderHint, zone)` callback. The pre-crypto
  case (zone="") still goes through the same callback, but the
  callback's MP implementation can short-circuit on zone=="" to
  return only the known-peer check.

This split satisfies parent-plan open item **I** with a clear
rationale: cost-of-protection determines location, not "where the
authz callback is implemented."

## State that crosses the cut

Beyond what's in the callback signature: **nothing.**

Verified by walking the post-decryption code (steps 7–12) and
listing every field read on `h *ChunkNotifyHandler`:

| Field read after decryption | Used for | Cross-cut state? |
|---|---|---|
| `h.LocalID` | `msgCtx.Data["local_id"]` | no — passed via callback registration on the MP side |
| `h.Transport` | `msgCtx.Data["transport"]` | no — MP can supply its own ref |
| `h.SecureWrapper` | `msgCtx.Data["secure_wrapper"]` | no — same |
| `h.OnConfirmationReceived` | `msgCtx.Data["on_confirmation_received"]` | no — moves to MP entirely |
| `h.GossipForPeer` | `msgCtx.Data["gossip_for_peer"]` | no — moves to MP entirely |
| `h.IsPeerAuthorized` | post-crypto zone authz | the callback registration stays at the MP boundary |
| `h.Router` | `Router.Route(ctx, msgType)` | no — the Router is constructed by MP and registered with handlers |

Every "cross-cut" item is something MP can supply directly when
constructing its own dispatcher, without transport handing it
across. The callback contract above (5 args) is sufficient.

## Cut-line and DNS response handling

The current implementation's `sendResponse` calls (FORMERR /
REFUSED / SERVFAIL paths) are scattered across both sides of the
cut. After the split:

| Failure | Where | Response |
|---|---|---|
| QNAME parse fails | step 2 (T) | FORMERR — transport sends |
| Pre-crypto authz fails | step 3 (T) | REFUSED — transport sends |
| EDNS0 absent + query-mode fails | step 5 (T) | FORMERR — transport sends |
| Decryption fails (forgery) | step 6 (T) | REFUSED — transport sends |
| Decryption fails (missing key) | step 6 (T) | drop (no response, sender retries) — transport handles |
| JSON parse fails | step 7 (M) | FORMERR — MP sends |
| Zone authz fails | step 10 (M) | REFUSED — MP sends |
| Router/handler error | step 11 (M) | SERVFAIL — MP sends |
| Successful dispatch | step 11 (M) | NOERROR (with optional confirm payload via `sendConfirmResponse`) — MP sends |

`sendConfirmResponse` (which encrypts a confirm payload and includes
it in the DNS response EDNS0 OPT) belongs on the **MP** side because
it encodes the dispatch outcome. It still uses the transport-owned
`SecureWrapper` for the encryption step — that's fine, MP holds the
ref.

The `unsolicitedCount` atomic counter (DoS metric, [L31, L86, L437,
L439, L444, L401-405](../../tdns-transport/v2/transport/chunk_notify_handler.go#L437))
stays on the transport-side handler since it's incremented inside
the pre-crypto authz step.

## Test impact

Of the seven `TestTransportBoundary_*` scenarios in
[transport_integ_test.go](../../tdns-mp/v2/transport_integ_test.go),
the ones that exercise this code path are:

| Scenario | What it asserts | Impact |
|---|---|---|
| 1 (sync delivery) | sync arrives on MsgQs.Msg via the full pipeline | needs to verify the new MP-side dispatcher fires |
| 5 (rejected sync) | sync from unauthorized peer returns REFUSED, doesn't reach MsgQs | the REFUSED happens at step 3 (T) — pre-crypto authz — so the assertion remains valid |

Scenarios 2, 3, 4, 6, 7 don't touch the chunk handler.

**Required harness changes after Phase 4:** scenario 1 may need a
small adjustment if the construction of the MP-side dispatcher
takes additional config; scenario 5 should be unchanged.

## What this spec does NOT decide

- Whether the MP-side dispatcher is a method on
  `MPTransportBridge` or a free function. Probably a method, but
  Phase 4 can choose.
- The exact name. Suggestions:
  `MPTransportBridge.HandleDecryptedChunk` (verb-symmetric with
  the transport-side hook) or
  `MPTransportBridge.DispatchIncomingMessage` (intent-symmetric
  with `Router.Route`).
- Whether `parsePayload` (currently a method on
  `*ChunkNotifyHandler` at [L255](../../tdns-transport/v2/transport/chunk_notify_handler.go#L255))
  moves verbatim to MP or gets restructured. It can move verbatim
  for the first cut; restructure later if profiling motivates.

These are Phase 4 implementation choices.

## Cumulative effect

Phase 4 reduces
[chunk_notify_handler.go](../../tdns-transport/v2/transport/chunk_notify_handler.go)
from ~580 lines to roughly 250 lines (steps 1–6 + helpers).
A new file in tdns-mp (likely `chunk_dispatcher.go`) takes the
remaining ~330 lines (steps 7–12 + parsePayload + sendConfirmResponse).
The split is:

- **transport**: generic CHUNK reassembly + decryption + DoS
  mitigation. App-agnostic.
- **MP**: message-shape parsing, zone-peer authz, router dispatch,
  confirm-response encoding. App-specific.

The transport-side surface becomes one new exported symbol
(`DecryptedChunkHandler`) and one new field on
`ChunkNotifyHandler` to register it. No wire format changes.
