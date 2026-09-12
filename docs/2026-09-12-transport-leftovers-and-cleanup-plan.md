# Transport redesign: leftovers, warts, and a cleanup plan

Date: 2026-09-12, revision 3. Status: PROPOSAL, awaiting the operator's
decision that it is in force. Nothing has been implemented.

Revision history:

- r1 (PR #52, `665e66d`): initial inventory and plan.
- r2 (`e4a1bac`): a dated amendment after the external review (verdict
  "request changes"): three holds and six residuals, all accepted.
- r3 (this text): the amendment folded into the body after the re-review
  (verdict "approve"), so that every step reads correctly on its own. The
  r2 amendment section is gone; its content is in the steps it corrected.

Code examined, in detached read-only worktrees under `tdns-project/fbreak/`:
tdns-mp `b8bba004` (tip of PR #50), tdns-transport `c619f2a` (main), tdns
`217335e0` (tip of PR #622). Every claim was checked against those commits;
file names are relative to the repository's `v2/`.

Companion documents: the block map in
`2026-09-12-mp-functional-breakdown.md` (what lives where), and the
transport redesign plan `2026-08-24-transport-redesign-consolidated-plan-v4.md`,
whose 2026-09-12 amendment reconciles its own text and maps each of its
remaining items to a step here.

Scope: the transport layer and its seams with tdns-mp and tdns. Not in
scope: F0 (the tdns re-pin), the COSE and HPKE work itself (step 7 prepares
the ground for it), tdns's multi-provider residue beyond the one item that
blocks a transport cleanup, and the three v4 leftovers named in section 6
as out of scope.

## 1. Inventory

Two kinds of item. **L** items are leftovers the v4 plan already carries;
they are listed so the two documents agree on what is open. **W** items are
warts the plan does not carry.

### 1.1 Leftovers the v4 plan carries

| Id | Item | Plan | State on 2026-09-12 | Here |
|---|---|---|---|---|
| L1 | Rename the beat's `Gossip` field to `AppData`; the only declared wire break. Five tag sites per the 09-09 correction. | F1 | Open. | Out of scope (section 6). |
| L2 | Docs and comment cleanup: stale Status lines on the 2026-05-29 plan and the 05-08 bite documents, the `.md~` file, the presentation finish (`peer list -v`, the `Agent.State` DTO shadow), the `hsync-peer-status` stub endpoint. | F2 | Partly done: `init.go`'s guide now describes `RouteToCallback`; the "until A3d.4" and `AgentRegistry.mu` comments are gone. The rest is open. | Step 8. |
| L3 | Transport owns the whole chunk chain: the query-mode serve side (`chunk_store.go`, `chunk_query_handler.go`, the signer's `fetchChunkPayloadViaQuery`, the `ChunkPayloadStore` config and wiring) and the unlabelled query-mode payload, which falls back to the byte sniff. | F2b | Open. `fetchChunkViaQuery` returns `EnvelopeUnknown` and names F2b. | Step 4. |
| L4 | Exported surface of the transport package, and the "no MP-coupled imports" check. | F3 | Open. The package exports 64 types and 166 functions and methods; the plan's target was under 30 types. | Step 8. |
| L5 | D1 follow-up: a discovery-versus-beat race test. (The other half of the original item, unlocked reads of `agent.ApiMethod` and `DnsMethod` on the send path, was fixed on 2026-09-10 in the PR #34 review round: `SendHelloWithFallback` and `SendBeatWithFallback` read under `agent.Mu.RLock`, and `hsync/hello.go` and `hsync/discovery.go` do the same.) | D1 | Open, unscheduled. | Out of scope (section 6). |
| L6 | The `Agent.State` DTO shadow retires with the DTO rework. | D2 leftover 3 | Open, tied to L2. | Step 8. |
| L7 | Items from the PR #34 review round that the plan does not list: `peer reset` does not reset an established mechanism's transport state; the `hsync.Registry` zone index (END.4); the E5 finding, declined. Source: that review round, kept in the operator's review directory outside the repository by design. | none | Open. | Out of scope (section 6). |
| L8 | The v4 plan's own text: the 2026-09-10 deviations block said the envelope label was not added, while "Current state" said it landed (`97a1c8a`); the same block carried the unlocked-reads note; "main untouched, no PRs" was stale. | none | **Done**: the v4 amendment of 2026-09-12 reconciles all three and names C4b. | Done. |

### 1.2 The receive path: two generations superimposed

The receive path for a NOTIFY(CHUNK) is `ChunkNotifyHandler.RouteViaRouter`
(`transport/chunk_notify_handler.go`). It authorizes the sender before any
crypto, fetches and decrypts the payload, has the application parse it,
authorizes again with the zone, and only then calls `Router.Route`. The
router's middleware chain was the original home of the first three of those
steps and is still installed.

| Id | Wart | Evidence |
|---|---|---|
| W1 | Authorization is evaluated three times per message: pre-crypto with an empty zone, post-parse with the zone, and again in `NewAuthorizationMiddleware`. | `chunk_notify_handler.go` (the H8 and M20 checks); `router_init.go:63` installs the middleware because tdns-mp sets `RouterConfig.TransportManager` (`hsync_transport.go:457`). Review finding C-4 (2026-05-30) asked C5 to decide; C5's text in v2, v3 and v4 says the app-verb middleware is removed. Not executed, not in the 09-10 deviation list. The 09-10 deviation also changed the premise: both callback checks stayed in `RouteViaRouter`, so the middleware has no remaining job for any verb. |
| W2 | `NewSignatureMiddleware` is installed on every role and always short-circuits, because `RouteViaRouter` has already decrypted and sets `ChunkCrypted=false, SignatureValid=true`. `NewDecryptionMiddleware` has no caller at all. | `router_init.go:74`; `crypto_middleware.go:171`. Consequences: `RouterConfig.AllowUnencrypted` and `TriggerDiscoveryOnMissingKey` do nothing on the DNS path; `Router.Describe` lists a chain that does not do what it says; the `MessageContext` fields `ChunkSigned`, `ChunkCrypted`, `SignatureValid`, `SignatureReason`, `Authorized`, `AuthReason`, `AuthorizedVia` exist for these middleware and are read by nothing but a debug line in `HandlePing`. No plan version mentions these middleware. |
| W3 | Three parsers know the MP field conventions (`MessageType`/`type`, `OriginatorID`/`MyIdentity`/`sender_id`, `Zone`/`zone`, `nonce`, `Zones`): tdns-mp's `parseAppPayload` (installed as `ParseApp` on every role), transport's `parsePayload` (the default when `ParseApp` is nil) and transport's `ParseIncomingMessage`, which `HandleHello`, `HandleBeat` and three tdns-mp verb handlers still call as a re-parse fallback. | `mp_chunk_parse.go:23`; `chunk_notify_handler.go:271`; `handlers.go:222` with callers at `handlers.go:145,173` and `mp_verb_handlers.go:63,106,462`. The 2026-04-30 split document marked `parsePayload` "moves to MP"; C5a kept it as the default. |
| W4 | `IncomingMessage` carries both `Type` and `TypeToken`. C6 said `TypeToken` becomes the only one; transport still routes on `Type`. | `handler.go:17`; `chunk_notify_handler.go:534`; `handlers.go:83`. |
| W5 | Dead transport declarations: `transport.DnsNotifyRequest` (a mirror of the tdns type, no user); `RouterConfig.ResponseWriter` and `RequestMsg` (no reader); `SecurityEventLogger` and `DefaultSecurityLogger` (used only by the middleware of W1 and W2). | `chunk_notify_handler.go:115`; `router_init.go`; `crypto_middleware.go:15-33`. |
| W6 | The contract between transport and application inside the router is a bag of string keys on `ctx.Data`: `incoming_message`, `secure_wrapper`, `response`, `response_rcode`, `response_peer_id`, `local_id`, `transport`, `on_confirmation_received`, `gossip_for_peer`, `zone`, `wire_envelope`, `unhandled_message_type`. | `chunk_notify_handler.go:540-570`, `handlers.go`, `mp_verb_handlers.go`. Known to the plan (C3 "inline-ACK path") and preserved deliberately; nothing types it. |
| W7 | The byte sniff `IsPayloadEncrypted` survives as the fallback for `EnvelopeUnknown` and inside `UnwrapIncoming` and `UnwrapIncomingFromPeer`. It cannot tell a COSE payload from a JOSE one. | `crypto.go:354,417,493`; `envelope.go:75`. Goes away with L3. |

### 1.3 Transport-own verbs and the tdns coupling

| Id | Wart | Evidence |
|---|---|---|
| W8 | The wire structs of transport's own verbs live in tdns. `dns.go` builds hello, beat and ping from `core.AgentHelloPost`, `core.AgentBeatPost`, `core.AgentPingPost` and the `core.AgentMsg*` strings, while the same three shapes exist a second time in transport as the parse structs `DnsHelloPayload`, `DnsBeatPayload`, `DnsPingPayload`. C4 kept "wire/crypto types" in `core`; these are not wire types, they are the MP API structs reused. This is what keeps `core/messages.go` in tdns, and it is the v4 leftover C4b. | `dns.go:229,290,343`; `dns.go:808-935`; tdns `core/messages.go`. |
| W9 | `transport/doc.go` describes the Sync and Relocate operations, a "Phase 3 stub" DNS transport and a four-state peer machine, none of which is current. | `doc.go`. Belongs to L2. |

### 1.4 The API mechanism is split across the two repositories

| Id | Wart | Evidence |
|---|---|---|
| W10 | The HTTPS mechanism's send side is in transport (`APITransport`, sync family only) but its receive side is entirely in tdns-mp: the endpoints `/hello`, `/beat`, `/ping`, `/sync/ping`, `/msg` and five separate `switch amp.MessageType` dispatches. Nothing on that path goes through the router, the verb table or the transport's confirmation semantics; the TLSA middleware is the whole gate. "One verb table per role" (C3) is true for DNS only. | `apirouter_sync.go:21-55`; `apihandler_agent.go:524,836,1210,1283,1402`. |
| W11 | tdns-mp keeps a second API send path next to `APITransport`: `Agent.SendApiHello`, `SendApiBeat`, `SendApiMsg`, `AgentRegistry.sendRfiToAgent`, with six production callers, including the election broadcast. | `hsync_hello.go`, `hsync_beat.go`, `hsyncengine.go:477,600,740`, `hsync_utils.go:454,495`, `parentsync_leader.go:1196`, `apihandler_agent.go:437`. |

The plan's target architecture says transport speaks the opaque-message
vocabulary for both mechanisms. In fact it does so for DNS, and the fleet is
DNS-only, which is why this has not hurt.

### 1.5 The HSYNC engine's mirrors

| Id | Wart | Evidence |
|---|---|---|
| W12 | Three peer-state enumerations: `transport.PeerState`, `hsync.PeerState` (adds LEGACY and renames INTRODUCING) with a conversion function, and `tdnsmp.AgentState`. The hsync package imports transport, so the mirror is not an import-cycle necessity. | `hsync/types.go:26`, `hsync/transport_peer.go:55`, `agent_structs.go:18`. |
| W13 | Two copies of the gossip types, `hsync.GossipMessage` and friends versus `tdnsmp.GossipMessage` and friends, with three converters between them. | `hsync/gossip.go`, `gossip_types.go`, `hsync_agent_gossip.go:64,91`, `auditor_engine.go:343`. |
| W14 | `hsync/dispatch.go` routes by message class, but `isElectionMsg` and `isKeyStateMsg` return false unconditionally, so `SetElectionHandler` and `SetKeyStateHandler` are never reached. The agent wires all three handlers to the same function. | `hsync/dispatch.go:48-54`; `hsync_data_engine.go:63-69`. |
| W15 | Two beat loops: the engine's `sendHeartbeats` for agent peers and `AgentRegistry.StartInfraBeatLoop` for the combiner and signer. | `hsync/beat.go`, `hsync_infra_beat.go`. Possibly by design, since infra peers are not in the hsync registry; listed so the decision is explicit. |

### 1.6 The crypto layer, as it stands before COSE and HPKE

| Id | Wart | Evidence |
|---|---|---|
| W16 | `PayloadCrypto` is not backend-agnostic. It composes JWE then JWS by hand, splits the JWS compact serialization itself to re-verify, holds exactly one backend, and never calls the `EncryptAndSign` and `DecryptAndVerify` that both backends implement. It also adds an outer standard-base64 layer that the backends do not: the wire carries `base64.StdEncoding(JWS(JWE(payload)))`, while `jose.Backend.EncryptAndSign` returns the raw JWS compact serialization and `DecryptAndVerify` parses raw JWS. `splitJWS` and `base64URLDecode` exist twice. | `crypto.go:231-330`; `crypto/jose/backend.go:472-525`; `distrib/transport.go:171,188`. |
| W17 | The CHUNK Format byte is set to `core.FormatJWT` whenever crypto is on, in both the send path and the response path, instead of being asked from the wrapper. | `dns.go:366,541,584`; `handlers.go:301`. |
| W18 | Every role in tdns-mp constructs `jose.NewBackend()` directly and type-asserts `*jose.Backend` to reach `PublicFromPrivate`, which is not on the `crypto.Backend` interface. Four copies of the same key-loading code. | `main_init.go:763`, `combiner_crypto.go:32`, `signer_transport.go:22`, `agent_setup.go:435`; also `keys_cmd.go:59`. |
| W19 | The HPKE backend is a stub that misdescribes itself: multi-recipient encryption encrypts for the first recipient only and returns raw ciphertext; signing goes through go-jose ES256 with a separate P-256 key; nothing calls it. The `hpke/` package (EDNS0 ephemeral option, KMREQ names) has no caller either, and `hpke/test_inline.go` exports a test helper from non-test code. | `crypto/hpke/backend.go:166-320`; `hpke/*.go`. |
| W20 | Of the `distrib` package only `PrepareDistributionChunks`, `SplitIntoCHUNKs` and `ReassembleCHUNKs` are used. `DistributionTracker`, `DistributionStore` with its SQL schema, the JWT manifest, `TransportEncoder` and the confirmation types have no caller in any of the three repositories. | grep over tdns-transport, tdns-mp, tdns. |

### 1.7 tdns residue and tdns-mp housekeeping

| Id | Wart | Evidence |
|---|---|---|
| W21 | tdns hosts `core/messages.go` (the verb strings and the `Agent*Post` structs), `OptMultiProvider`, `ZoneMPExtension` and one `OptMultiProvider` check in the KSK rollover. The two key-state strings `mpdist` and `foreign` are deliberate (PR #622 T-S1). | tdns `core/messages.go`, `structs.go`, `enums.go`, `parseoptions.go`, `ksk_rollover_automated.go:1699`. |
| W22 | `deadcode_combiner_db_schema.go` is in the tree under `//go:build ignore` with a "DEAD CODE" header. | tdns-mp `v2/`. |
| W23 | `gossip_types.go` and `mp_msg_types.go` still say "Copied from tdns/v2/...". | file headers. |

## 2. What the cleanup must not change

These are the v4 plan's binding rules, restated because every step below was
checked against them.

1. The pre-crypto sender authorization stays in transport, before the fetch
   and the decryption. The zone authorization stays before the DNS response
   is sent, so an unauthorized message is REFUSED rather than acknowledged
   and dropped. The two callback calls are not merged across the seam.
2. Transport's vocabulary is hello, beat, ping, confirm, chunk, plus one
   opaque carrier. Transport does not read inside the application payload.
3. Two peer stores joined by `PeerID`; `Agent` embeds `*hsync.Peer`; no
   deep-copy bridges. LEGACY is the one MP overlay transport never sees.
4. Every step is wire-compatible (INVARIANT under the probe discipline)
   unless declared as a wire break. The golden tests are regenerated only in
   a step that declares the break, and a gate that must prove invariance is
   written and green before the change it guards, never in the same commit.
5. Lock order, the writer-path audit rule, one step per commit per
   repository, operator deploy and verify at each checkpoint.

The alternation between transport and application on the receive path is
the consequence of rules 1 and 2, not a wart, and it stays.

## 3. Proposed cleanup, in order

Each step is one commit per repository. "Gates" are the tests that must stay
green; where a test asserts the thing being removed, the step says so.

### Step 1: one receive pipeline (tdns-transport; INVARIANT)

Make `RouteViaRouter` the documented and only pipeline: authorize sender,
fetch, check envelope, decrypt, parse, authorize zone, route, respond.

- Delete `NewAuthorizationMiddleware`, `NewSignatureMiddleware`,
  `NewDecryptionMiddleware`, `CryptoMiddlewareConfig`, `SecurityEvent`,
  `SecurityEventLogger`, `DefaultSecurityLogger`.
- `RouterConfig` keeps `PeerRegistry`, `VerboseStats`, `Confirmations`;
  loses `TransportManager`, `PayloadCrypto`, `TriggerDiscoveryOnMissingKey`,
  `AllowUnencrypted`, `ResponseWriter`, `RequestMsg`.
- `MessageContext` loses `ChunkSigned`, `ChunkCrypted`, `SignatureValid`,
  `SignatureReason`, `Authorized`, `AuthReason`, `AuthorizedVia`. The debug
  line in `HandlePing` is adjusted.
- Delete `transport.DnsNotifyRequest`.
- Add typed accessors for the `ctx.Data` keys that cross the seam
  (`IncomingOf(ctx)`, `SetResponse(ctx, payload, rcode)`, and so on) and
  use them from both repositories. The keys and their values are unchanged,
  so this is an API addition, not a wire change.
- Rewrite `doc.go`.

Resolves W1, W2, W5, W6 (as far as typing goes), W9.

Behaviour. The production DNS path, `RouteViaRouter` followed by
`Router.Route`, is unchanged: the three middleware either passed through
or re-evaluated a decision `RouteViaRouter` had already made with identical
inputs. A caller that invokes `Router.Route` directly is changed:
`dns_message_router_test.go` and `cmd/transport-exercise` do, and after this
step a router is a verb table with statistics, logging, the response wrapper
and the callback, nothing more; a consumer that wants authorization or
decryption goes through `RouteViaRouter`. `AllowUnencrypted` and
`TriggerDiscoveryOnMissingKey` were already inert on the DNS path; deleting
them removes a false promise, which is visible to anyone who believed the
flags worked.

Gates: `TestTransportDispatch_PerVerb` (it drives the real chain, which
becomes stats, logging, callback); the goldens, untouched; the transport
router tests, rewritten where they asserted the middleware;
`crypto_middleware_test.go` is deleted with its subject;
`transport-exercise`'s middleware check is rewritten against a
user-supplied middleware.

Size: small but not mechanical. The typed accessors are used from both
repositories.

### Step 2: one parser, one verb field (tdns-transport and tdns-mp; INVARIANT)

- `ParseApp` becomes required; `NewChunkNotifyHandler` refuses a nil one.
  Delete transport's `parsePayload` and `ParseIncomingMessage`. `HandleHello`
  and `HandleBeat` use the parsed message the pipeline already stored; the
  three tdns-mp verb handlers drop their re-parse fallback and fail if the
  stored message is missing, which cannot happen on the production path.
- `transport-exercise` supplies a ten-line parser that reads
  `MessageType` and `MyIdentity`, which documents the minimum a consumer
  must provide.
- Collapse `IncomingMessage.Type` into `TypeToken`; `RouteViaRouter` and
  `HandlePing` read `Token()`. Check the tests that construct
  `IncomingMessage` or read `Type` (`app_message_test.go` and the dispatch
  test) in the same commit.

Resolves W3, W4. Wire: identical bytes; the parsing rules are pinned by
`mp_chunk_parse_test.go` and the receive goldens.

Size: small but not mechanical; making `ParseApp` required touches every
role's wiring.

### Step 3, C4b: transport-own verb structs move home (tdns-transport; INVARIANT)

This is the v4 leftover C4b.

- Define `HelloPost`, `BeatPost`, `PingPost` in transport with the exact
  JSON tags of the `core.Agent*Post` structs, and merge each with its
  `Dns*Payload` parse struct so hello, beat and ping each have one wire
  struct used for both directions. Drop the `core.AgentMsg*` strings in
  favour of transport's own constants.
- `dns.go` then imports `core` only for `CHUNK`, `TypeCHUNK` and the Format
  constants.
- Until `core/messages.go` moves (section 4), the tags are owned by
  transport and the tdns copies are read-only mirrors; the send and receive
  goldens are the drift detector and must be green before and after.

Resolves W8 on the transport side. tdns is not touched.

### Step 4, F2b: the labelled query-mode chain (tdns-transport and tdns-mp)

Depends only on step 1 and can proceed without step 5. Query mode is not
the live fleet path, but the step still gets a rig run.

- Carrier decision, proposed: the manifest's metadata gets an `envelope`
  field, written by the sender's `PrepareDistributionChunks` from the
  wrapper's label. The manifest is JSON metadata already, and
  `CreateManifestMetadata` takes extra fields, so this is one line each
  side. A receiver that finds no field keeps the sniff for one release.
- Move `chunk_store.go`, `chunk_query_handler.go` and the signer's
  `fetchChunkPayloadViaQuery` into transport; `DNSTransport` owns serving
  and fetching; `chunk_mode` and `chunk_query_endpoint` become transport
  configuration; the `FetchChunkQuery` callback and the `Transport == nil`
  branch in the handler go away.
- Second commit, one release later: delete `IsPayloadEncrypted`,
  `UnwrapIncoming`, `UnwrapIncomingFromPeer`; `EnvelopeUnknown` becomes
  FORMERR.

Resolves L3, W7. Wire: the metadata field is additive, INVARIANT; the
second commit is an EXPLAINED DELTA for a query-mode sender that never
learned to label, which after the first commit is none.

### Step 5: the API mechanism through the same pipeline (mostly tdns-mp; INVARIANT)

This is the largest step and the one that needs an operator decision
first: either the API mechanism is a peer of DNS, or it is legacy and
`doc.go` should say so. If it is a peer, two commits in this order:

1. Goldens that pin today's HTTP bodies for `/hello`, `/beat`, `/ping`,
   `/sync/ping` and `/msg`. None exist. Green before anything moves.
2. The reroute. The five endpoints build a `MessageContext` from the HTTP
   body, with `PeerID` from the client certificate and the TLSA middleware
   as the pre-crypto authorization, and call `Router.Route` under a
   response middleware that writes JSON instead of a DNS response. The verb
   table then governs both mechanisms, and the API request and response
   types live once. Retire `SendApiHello`, `SendApiBeat`, `SendApiMsg` and
   `sendRfiToAgent` in favour of `TransportManager.Send` and `SendAll` at
   the six call sites.

Rig gate: the election broadcast through `SendAll`, on the rig, before the
step is called done.

Resolves W10, W11. Wire: the HTTP bodies are unchanged, proven by the
goldens of the first commit.

### Step 6: the engine's mirrors (tdns-mp; INVARIANT)

Independent of steps 1 to 3 and can run in parallel with them.

- Move the gossip types to package `hsync` as the single definition;
  `tdnsmp` aliases them; delete the three converters. The JSON tags are the
  wire, and they do not change.
- Delete the two false predicates and the election and key-state handler
  slots in `hsync/dispatch.go`; one `SetHandler`. Safe because the
  predicates are unconditionally false and the agent wires all three
  slots to the same function.
- Replace `hsync.PeerState` with `transport.PeerState` plus a derived
  `IsLegacy()` on the hsync peer. LEGACY is already derived, not stored:
  `agent_view.go` applies it to an established peer with zero
  participations, and `IsLegacy()` restates that. `tdnsmp.AgentState`
  retires with the DTO rework of L2 and L6. The CLI's state strings are the
  visible surface; keep them identical.
- Decide W15 and write the decision down; no code change proposed.

Resolves W12, W13, W14.

### Step 7: an honest crypto seam, before COSE and HPKE (both repos; INVARIANT)

This step does not add COSE or resurrect HPKE. It makes the seam that both
will use truthful, so that work is additive.

What is on the wire today, and stays: `base64.StdEncoding(JWS(JWE(payload)))`.
The outer standard-base64 layer is added by `PayloadCrypto`, not by the
backend: `jose.Backend.EncryptAndSign` returns the raw JWS compact
serialization and its `DecryptAndVerify` parses raw JWS, while the live
`DecryptAndVerifyPayload` base64-decodes first. So "call the backend's
`EncryptAndSign` and drop the wrapper's base64" would change the bytes.
Whether the wrap lives in `PayloadCrypto` or becomes part of what a
backend's `Envelope` contract promises is an implementation choice, but it
must be paired: a backend that wraps on encrypt and not on decrypt is
wrong, and the gate below is what catches it.

Gate, written and green before the refactor. JWE encryption is randomised
(content key and IV), so byte identity cannot be asserted on freshly
produced ciphertext. The INVARIANT gate is therefore a cross-decrypt test
with checked-in test keys: a ciphertext captured from the current path must
decrypt through the new path, a ciphertext from the new path must decrypt
through the current path, and the produced bytes must pass a structural
check (standard base64 outside, a three-part JWS, a JWE inside with the
same protected headers). `mechanism_crypto_test.go` round-trips only and is
not sufficient on its own.

The change:

- `crypto.Backend` gains `Envelope() uint8` (the label the backend
  produces) and `PublicFromPrivate`. `PayloadCrypto` calls the backend's
  `EncryptAndSign` and `DecryptAndVerify` and deletes its own JWS surgery;
  `splitJWS` and `base64URLDecode` disappear from both packages. `dns.go`
  and `handlers.go` take the Format byte from the wrapper.
- One `newPayloadCrypto(conf, role)` in tdns-mp replaces the four copies;
  the backend comes from `crypto.GetBackend(conf.CryptoBackend)` with the
  default `jose`. The `long_term_jose_*` configuration keys stay until the
  COSE work renames them.
- Delete `crypto/hpke`, `hpke/` and the unused half of `distrib` from main.
  Git history keeps them, and the COSE-HPKE design will reshape the HPKE
  backend anyway; carrying a stub that imports go-jose and describes a
  "Phase 4" that never came is a liability, not a head start.

Resolves W16, W17, W18, W19, W20. Wire: identical, proven by the
cross-decrypt gate and the receive goldens.

### Step 8: F2 and F3 finish

Not a bundle at the end: each step corrects the documents and comments it
makes stale in its own commit. What is left for this step:

- F2 residue, now concrete: L2's items, L6; `agent_utils.go:94`; W22, W23;
  `init.go`'s guide re-read after steps 1 and 2.
- F3: count again after steps 1, 3 and 7, unexport what only tests use, and
  set a measured target instead of "under 30".
- The v4 plan already carries the 2026-09-12 amendment that maps its items
  here (L8); when a step lands, the v4 "Left" list is updated in the same
  commit.

## 4. Later work this cleanup enables, out of scope here

- Move `core/messages.go` from tdns to tdns-mp (after steps 3 and 5 nothing
  in transport needs it): a tdns change plus a re-pin, F0-class.
- An outer carrier on the wire, `{verb, scope, payload}`, so transport can
  route without the parse callback: a wire break, to ride F1's flag day or
  the HSYNCPARAM renumbering day if either happens.
- COSE and HPKE on the seam of step 7, as COSE-HPKE.
- tdns's `OptMultiProvider` and `ZoneMPExtension` residue.

## 5. Order, size and dependencies

| Step | Repos | Wire | Depends on | Hand-edited lines, rough | Whole files deleted |
|---|---|---|---|---|---|
| 1 pipeline | transport | INVARIANT | none | ~270 | ~890 (middleware and its test) |
| 2 parser and verb field | transport, mp | INVARIANT | 1 | ~160 | 0 |
| 3 verb structs (C4b) | transport | INVARIANT | 2 | ~160 | 0 |
| 4 F2b | transport, mp | INVARIANT, then one declared delta | 1 | ~330 plus ~280 moved | ~60 |
| 5 API mechanism | mp, transport | INVARIANT | 1, 2, operator decision | ~850 | 0 |
| 6 engine mirrors | mp | INVARIANT | none | ~230 | 0 |
| 7 crypto seam | transport, mp | INVARIANT | 1, the cross-decrypt gate | ~470 | ~4,150 (HPKE, unused distrib, their tests) |
| 8 F2, F3 | all | none | the rest | ~210 | ~60 |

The line counts are an estimate with a wide margin (half to double); step 5
is the least certain and becomes a documentation note if the API mechanism
is declared legacy. Steps 1 to 3 are the first cut and remove the parts of
the receive path that look like a design problem without being one. Step 7
is the prerequisite for the COSE and HPKE work and comes before it. Steps 4
and 5 change where code lives and deserve a rig run each.

Execution order:

1. Steps 1, 2, 3, in that order.
2. Step 6, whenever.
3. Step 4, when query mode is next touched.
4. Step 7, only with the cross-decrypt gate in place first.
5. Step 5, only after the operator's answer on the API mechanism, and only
   after its first commit has today's bodies golden.

Every step: one commit per repository on a branch, the v4 probe discipline
(observer node first, then the fleet, then a heal pass and a full probe),
goldens regenerated only on a declared break.

## 6. Left alone, and out of scope

Left alone on purpose:

- The callback structure of the receive path (section 2).
- The two peer maps and the embed.
- The `ctx.Data` keys as the carrier between transport and application
  (step 1 types the access, not the carrier).
- The two beat loops, pending the W15 decision.
- The `Confirm` method on the `Transport` interface next to `SendApp`:
  confirm is transport-own and stays typed.

Out of scope of this cleanup, staying on the v4 "Left" list until someone
adds them as named steps:

- L1, F1: the `Gossip` to `AppData` rename, the declared wire break.
- L5: the discovery-versus-beat race test.
- L7: `peer reset` and an established mechanism's transport state; the
  `hsync.Registry` zone index (END.4). Source: the PR #34 review round, in
  the operator's review directory outside the repository.

## 7. Review record

- 2026-09-12, external review of r1: "request changes". Inventory
  confirmed; steps 1 to 3 the right first cut. Holds: step 7's wire claim
  was wrong (the outer base64 wrap is on the wire); step 1's "no behaviour
  change" was too strong (direct `Router.Route` callers); L5 was half
  stale (the unlocked reads were already fixed). Residuals: name step 3 as
  C4b; declare L1 and L7 out of scope or schedule them; reconcile the v4
  text. All accepted; r2 recorded them as an amendment and the v4 plan got
  its own.
- 2026-09-12, re-review of r2: "approve", ready to implement from step 1
  once the proposal is in force. Non-blocking residuals: the split between
  body and amendment (this revision removes it), the step 7 wrap must be
  paired on both directions (now stated in the step), and the L5 row (now
  corrected).
