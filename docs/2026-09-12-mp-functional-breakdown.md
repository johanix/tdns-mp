# Functional breakdown: tdns, tdns-transport, tdns-mp

Date: 2026-09-12.

Code examined, in detached read-only worktrees under `tdns-project/fbreak/`:

| Repository | Ref | Commit |
|---|---|---|
| tdns | tip of PR #622 (`feature/bmp-snapshot`) | `217335e0` |
| tdns-mp | tip of PR #50 (`feature/bmp-snapshot`) | `b8bba004` |
| tdns-transport | `main` | `c619f2a` (merge of `66dc80d3`, the commit tdns-mp pins) |

The focus is tdns-mp and tdns-transport. tdns appears only as the platform the
other two stand on: which of its pieces they use, and which extension points
they hook.

Two TikZ drawings accompany this document:
`2026-09-12-mp-functional-breakdown-drawings.tex` (macros in the style of the
`iis-talks` drawings; `\input` it into a deck) and
`2026-09-12-mp-functional-breakdown-standalone.tex` (compiles on its own with
`pdflatex`). Drawing 1 is the block map of section 2; drawing 2 is the path of
one message through the three repositories.

## 1. The three repositories

**tdns** is the DNS platform: authoritative engine, resolver (IMR), zone
refresh and staging, keystore and signing, the experimental RR types, the
EDNS0 options, and the registries and hooks a second binary uses to extend it.
It imports neither of the other two.

**tdns-transport** is a messaging library for agents that talk to each other
over DNS or HTTPS: crypto backends, payload wrapping, the two mechanisms, a
message router with middleware, a peer registry with discovery, a reliable
queue, and a manager that ties them together. It carries opaque application
messages and knows only its own five verbs. It imports tdns for the CHUNK/JWK
record types, the CHUNK EDNS0 option, the NOTIFY registration and the IMR.

**tdns-mp** is the multi-provider application: four roles (agent, combiner,
signer, auditor) as binaries, the application verbs and their wire payloads,
the HSYNC peer-lifecycle engine, gossip, provider groups, leader election, the
synched data engine, the combiner, the signer's key lifecycle, the auditor, the
management API, the CLI and the configuration. It imports both of the others.

Dependency direction is strictly one way:

```
tdns-mp  -->  tdns-transport  -->  tdns
tdns-mp  ------------------------> tdns
```

| Repository | Go, non-test | Go, tests | Packages that matter |
|---|---|---|---|
| tdns-transport `v2/` | 10 964 | 4 656 | transport 7 361, distrib 1 481, hpke 800, crypto/hpke 562, crypto/jose 529, crypto 231 |
| tdns-mp `v2/` | 45 350 | 4 904 | v2 (package `tdnsmp`) 33 547, cli 8 506, cli/configure 1 825, hsync 1 472 |
| tdns `v2/` | 143 102 | 85 334 | v2 root, core, edns0, cli, cache, debug, externaldb |

What each importer takes from the layer below:

| Importer | Imports | Identifiers used |
|---|---|---|
| tdns-transport | tdns `core`, `edns0`, `v2` root | `core.CHUNK`, `core.TypeCHUNK`, `core.FormatJSON`/`FormatJWT`, manifest helpers, `core.JWK`/`ValidateJWK`/`DecodeJWKToPublicKey`, `core.AgentHelloPost`/`BeatPost`/`PingPost`, `edns0.CreateChunkOption`/`ParseChunkOption` and the two option codes, `tdns.RegisterNotifyHandler`, `tdns.DnsNotifyRequest`, `tdns.Imr` |
| tdns-mp | tdns-transport `transport` (30 files), `crypto/jose` (8 files), `crypto` (4 files) | the whole transport surface; `jose.NewBackend` and `*jose.Backend` in every role's crypto init |
| tdns-mp | tdns `v2`, `core`, `cli`, `edns0`, `cache`, `algorithms` | zone data, keystore, engines, hooks, RR types, CLI scaffolding |

tdns-mp's `distrib` import is one test file. Nothing in tdns-mp or tdns imports
`tdns-transport/v2/hpke` or `crypto/hpke`.

## 2. Block map

Each row is one functional block. "Repo" is where the code lives today; the
file names are the entry points, all relative to the repository's `v2/`.

| # | Block | Repo | Where | What it does |
|---|---|---|---|---|
| A | Crypto backend abstraction | transport | `crypto/backend.go`, `crypto/registry.go` | `crypto.Backend` interface: keypair, parse/serialize, `Encrypt`/`Decrypt`, `EncryptMultiRecipient`/`DecryptMultiRecipient`, `Sign`/`Verify`, `PublicKeyFromStdlib`. Name-keyed registry (`RegisterBackend`, `GetBackend`). |
| A1 | JOSE backend | transport | `crypto/jose/backend.go` | ES256 JWS, ECDH-ES + AES-GCM JWE, JWK key files. Registers itself as `"jose"` in `init()`. The only backend tdns-mp uses. |
| A2 | HPKE backend | transport | `crypto/hpke/backend.go`, `hpke/` | X25519 HPKE plus an EDNS0 ephemeral-key option and KMREQ qname helpers. Registered, but no caller in tdns-mp or tdns. |
| B | Payload wrapping | transport | `transport/crypto.go`, `transport/envelope.go` | `PayloadCrypto` (local keys, per-peer encryption and verification keys, `EncryptAndSignPayload` = base64(JWS(JWE(payload))), `DecryptAndVerifyPayload`), `SecurePayloadWrapper` (`WrapOutgoing`, `UnwrapIncomingFromPeerEnvelope`). The envelope label (`EnvelopeNone`, `EnvelopeJOSE`, `EnvelopeCOSE` reserved) rides in the CHUNK Format byte. |
| C | DNS mechanism | transport | `transport/dns.go`, `transport/chunk_notify_handler.go` | `DNSTransport`: NOTIFY(CHUNK) with the payload in an EDNS0 CHUNK option, or `chunk_mode=query` where the payload is served as CHUNK records and fetched by the receiver. Inline confirmation in the NOTIFY response. `ChunkNotifyHandler.RouteViaRouter` is the receive path. |
| D | API mechanism | transport | `transport/api.go`, `transport/app_message.go` | `APITransport`: HTTPS JSON. Carries hello, beat, ping, confirm and the sync family only; every other verb is DNS-only. |
| E | Message router | transport | `transport/dns_message_router.go`, `router_init.go`, `handlers.go`, `crypto_middleware.go`, `stats_middleware.go` | `DNSMessageRouter`: handlers registered by verb with priority, global middleware chain, metrics, `Describe`. `InitializeRouter` installs authorization, signature, stats and logging middleware and the transport-own verbs. |
| F | Peer state and discovery | transport | `transport/peer.go`, `transport/discovery.go`, `transport/imr.go` | `Peer` (identity, per-mechanism address, state NEEDED to OPERATIONAL with decay, JWK/TLSA/KEY slots, stats), `PeerRegistry`. Discovery: URI, SVCB, TLSA, JWK, KEY lookups through the tdns IMR; `RegisterDiscoveredPeer` loads the discovered JWK into `PayloadCrypto`. |
| G | Manager and reliable delivery | transport | `transport/manager.go`, `manager_fanout.go`, `reliable_message_queue.go`, `transport/transport.go` | `TransportManager`: mechanism selection, `Send` with fallback, `SendAll` fan-out for hello/beat, `Enqueue` into the `ReliableMessageQueue` that retries until `MarkConfirmed`. `Transport` interface and the request/response structs. |
| H | Chunk manifests | transport | `distrib/` | Split, reassemble, JSON and JWT manifests, HMAC. Used by the DNS mechanism in query mode. The tracker and persistence interfaces have no caller. |
| I | Application verbs | mp | `mp_verbs.go`, `mp_verb_handlers.go`, `mp_wire_payloads.go`, `mp_send.go`, `mp_chunk_parse.go`, `mp_msg_types.go` | One table of verbs with the roles that accept each, the validating handler, the consumer, the wire struct, the send builder and the typed queue. |
| J | Transport bridge | mp | `hsync_transport.go`, `agent_authorization.go`, `agent_discovery.go` | `MPTransportBridge` embeds `TransportManager` and owns everything role-specific: constructing the mechanisms and router per role, hello/beat with fallback and gossip, enqueue helpers, DNSKEY propagation tracking, RFI to signer and combiner, peer authorization. |
| K | HSYNC engine | mp | `hsync/` (engine, registry, discovery, hello, beat, reconcile, hsync3_diff, interfaces), `hsync_bridge.go`, `hsync_data_engine.go` | The peer-lifecycle loop: reconcile membership from HSYNC3 and HSYNCPARAM, discover, hello, beat, gossip side effects. Dependencies are injected interfaces; `hsync_bridge.go` holds the adapters. |
| L | Gossip, groups, election | mp | `gossip.go`, `gossip_types.go`, `provider_groups.go`, `parentsync_leader.go`, `hsync_agent_gossip.go` | The per-group NxN state matrix exchanged on beats, provider groups derived from HSYNCPARAM participants, the CALL/VOTE/CONFIRM leader election. |
| M | Synched data engine | mp | `syncheddataengine.go`, `agent_policy.go`, `sde_types.go`, `hsyncengine.go`, `hsync_utils.go`, `mpzonedata.go`, `mp_extension.go` | Per-zone, per-agent tracked RRsets with pending/confirmed lifecycle; the agent's reaction to sync, rfi, edits, keystate; the pre- and post-refresh analysis of HSYNC and DNSKEY changes. |
| N | Combiner | mp | `combiner_chunk.go`, `combiner_msg_handler.go`, `combiner_utils.go`, `combiner_peer.go`, `combiner_crypto.go`, `db_combiner_*.go` | Contribution intake with edit policy, protected namespaces and DNSKEY policy; persistence with origin; projection of the served zone through one tdns `StageBatch`. |
| O | MP signer | mp | `start_signer.go`, `signer_*.go`, `cmd/mpsigner` | See section 3.6. |
| P | Auditor | mp | `auditor_*.go`, `start_auditor.go` | Read-only fourth party: runs the HSYNC engine, records observations, web UI. |
| Q | Parent sync | mp | `delegation_sync.go`, `parentsync_*.go` | The elected leader drives the parent through tdns's DSYNC machinery and reports back with status-update. |
| R | Boot and configuration | mp | `main_init.go`, `config.go`, `mp_config_parse.go`, `multi_provider_conf.go`, `config_validate.go`, `start_*.go`, `cmd/*/main.go` | `MainInit` plus `initMP{Agent,Combiner,Signer,Auditor}`; the `multi-provider:` block parsed through a tdns config hook; one `StartMP*` per role that starts the tdns engines it needs and the MP engines on top. |
| S | Management API and CLI | mp | `apihandler_*.go`, `apirouter_sync.go`, `cli/`, `cli/configure/` | The per-role management API, the agent-to-agent HTTPS sync API with TLSA verification, `tdns-mpcli` including multi-instance targeting and `configure`. |
| T | Persistence | mp | `hsyncdb.go`, `db_hsync.go`, `db_schema_hsync.go`, `db_combiner_*.go`, `auditor_eventlog.go` | `HsyncDB` on the tdns keystore's SQLite: key states, sync operations, confirmations, transport events, contributions, edits. |
| U | Platform pieces the stack relies on | tdns | `core/rr_chunk.go`, `rr_jwk.go`, `jwk_helpers.go`, `rr_hsync3.go`, `rr_hsyncparam.go`, `chunk_utilities.go`, `core/messages.go`, `edns0/edns0_chunk.go`, `registration.go`, `key_lifecycle_hooks.go`, `config.go` hooks, zone staging, keystore, `Imr` | The RR types and EDNS0 option, the NOTIFY and query handler registries, the key lifecycle hooks and staging API from PR #622, the config and refresh hooks, the engines. |

## 3. The questions

### 3.1 Encrypt, decrypt and authenticate

Two different mechanisms, two different answers.

**DNS mechanism.** All of it is in tdns-transport, blocks A, B and C.

- Sending: `DNSTransport.sendNotifyWithPayload` calls
  `SecurePayloadWrapper.WrapOutgoing`, which calls
  `PayloadCrypto.EncryptAndSignPayload`: JWE for the peer's key, JWS with our
  key, base64. The result goes into the EDNS0 CHUNK option with Format set to
  the JOSE envelope label, or into CHUNK records in query mode. Responses are
  encrypted the same way in `handlers.go` (`encryptResponsePayload`).
- Receiving: `ChunkNotifyHandler.RouteViaRouter` reads the envelope label,
  refuses labels it cannot process, runs the application's pre-crypto
  authorization callback, then `UnwrapIncomingFromPeerEnvelope` with the
  verification key of the sender named in the QNAME and no other. A missing
  key triggers discovery and drops the message; a failed decryption is
  REFUSED. The router's signature and decryption middleware exist but see an
  already-decrypted context and pass through.
- Keys: `PayloadCrypto` holds the local pair and per-peer keys. Configured
  keys are loaded by tdns-mp (`initAgentCrypto` in `main_init.go`,
  `InitCombinerCrypto`, `initSignerCrypto`, the auditor's variant in
  `initMPAuditor`), all from `long_term_jose_priv_key` and
  `long_term_jose_pub_key`. Discovered keys come from the JWK record at
  `dns.<identity>` (`transport/imr.go`, decoded by tdns
  `core.DecodeJWKToPublicKey`) and are installed by
  `RegisterDiscoveredPeer`. The agent publishes its own JWK record from
  `agent_setup.go` (`AgentJWKKeyPrep`, via tdns `PublishJWKRR`).

**API mechanism.** Plain JSON over TLS. Authentication is mutual TLS with the
client certificate checked against the peer's discovered TLSA record, in
tdns-mp `apirouter_sync.go` (`tlsaVerificationMiddleware`). No JOSE is
involved.

**Authorization** (may this peer talk to me at all, and about this zone) is a
tdns-mp decision, `agent_authorization.go`: an explicit configured list, or
membership of the zone's HSYNC3 RRset. Transport enforces it twice, before
crypto with only the QNAME sender and after parsing with the zone.

### 3.2 The DNS message router

tdns-transport, block E, `transport/dns_message_router.go`. Entry from the DNS
side is tdns's NOTIFY dispatcher: each role registers
`ChunkNotifyHandler.RouteViaRouter` for qtype CHUNK through
`tdns.RegisterNotifyHandler`. `RouteViaRouter` does the transport work of
section 3.1, builds a `MessageContext`, and calls `Router.Route(ctx, verb)`.

`InitializeRouter` (`router_init.go`) installs the middleware chain in order
(authorization, signature, statistics, logging), the default handler that
answers REFUSED for an unregistered verb, and the transport-own verbs
`ping`, `hello`, `beat` and, for roles that send confirmed distributions,
`confirm`. tdns-mp then calls `RegisterAppVerbs` (`mp_verbs.go`) to add the
application verbs the role accepts. `RouteToCallback` hands every handled
message to tdns-mp's `routeIncomingMessage`, which fans out to the typed
`MsgQs` channels the role's engines read.

The router is the single place where verbs meet handlers; the map from verb
to consumer is the table in `mp_verbs.go`.

### 3.3 The gossip conversation

Gossip has no verb of its own. It is piggybacked on beats, in both directions:
`BeatRequest.Gossip` and `DnsBeatPayload.Gossip` on the way out, and the
beat's inline confirmation on the way back (`HandleBeat` in `handlers.go` asks
the application for gossip through `ChunkNotifyHandler.GossipForPeer`).
Transport carries `json.RawMessage` and never looks inside.

Everything about the content is tdns-mp, block L:

- `gossip_types.go`: `GossipMessage` per provider group, with every member's
  view of every other member, the group-name proposal and the election state.
- `gossip.go`: `GossipStateTable`, the NxN matrix: `UpdateLocalState`,
  `MergeGossip`, `BuildGossipForPeer`, `CheckGroupState` (fires the
  group-operational and group-degraded callbacks), `RefreshLocalStates`.
- `provider_groups.go`: a group is the hash of the sorted participants derived
  from HSYNCPARAM; `VotingMembers` excludes auditors.
- Wiring in `hsync_transport.go`: `SendBeatWithFallback` builds our gossip and
  merges the response's; `routeBeatMessage` merges inbound gossip; the
  `GossipForPeer` callback supplies gossip for beat responses.
- The engine side: `hsync/gossip_port.go` (`GossipPort`), `hsync/beat.go`
  (refresh local states and check group state on every tick),
  `hsync_agent_gossip.go` (the adapter to the agent's table). The election
  consumes gossip through `wireAgentGossipCallbacks` in `hsync_bridge.go` into
  `parentsync_leader.go`.
- Operator view: `apihandler_gossip.go` and `cli/gossip_cmds.go`.

### 3.4 Message types, and adding a new one

There are two vocabularies.

**Transport-own verbs**: hello, beat, ping, confirm. Request and response
structs in `transport/transport.go`, wire structs `Dns*Payload` in
`transport/dns.go`, handlers in `transport/handlers.go`, API bodies in
`transport/api.go`. These are the only verbs transport interprets.

**Application verbs**: sync, update, rfi, keystate, edits, config, audit,
status-update, relocate. Each is one row in `appVerbTable` in tdns-mp
`mp_verbs.go`, and that row is the whole definition:

| Piece | File |
|---|---|
| verb token, accepting roles, description | `mp_verbs.go` |
| validating handler that prepares the inline confirmation | `mp_verb_handlers.go` (`handleApp<Verb>`) |
| consumer that hands the message to a queue | `hsync_transport.go` (`route<Verb>Message`) |
| wire payload struct and parser | `mp_wire_payloads.go` |
| send builder to a `transport.AppMessage` | `mp_send.go` |
| typed queue the engine reads | `mp_msg_types.go` (`MsgQs`) |
| API-side struct and the verb string | tdns `core/messages.go` (`AgentMsg`, `Agent*Post`) |

On the wire an application verb is `transport.AppMessage{Scope, TypeToken,
Payload}`; transport parses nothing of the payload but hands it to the
application's parser, `parseAppPayload` in `mp_chunk_parse.go`, which reads
the MP field conventions (`MessageType`, `OriginatorID` or `MyIdentity`,
`Zone`, `nonce`).

Adding a verb is therefore easy and entirely inside tdns-mp: a row in the
table, a handler, a consumer, a payload struct, a send builder, and a queue
field if the consumer needs a new one. Two tests pin it:
`transport_dispatch_test.go` drives every row through the real router and
middleware, and `golden_wire_test.go` with `testdata/golden-wire/*.json` pins
the bytes, so a new verb needs a golden file. The only reasons to touch
tdns-transport are a verb that must also travel over the API mechanism
(`IsSyncFamily` and the `/sync` body in `api.go`) or a new transport-level
semantic. The verb string also exists in tdns `core/messages.go` because the
API path shares those structs; a DNS-only verb does not need it.

### 3.5 Adding COSE next to JOSE

The design already reserves the place: `crypto.Backend` is name-keyed, and
`EnvelopeCOSE` is defined in `transport/envelope.go` and answered FORMERR
until implemented. The change is nevertheless not contained in one package,
because the JOSE shape leaks in three places. By repository:

**tdns-transport, the bulk.**

- `crypto/cose/backend.go`: a new `crypto.Backend`. The interface's
  multi-recipient methods are documented in JWE terms but return bytes, so a
  COSE_Encrypt and COSE_Sign1 implementation fits the signatures.
- `transport/crypto.go`: `PayloadCrypto` is not backend-agnostic today.
  `DecryptAndVerifyPayload` splits the JWS compact serialization itself
  (`splitJWS`, `base64URLDecode`) and re-verifies with the backend;
  `EncryptAndSignPayload` composes JWE then JWS by hand; `IsPayloadEncrypted`
  sniffs for base64-that-is-not-JSON. The composition has to move behind the
  backend (both backends already implement `EncryptAndSign` and
  `DecryptAndVerify`, and `PayloadCrypto` does not call them), and
  `PayloadCrypto` needs a backend per envelope rather than one.
- `transport/envelope.go`: accept `EnvelopeCOSE`.
- `transport/dns.go` and `transport/handlers.go`: the Format byte is set to
  `core.FormatJWT` whenever crypto is on; it must become the envelope of the
  backend that wrapped the payload.
- `transport/chunk_notify_handler.go`: `UnwrapIncomingFromPeerEnvelope` picks
  the backend by label. Query mode arrives unlabelled and falls back to the
  sniff, which cannot tell COSE from JOSE; labelling that path is the open
  item the code calls F2b.
- Negotiation: `HelloRequest.Capabilities` exists and is carried but nothing
  reads it. That is the natural place to advertise `cose`.

**tdns-mp, mechanical but in several places.**

- Every role's crypto init calls `jose.NewBackend()` and type-asserts
  `*jose.Backend` to reach `PublicFromPrivate`, which is not on the interface:
  `main_init.go`, `combiner_crypto.go`, `signer_transport.go`,
  `agent_setup.go`, `keys_cmd.go`. These should select the backend from
  configuration through `crypto.GetBackend`.
- Configuration names: `long_term_jose_priv_key`, `long_term_jose_pub_key`,
  and the `<role>.jose.priv.json` files that `cli/configure` renders.
- CLI: `keys generate --jose`, and `jwt inspect` (`cli/jwt_cmds.go`) which
  uses go-jose directly and would need a COSE sibling.
- `AgentJWKKeyPrep` hand-decodes the JWK to an ECDSA key before publishing;
  unaffected if the published key stays a JWK.

**tdns, one constant.**

- `core/rr_defs.go`: `FormatCOSE = 3` and its presentation string, so a CHUNK
  record with a COSE payload prints and parses. The envelope label reuses the
  Format codes, so this value must agree with `EnvelopeCOSE`.
- The identity key can stay a JWK record: a COSE ES256 signature uses the same
  P-256 key that the JWK publishes, and `DecodeJWKToPublicKey` yields a
  stdlib key that `PublicKeyFromStdlib` wraps for any backend. Only a wish to
  publish COSE_Key would add an RR type here.

Rough weight: two thirds in tdns-transport, a third in tdns-mp, one constant
in tdns.

### 3.6 The MP signer

`tdns-mpsigner` is tdns-auth with the multi-provider key protocol on top. The
signing itself, key generation, the rollover state machines, the keystore and
`KeyStateWorker` are tdns. tdns-mp adds:

- `start_signer.go`: starts the tdns engines a signer needs (DNS, refresh,
  notifier, zone updater, resigner, `KeyStateWorker`) and then the MP
  transport and `SignerMsgHandler`.
- `signer_keydb.go`: `RegisterMPKeyLifecycleHooks` fills tdns's
  `KeyLifecycleHooks` (PR #622, T-S2): a new key is staged as `mpdist`, a
  retired key as `mpremove`, promotion is gated on peer confirmation plus the
  DNSKEY TTL, generation only bootstraps, and every state change pushes a
  fresh inventory to the agents. Also `syncForeignDNSKEYs` for the other
  providers' keys.
- `signer_msg_handler.go`: consumes KEYSTATE signals from the local agent
  (`propagated` moves `mpdist` to `published` and `mpremove` to `removed`,
  then triggers a resign) and answers KEYSTATE RFIs with the inventory.
- `signer_transport.go`: the signer's `PayloadCrypto` from configured agent
  keys; no discovery. `signer_chunk_handler.go`: the CHUNK NOTIFY entry and
  the query-mode fetch. `signer_peer.go`: the signer as a peer of its agent.
- Router verbs on a signer: `rfi`, `keystate`, `status-update`.

Not to be confused with `tdns-signer` in tdns `cmdv2/signer`, which is
tdns-auth under another name for bump-on-the-wire signing and has no
multi-provider role.

### 3.7 Other blocks, briefly

- **Peer discovery**: the lookups and the peer record are transport (block F);
  the decision to discover, the retry schedule and the semaphore are the HSYNC
  engine (`hsync/discovery.go`); `agent_discovery.go` is the MP gate that
  calls `TransportManager.DiscoverAndRegisterAgent`.
- **Reliable delivery**: the queue and the confirm verb are transport (block
  G); what a confirmation means for the data is `ProcessConfirmation` in the
  synched data engine, and the operator's view of distributions is
  `distribution_cache.go` plus the `distrib` API handlers.
- **Leader election and parent sync**: tdns-mp only, blocks L and Q, using
  tdns's DSYNC and delegation-sync code as the parent-facing tool.
- **Boot**: each `cmd/*/main.go` sets `tdns.Globals.App.Type`, runs
  `MainInit`, and calls one `StartMP<Role>`; the extension points used are
  `RegisterNotifyHandler`, `RegisterQueryHandler`,
  `RegisterKeyLifecycleHooks`, `RegisterZoneOptionHandler/Validator`,
  `PostParseConfigHook`, `PostValidateConfigHook`, `PostParseZonesHook`,
  `OnZonePreRefresh`, `OnZonePostRefresh` and `StartEngine`.

## 4. Loose ends seen on the way

These are observations, not findings against the PRs.

- `tdns-transport/v2/hpke` and `crypto/hpke` have no caller outside their own
  registration and the transport-exercise tool.
- `tdns-transport/v2/distrib`: only the manifest split and reassembly are
  used, by `dns.go` in query mode. `DistributionTracker`, `DistributionStore`
  and the JWT manifest have no caller in tdns-mp.
- `PayloadCrypto` re-implements the sign-then-encrypt composition that both
  backends already offer as `EncryptAndSign` and `DecryptAndVerify`.
- The router's signature and decryption middleware are installed but always
  see a context that `RouteViaRouter` has already decrypted.
- tdns retains a small multi-provider residue: `core/messages.go` (the verb
  strings and API structs), `OptMultiProvider`, `ZoneMPExtension`, and the two
  key-state strings `mpdist` and `foreign` that PR #622 lets the keystore
  serve.
