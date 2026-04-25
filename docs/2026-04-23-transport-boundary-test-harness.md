# Transport-boundary integration test harness

Date: 2026-04-23  
Status: PLAN — implementation specification  
Parent: [2026-04-15-transport-interface-redesign.md](./2026-04-15-transport-interface-redesign.md) (Phase 0 / former Bite 2)

This document is **only** an expansion of Phase 0 from the parent plan: where code and tests should live, what to build first, how each of the **seven** scenarios is satisfied, and what “done” means for CI. It does **not** restate the architectural rationale; read the parent doc for that.

Framing agreed separately: this work may be treated as **its own project** (harness + seven scenarios first), with broader tdns-mp integration tests as follow-on milestones—not as a prerequisite to starting here.

---

## 1. Objectives

1. **Regression safety net** at the boundary between `tdns-mp` (`MPTransportBridge`, `MsgQs`, `AgentRegistry`) and `tdns-transport` (`TransportManager`, DNS/API transports, CHUNK path, handlers).
2. **Reusable harness** so future transport refactors add scenarios instead of reinventing fixtures.
3. **CI gate**: all **seven** scenarios pass on every merge (`go test` in the `tdns-mp/v2` module).

Non-goals for this document’s scope:

- Refactoring production transport or MP code (tests may *suggest* bugs; fixing them is optional per finding).
- Full end-to-end multi-binary deployments (mpagent + mpcombiner + live zones)—out of scope unless a scenario explicitly requires it (none of the seven do).

---

## 2. Module and layout

| Choice | Recommendation |
|--------|----------------|
| Module | `github.com/johanix/tdns-mp/v2` (`tdns-mp/v2/go.mod`) — all new test code runs here so `replace` directives for `tdns-transport` and `tdns/v2` apply. |
| Package | Prefer **`package tdnsmp`** test files under `v2/` (e.g. `v2/transport_integ_test.go`, `v2/transport_harness_test.go`) **or** a subdirectory **`v2/integtransport/`** with `package tdnsmp` only if build tags are needed to keep long tests out of default `go test ./...`. |
| External / black-box package | `package tdnsmp_test` under `v2/integ/` is possible but likely **awkward**: much of the harness touches `MPTransportBridgeConfig`, `AgentRegistry` wiring, and possibly unexported helpers. Default to **same package** tests unless exports are sufficient. |

Suggested file split (names illustrative):

- `transport_harness_test.go` — env builder: `MsgQs`, minimal `AgentRegistry`, `NewMPTransportBridge`, optional in-memory DNS / HTTP test servers.
- `transport_integ_test.go` — one `TestTransportBoundary_*` (or subtests) per scenario below.
- Optional: `transport_harness_dns_test.go` if DNS-only setup is large.

---

## 3. Shared harness: components and contracts

### 3.1 Two logical peers (“Alice” and “Bob”)

Each peer needs:

- Its own `*MPTransportBridge` (via `NewMPTransportBridge`).
- Its own `*AgentRegistry` (or a documented shared registry if a scenario requires both sides to see the same registry—usually **two registries**, one per logical process).
- Its own `*MsgQs` with **buffered** channels where the test reads (`Msg`, `Confirmation`, etc.); unbuffered channels will deadlock if production code sends before the test receives.

Document for each scenario:

- **Local identity** (`LocalID` / `AgentRegistry.LocalAgent.Identity`) — FQDN strings consistent with what DNS and CHUNK QNAME logic expect.
- **Control zone** — must match whatever `NewMPTransportBridge` / `NewChunkNotifyHandler` require (`MPTransportBridgeConfig.ControlZone`).

### 3.2 `MsgQs` construction

Minimum fields depend on the scenario:

| Scenario | Channels / callbacks typically required |
|----------|-------------------------------------------|
| 1 (CHUNK → Msg) | `Msg` (buffered), possibly `Hello`/`Beat` if routers enqueue |
| 3–4 (Confirmation) | `Confirmation` (buffered), `OnRemoteConfirmationReady` for async path if the code path under test uses it |
| 5 (LEGACY sync) | Often none from `MsgQs`; may use transport handler only |
| 6 (Hello rejection) | Usually none; test drives `EvaluateHello` (or HTTP `/hello`); `Hello` channel only if asserting full handler side-effects |
| 7 (Discovery) | Optional; scenario asserts `PeerRegistry` + callback—`MsgQs` may be minimal |

Default: construct **all** `MsgQs` channels with small buffers (e.g. 4–16) so sporadic sends do not block; unused channels can remain drained or ignored.

### 3.3 `AgentRegistry` and `MultiProviderConf`

`AgentRegistry` carries `LocalAgent *tdns.MultiProviderConf`, `MPTransport`, `TransportManager`, maps for agents, etc. The harness should provide:

- A **minimal** `MultiProviderConf` with `Identity` set to the local peer’s FQDN agent ID.
- **Remote agents** inserted with whatever fields `SendHelloWithFallback` / `SendSyncWithFallback` / discovery paths read (`ApiDetails`, `DnsDetails`, `ApiMethod`, `DnsMethod`, `Zones`, `State`).

“Fake” in the parent doc means **lightweight in-process structs**, not necessarily a separate `FakeAgentRegistry` type: a real `AgentRegistry` populated via constructors or test-only helpers is fine if it stays deterministic.

### 3.4 Building `MPTransportBridge`

Drive everything through `NewMPTransportBridge(&MPTransportBridgeConfig{...})` with explicit:

- `LocalID`, `ControlZone`, `AgentRegistry`, `MsgQs`
- `SupportedMechanisms` (`"api"`, `"dns"` casing—match what production uses)
- `CombinerID` / `SignerID` / `SignerAddress` — set dummy values if unused for a scenario; some code paths dereference config without needing a live combiner.
- **Chunk mode**: start with the mode the team uses most in CI (e.g. `edns0` vs `query`); document which scenarios require which. Scenario 1 may be easier with **query mode + in-memory chunk store** if that reduces UDP variance—decide once and document in the harness README comment block.
- **DNS transport**: either shared in-memory DNS server (preferred for determinism) or **loopback UDP** with random ports—see §5.
- **API transport**: `httptest.Server` per peer for sync/hello/beat/ping endpoints, with handlers delegating into `tdns-transport` router where applicable, **or** minimal stubs that return the JSON the client expects (second option is faster but must stay in sync with wire types).

After `NewMPTransportBridge`, call whatever production startup order requires: e.g. `RegisterChunkNotifyHandler`, `StartIncomingMessageRouter` with a **test-scoped** `context.Context` (cancel in `t.Cleanup`).

### 3.5 Shared DNS surface

The parent deliverable: “two in-process TransportManagers with **shared** in-memory DNS (or loopback UDP).”

**Shared** means: when Alice sends a NOTIFY to Bob’s nameserver identity, resolution and packet delivery resolve to **Bob’s** handler (same process or loopback to Bob’s port). Implementation options:

1. **In-memory DNS** — single `dns.Server` or custom `net.PacketConn` pair that both transports use (if the transport stack allows injecting `Exchange` / client conn).
2. **UDP loopback** — two server goroutines on `127.0.0.1:0`, explicit forwarding or shared port if the design allows one listener acting as “the control plane.”

Record in the harness **which option** is chosen and **how** `DNSTransport` is configured to use it (`tdns` server hooks, `Replace` in `go.mod` already point at local `tdns-transport`—no extra replace for tests unless needed).

### 3.6 Assertion helpers

Centralize:

```text
recvTimeout(t, ch, timeout) (T, bool)
mustRecvConfirmation(t, ch, predicate func(*ConfirmationDetail) bool)
mustRecvAgentMsgPostPlus(t, ch, predicate func(*AgentMsgPostPlus) bool)
```

Use **short** default timeouts (e.g. 2–5s) locally, **longer** on CI if flakes appear (document env var e.g. `TDNS_MP_INTEG_TIMEOUT`).

Always **drain or cancel** background goroutines (router, DNS server) in `t.Cleanup`.

---

## 4. Scenario specifications

Open item **K** in the parent redesign doc is satisfied when **all seven** scenarios below are implemented and green on CI. Scenarios **5** and **6** split **sync** vs **hello** policy rejection so both code paths are explicitly guarded (parent text previously mixed “hello” and `HandleSync` wording).

For each: **goal**, **setup**, **action**, **assertions**, **notes**.

### Scenario 1 — CHUNK NOTIFY round trip

| Field | Detail |
|-------|--------|
| Goal | Sender’s sync is received by the peer’s incoming path and surfaced on `MsgQs.Msg`. |
| Setup | Two bridges; Bob’s router + chunk handler active; Alice has Bob in `PeerRegistry` with addresses/keys needed for send; shared DNS (or configured API+DNS) per harness choice. |
| Action | Alice sends a sync (via `SendSyncWithFallback` or the smallest API that hits the same code path as production) targeting Bob with a known zone / payload / message type. |
| Assert | One message on `Bob.MsgQs.Msg` within timeout; fields match **at least**: sender identity, zone (if present on `AgentMsgPostPlus`), message type, payload body or hash agreed in test. |
| Notes | Inspect `AgentMsgPostPlus` / `AgentMsgPost` definitions in `mp_msg_types.go` and core for exact field names. May require Bob’s `IsPeerAuthorized` / HSYNC hooks to return true—inject `GetZone` / `AuthorizedPeers` on config as needed. |

### Scenario 2 — SYNC with API→DNS fallback

| Field | Detail |
|-------|--------|
| Goal | When API fails mid-flight, delivery completes via DNS; fallback is **observable** (stats or structured check). |
| Setup | Remote peer has **both** `ApiMethod` and `DnsMethod`; `Peer.PreferredTransport` favors API; both transports configured on Alice’s bridge. |
| Action | First sync succeeds via API (optional baseline). Close or break Alice’s API client target (`httptest.Server.Close` or handler returning 500) **before** second send; send sync again. |
| Assert | Second sync still reaches Bob’s `Msg` (or equivalent success signal); **and** evidence of fallback—e.g. `peer.Stats` / mechanism-specific counters in transport, or log hook via `tdns` test logger if no counter exists yet. If no observable signal exists, **add a minimal test-only metric hook** only after team agreement (otherwise assert DNS path indirectly by breaking API only and asserting delivery). |
| Notes | Flake risk: race on server close—serialize with barriers or `sync.WaitGroup`. |

### Scenario 3 — Confirmation routing, inline path

| Field | Detail |
|-------|--------|
| Goal | Receiver answers sync with **immediate** confirmation; Alice’s `MsgQs.Confirmation` receives expected distribution ID and status. |
| Setup | Bob’s handler (or combiner stub) returns inline confirm in the same request path the production DNS/API sync uses; Alice’s `ChunkHandler.OnConfirmationReceived` wired as in production (`NewMPTransportBridge`). |
| Action | Alice sends sync that triggers immediate confirmation. |
| Assert | `Confirmation` channel receives `ConfirmationDetail` (or type actually sent) with expected `DistributionID`, `Status`, and `Source` / zone consistent with test. |
| Notes | Trace `sendImmediateConfirmation` / transport `HandleConfirmation` to align with real status strings (`ConfirmSuccess`, etc.). |

### Scenario 4 — Confirmation routing, async NOTIFY path

| Field | Detail |
|-------|--------|
| Goal | Sync returns pending; later NOTIFY carries confirmation; same logical confirmation arrives on `MsgQs.Confirmation`. |
| Setup | Bob responds without inline finalize (pending path); test then drives second phase NOTIFY (may require calling into chunk handler / DNS server helper that injects NOTIFY bytes matching production format). |
| Action | Two-phase: (1) sync, (2) async confirmation. |
| Assert | Same distribution ID and compatible status as scenario 3; may include `AppliedRecords` / `RejectedItems` if test payload includes RR details. |
| Notes | **Hardest scenario** — may be implemented **last**. If NOTIFY construction is too heavy for v1, split: subtest `Pending` only, full NOTIFY in v2—document any deferral in harness header. |

### Scenario 5 — LEGACY / zero-scope **sync** rejection

| Field | Detail |
|-------|--------|
| Goal | Peer with **zero** shared zones must not complete **sync**; transport `HandleSync` rejects with the documented policy. |
| Setup | Receiver’s `PeerRegistry` entry for the sender has **empty** `SharedZones` (or equivalent path that yields `len(ctx.Peer.GetSharedZones()) == 0` in transport). Sender attempts sync toward that peer. |
| Action | Send sync (DNS or API path—whichever the harness uses for sync) that would succeed if `SharedZones` were non-empty. |
| Assert | `HandleSync` returns error / negative handler outcome; message or error string matches **LEGACY** / “zero shared zones” semantics per `tdns-transport/v2/transport/handlers.go` (today’s behavior). |
| Notes | This is the **transport-layer** gate on sync. It does **not** replace scenario 6; hello acceptance is a separate MP evaluation path. |

### Scenario 6 — **Hello** rejection (HSYNC / zone policy)

| Field | Detail |
|-------|--------|
| Goal | A **hello** that should be refused by policy is refused **before** transport treats the relationship as introduced—same class of protection as open item **K**’s “hello” bullet, independent of scenario 5. |
| Setup | `AgentRegistry` with `LocalAgent` set; **seed zone data** so `EvaluateHello` can run (`hsync_hello.go` uses global `Zones` today—see §6). Construct a zone with a valid HSYNC3 RRset that includes **local** identity but **excludes** the remote caller’s identity (or use an **unknown zone** / **missing HSYNC3** per a second subtest if useful). Build `AgentHelloPost` consistent with production JSON (`AgentMsgHello`, identities, zone). |
| Action | Call `(*AgentRegistry).EvaluateHello(&ahp)` **or** POST to the same logic via `httptest` + minimal handler wiring if you intentionally test the HTTP surface—either is acceptable if it executes the real `EvaluateHello` body. |
| Assert | `needed == false`; `errmsg` non-empty and stable (substring match on the known rejection reason for the chosen case—e.g. HSYNC3 does not include both identities, unknown zone, or no HSYNC3 RRset). If using HTTP, assert response `Error` / `ErrorMsg` reflects the same rejection. |
| Notes | This scenario intentionally does **not** rely on `HandleSync`. It locks **hello-time** policy. If production later injects zone lookup instead of global `Zones`, update the harness to use the same injection hook and drop global seeding. |

### Scenario 7 — Discovery completion path

| Field | Detail |
|-------|--------|
| Goal | After “discovery completes,” transport peer is **KNOWN** and `OnAgentDiscoveryComplete` behavior (sync peer + preferred transport) has run. |
| Setup | Agent in **NEEDED** (or pre-discovery) with empty transport details; then populate `ApiDetails`/`DnsDetails` and flags as if IMR/discovery succeeded. |
| Action | **Simulate** completion by calling `MPTransportBridge.OnAgentDiscoveryComplete(agent)` (matches parent “simulate discovery completion”) **or** drive minimal discovery callback from real discovery code if harness grows IMR fakes. |
| Assert | `PeerRegistry.Get(string(agent.Identity))` shows `PeerStateKnown` (or `transport.PeerStateKnown`); `PreferredTransport` matches `GetPreferredTransportName` rules for the synthetic `ApiMethod`/`DnsMethod` flags. |
| Notes | Tier 1 = direct callback (fast, stable). Tier 2 = IMR + fake resolver (later milestone). |

---

## 5. DNS vs API: implementation order

Suggested order to limit simultaneous unknowns:

1. **Scenario 7** (discovery / no network) — validates harness wiring of `PeerRegistry` + bridge.
2. **Scenario 5** (LEGACY sync rejection, minimal network).
3. **Scenario 6** (hello rejection — needs `Zones` / HSYNC3 fixture; implement once harness has zone seeding helper).
4. **Scenario 1** on **API-only** or **DNS-only** first—whichever is simpler with `httptest` / one transport—then extend to CHUNK/DNS as required by fidelity.
5. **Scenario 3** (inline confirm).
6. **Scenario 2** (fallback).
7. **Scenario 4** (async NOTIFY).

Adjust if the team prefers API-first for all sync traffic in CI.

---

## 6. Global state and injection hazards

Several MP paths use **global** `Zones` (e.g. `EvaluateHello` in `hsync_hello.go`). Scenarios **1–5** and **7** may avoid it if the harness injects `GetZone` on `MPTransportBridgeConfig` where applicable. **Scenario 6** requires deterministic zone + HSYNC3 data visible to `EvaluateHello`—either:

- Seed the global `Zones` in test setup (document initialization order and mutex rules), or  
- Refactor production to inject zone lookup (**out of scope** for Phase 0 unless blocking—then record as a **pre-task** and temporarily `t.Skip` scenario 6 with a ticket reference).

Document every global touched in `transport_harness_test.go` header.

---

## 7. CI integration

| Item | Detail |
|------|--------|
| Command | From repo root: `cd tdns-mp/v2 && go test ./... -count=1 -timeout=30m` (tune timeout). |
| Race | Enable `-race` on a scheduled job or heavy PR path if runtime allows. |
| Parallels | Use `t.Parallel()` only where ports and globals are isolated; default **sequential** for first landing. |
| Tags | Optional `-tags=integ` if default `go test` must stay fast; then CI runs both. |

**Exit gate (same as parent Phase 0, expanded):** all **seven** scenarios green on the canonical CI pipeline. The parent redesign treats this exit gate as a **prerequisite** before Phases **1–9**; see open item **K** there.

---

## 8. Risks (unchanged from parent, expanded)

| Risk | Mitigation |
|------|------------|
| Harness surfaces production bugs | Open issues, skip or `t.Skip` with ticket ID only if truly blocking CI—default is fix or narrow scenario. |
| Flaky UDP/time | Prefer in-memory DNS; fixed sleeps discouraged—use `require.Eventually` or channel sync. |
| Drift from wire formats | Small shared golden JSON fixtures checked into `v2/testdata/`. |

---

## 9. Deliverables checklist (expanded)

- [ ] Harness builder API used by all seven scenarios (`newTransportIntegEnv(t) *integEnv` or similar).
- [ ] Documented **two-peer** topology and how DNS/API are shared.
- [ ] Buffered `MsgQs`, deterministic identities and zones.
- [ ] Helper to seed **minimal `ZoneData` + HSYNC3** (or equivalent) for **scenario 6** (`EvaluateHello`).
- [ ] Channel / timeout helpers with cleanup.
- [ ] Seven tests (or subtests) mapped 1:1 to §4.
- [ ] CI job updated to run the module tests.
- [ ] Parent redesign doc open item **K** references this file as the prerequisite before Phase 1+ (see parent doc).

---

## 10. Relationship to broader “whole tdns-mp” testing

This harness is intentionally **narrow**. After exit gate:

- Reuse **`newTransportIntegEnv`** patterns for combiner-only or signer-only packages.
- Add **new** docs/milestones for non-transport integration (DB, `SynchedDataEngine`, API routers) rather than expanding this file indefinitely.

---

## 11. Open decisions (fill before coding)

1. **Chunk mode** for CI default (`edns0` vs `query`).
2. **DNS implementation** for scenarios 1–2–4: in-memory vs loopback UDP.
3. **Scenario 4** full NOTIFY in v1 or deferred to v1.1 with explicit skip.
4. **Scenario 6** fixture strategy: global `Zones` seed vs production injection of `GetZone` (if the latter lands first, tests should use the hook and avoid globals).

Record decisions at the top of the harness file or in a short `README` next to tests.
