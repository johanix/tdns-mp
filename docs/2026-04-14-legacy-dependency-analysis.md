# Legacy Code Dependency Analysis: tdns-mp -> tdns/v2

**Date**: 2026-04-14
**Purpose**: Exhaustive inventory of every exported symbol defined in
tdns/v2 legacy/deadcode/mptypes/mpmethods files that is referenced
from tdns-mp code, with exact file and line numbers.

## Executive Summary

tdns-mp/v2 references **110+ exported symbols** from 18 source files
in tdns/v2 (legacy\_\*.go, mptypes.go, mpmethods.go). The
dependency structure is:

1. **Type aliases in types.go** -- 26 aliases like
   `type CombinerSyncRequest = tdns.CombinerSyncRequest` that make
   tdns types available under local names.
2. **Re-defined types in agent\_structs.go and sde\_types.go** --
   tdns-mp has its own `Agent`, `AgentRegistry`, `SynchedDataUpdate`,
   etc. These are NOT aliases -- they are independent struct
   definitions that shadow the tdns versions.
3. **Method calls on tdns types** -- Methods like
   `zd.EnsureMP()`, `zd.GetKeystateOK()` are defined in tdns/v2
   (mpmethods.go, legacy\_hsync\_utils.go) and called on
   `*tdns.ZoneData` receivers from tdns-mp.
4. **Package-level functions** -- Functions like
   `CombinerProcessUpdate()`, `RegisterCombinerChunkHandler()`,
   `NewLeaderElectionManager()` are defined in tdns/v2 legacy files
   but re-defined in tdns-mp. The tdns-mp versions are the active
   ones; the tdns/v2 legacy copies are dead.
5. **Imr methods** -- `LookupAgentJWK()`, `LookupAgentKEY()`, etc.
   are methods on `*tdns.Imr` defined in tdns/v2 legacy files and
   called from tdns-mp.

### Key Structural Insight

Most functions in legacy\_\*.go have been **copied** into tdns-mp and
are now locally defined there. These local definitions call methods
that are still defined in tdns/v2 (mpmethods.go, some legacy files).
The dependency chain is:

```
tdns-mp local function (e.g. hsync_utils.go:RequestAndWaitForKeyInventory)
  -> calls method on *tdns.ZoneData (e.g. zd.SetKeystateOK)
     -> method defined in tdns/v2/mpmethods.go
```

---

## 1. Dependencies on mpmethods.go

Source: `tdns/v2/mpmethods.go`
These are methods on `*tdns.ZoneData` and related types.

### ZoneData.EnsureMP()
| tdns-mp file | line | usage |
|---|---|---|
| combiner\_utils.go | 184 | `mpzd.EnsureMP()` |
| combiner\_utils.go | 586 | `mpzd.EnsureMP()` |
| combiner\_utils.go | 835 | `mpzd.EnsureMP()` |
| config.go | 123 | `w.EnsureMP()` |
| hsync\_utils.go | 217 | `mpzd.EnsureMP()` |
| hsync\_utils.go | 228 | `mpzd.EnsureMP()` |
| hsync\_utils.go | 244 | `mpzd.EnsureMP()` |
| hsync\_utils.go | 823 | `mpzd.EnsureMP()` |
| hsync\_utils.go | 973 | `mpzd.EnsureMP()` |
| hsync\_utils.go | 1010 | `mpzd.EnsureMP()` |
| hsync\_utils.go | 1123 | `new_zd.EnsureMP()` |
| hsync\_utils.go | 1127 | `new_zd.EnsureMP()` |
| main\_init.go | 82 | `zd.EnsureMP()` |
| mp\_extension.go | 60 | `mpzd.EnsureMP()` |
| mp\_extension.go | 76 | `mpzd.EnsureMP()` |
| mp\_extension.go | 92 | `mpzd.EnsureMP()` |
| mp\_extension.go | 108 | `mpzd.EnsureMP()` |
| mp\_extension.go | 124 | `mpzd.EnsureMP()` |

### ZoneData.GetLastKeyInventory()
| tdns-mp file | line | usage |
|---|---|---|
| apihandler\_agent.go | 348 | `inv := zd.GetLastKeyInventory()` |
| apihandler\_agent.go | 774 | `inv := zd.GetLastKeyInventory()` |
| hsync\_utils.go | 175 | `inv := mpzd.GetLastKeyInventory()` |
| syncheddataengine.go | 529 | `if inv := zd.GetLastKeyInventory(); inv != nil {` |

### ZoneData.SetLastKeyInventory()
| tdns-mp file | line | usage |
|---|---|---|
| hsync\_utils.go | 318 | `mpzd.SetLastKeyInventory(&tdns.KeyInventorySnapshot{` |
| hsyncengine.go | 161 | `zd.SetLastKeyInventory(&tdns.KeyInventorySnapshot{` |

### ZoneData.GetKeystateOK()
| tdns-mp file | line | usage |
|---|---|---|
| apihandler\_agent.go | 344 | `if !zd.GetKeystateOK() {` |
| apihandler\_agent.go | 750 | `OK: zd.GetKeystateOK(),` |

### ZoneData.SetKeystateOK()
| tdns-mp file | line | usage |
|---|---|---|
| hsync\_utils.go | 279 | `mpzd.SetKeystateOK(false)` |
| hsync\_utils.go | 296 | `mpzd.SetKeystateOK(false)` |
| hsync\_utils.go | 310 | `mpzd.SetKeystateOK(false)` |
| hsync\_utils.go | 337 | `mpzd.SetKeystateOK(true)` |
| hsync\_utils.go | 343 | `mpzd.SetKeystateOK(false)` |
| hsync\_utils.go | 349 | `mpzd.SetKeystateOK(false)` |

### ZoneData.GetKeystateError()
| tdns-mp file | line | usage |
|---|---|---|
| apihandler\_agent.go | 346 | `zd.GetKeystateError()` |
| apihandler\_agent.go | 751 | `Error: zd.GetKeystateError(),` |
| hsync\_utils.go | 281 | `mpzd.GetKeystateError()` |
| hsync\_utils.go | 298 | `mpzd.GetKeystateError()` |
| hsync\_utils.go | 312 | `mpzd.GetKeystateError()` |
| hsync\_utils.go | 351 | `mpzd.GetKeystateError()` |

### ZoneData.SetKeystateError()
| tdns-mp file | line | usage |
|---|---|---|
| hsync\_utils.go | 280 | `mpzd.SetKeystateError("no TransportManager available")` |
| hsync\_utils.go | 297 | `mpzd.SetKeystateError(...)` |
| hsync\_utils.go | 311 | `mpzd.SetKeystateError(...)` |
| hsync\_utils.go | 338 | `mpzd.SetKeystateError("")` |
| hsync\_utils.go | 344 | `mpzd.SetKeystateError("cancelled")` |
| hsync\_utils.go | 350 | `mpzd.SetKeystateError(...)` |

### ZoneData.GetKeystateTime()
| tdns-mp file | line | usage |
|---|---|---|
| apihandler\_agent.go | 752 | `zd.GetKeystateTime().Format(time.RFC3339)` |

### ZoneData.SetKeystateTime()
| tdns-mp file | line | usage |
|---|---|---|
| hsync\_utils.go | 276 | `mpzd.SetKeystateTime(time.Now())` |

### Agent.IsAnyTransportOperational()
| tdns-mp file | line | usage |
|---|---|---|
| hsyncengine.go | 783 | `if !agent.IsAnyTransportOperational() {` |
| hsyncengine.go | 806 | `if !agent.IsAnyTransportOperational() {` |
| hsyncengine.go | 823 | `if !agent.IsAnyTransportOperational() {` |
| hsyncengine.go | 849 | `if !agent.IsAnyTransportOperational() {` |
| hsyncengine.go | 875 | `if !agent.IsAnyTransportOperational() {` |
| parentsync\_leader.go | 1164 | `if !agent.IsAnyTransportOperational() {` |
| parentsync\_leader.go | 1360 | `Operational: agent.IsAnyTransportOperational(),` |
| start\_agent.go | 101 | `agent.IsAnyTransportOperational()` |
| start\_agent.go | 237 | `if !agent.IsAnyTransportOperational() {` |

### Agent.EffectiveState()
| tdns-mp file | line | usage |
|---|---|---|
| gossip.go | 347 | `state := agent.EffectiveState()` |
| hsyncengine.go | 785 | `AgentStateToString[agent.EffectiveState()]` |
| hsyncengine.go | 807 | `AgentStateToString[agent.EffectiveState()]` |
| hsyncengine.go | 824 | `AgentStateToString[agent.EffectiveState()]` |
| hsyncengine.go | 852 | `AgentStateToString[agent.EffectiveState()]` |
| hsyncengine.go | 878 | `AgentStateToString[agent.EffectiveState()]` |
| parentsync\_leader.go | 1358 | `string(agent.EffectiveState())` |

**Note**: `IsAnyTransportOperational` and `EffectiveState` are
defined in both mpmethods.go AND agent\_structs.go. The tdns-mp
local definitions (on local `Agent` type) are the active ones.
The mpmethods.go versions are on `*tdns.Agent` which is a
different type. These are NOT cross-repo calls. Verified: the
`Agent` type in tdns-mp is locally defined, not an alias.

---

## 2. Dependencies on legacy\_hsync\_utils.go

Source: `tdns/v2/legacy_hsync_utils.go`
Methods on `*tdns.ZoneData` and package-level functions.

**Important**: Several of these are re-defined locally in
tdns-mp/v2/hsync\_utils.go. The local versions are the active
ones. Only methods on `*tdns.ZoneData` that are NOT locally
redefined are true cross-repo dependencies.

### LocalDnskeysFromKeystate() -- method on *ZoneData
| tdns-mp file | line | usage |
|---|---|---|
| apihandler\_agent.go | 356 | `zd.LocalDnskeysFromKeystate()` |
| hsync\_utils.go | 1043 | `mpzd.LocalDnskeysFromKeystate()` |
| hsyncengine.go | 167 | `zd.LocalDnskeysFromKeystate()` |
| syncheddataengine.go | 141 | `zd.LocalDnskeysFromKeystate()` |

**Note**: This is called on `*tdns.ZoneData` receiver. The method
is defined in tdns/v2/legacy\_hsync\_utils.go. This is a true
cross-repo dependency.

### HsyncChanged() -- locally redefined in tdns-mp
Defined at tdns-mp/v2/hsync\_utils.go as a function (not method).
Only called locally. **Not a cross-repo dependency.**

### LocalDnskeysChanged() -- locally redefined in tdns-mp
Defined at tdns-mp/v2/hsync\_utils.go. **Not a cross-repo dep.**

### RequestAndWaitForKeyInventory() -- locally redefined
Defined at tdns-mp/v2/hsync\_utils.go:275 as method on
`*MPZoneData`. **Not a cross-repo dependency.**

### RequestAndWaitForEdits() -- locally redefined
Defined at tdns-mp/v2/hsync\_utils.go:361 as package function.
**Not a cross-repo dependency.**

### RequestAndWaitForConfig() -- locally redefined
Defined at tdns-mp/v2/hsync\_utils.go. **Not a cross-repo dep.**

### RequestAndWaitForAudit() -- locally redefined
Defined at tdns-mp/v2/hsync\_utils.go. **Not a cross-repo dep.**

### MPPreRefresh() -- locally redefined
Defined at tdns-mp/v2/hsync\_utils.go:1009 as method on
`*MPZoneData`. **Not a cross-repo dependency.**

### ValidateHsyncRRset() -- zero callers
### PrintOwnerNames() -- zero callers
### PrintApexRRs() -- zero callers

---

## 3. Dependencies on legacy\_hsync\_transport.go

Source: `tdns/v2/legacy_hsync_transport.go`

**All functions are re-defined in tdns-mp/v2/hsync\_transport.go.**
The `MPTransportBridge` type and all its methods exist locally in
tdns-mp. These are NOT cross-repo dependencies.

The type `MPTransportBridgeConfig` is also locally defined.

Call sites listed for completeness (all use local definitions):

### NewMPTransportBridge -- local
| tdns-mp file | line |
|---|---|
| main\_init.go | 176, 330, 510 |

### RegisterChunkNotifyHandler -- local
| tdns-mp file | line |
|---|---|
| start\_agent.go | 55 |

### StartIncomingMessageRouter -- local
| tdns-mp file | line |
|---|---|
| start\_agent.go | 58 |
| start\_combiner.go | 54 |
| start\_signer.go | 37 |

### SendSyncWithFallback -- local
| tdns-mp file | line |
|---|---|
| apihandler\_agent.go | 983 |
| apihandler\_combiner.go | 568 |
| hsyncengine.go | 720, 978 |

### SyncPeerFromAgent -- local
| tdns-mp file | line |
|---|---|
| apihandler\_agent.go | 967 |
| hsyncengine.go | 711, 964 |

### SendHelloWithFallback -- local
| tdns-mp file | line |
|---|---|
| hsync\_hello.go | 281 |

### SendPing -- local
| tdns-mp file | line |
|---|---|
| apihandler\_agent\_distrib.go | 310 |
| apihandler\_peer.go | 226 |
| combiner\_peer.go | 155 |
| signer\_peer.go | 152 |

### SendBeatWithFallback -- local
| tdns-mp file | line |
|---|---|
| hsync\_beat.go | 112 |
| hsync\_hello.go | 215 |
| hsync\_infra\_beat.go | 81 |

### EnqueueForCombiner -- local
| tdns-mp file | line |
|---|---|
| parentsync\_leader.go | 1379 |
| start\_agent.go | 302 |
| syncheddataengine.go | 224, 322, 649, 726 |

### EnqueueForZoneAgents -- local
| tdns-mp file | line |
|---|---|
| start\_agent.go | 317 |
| syncheddataengine.go | 233, 688 |

### EnqueueForSpecificAgent -- local
| tdns-mp file | line |
|---|---|
| syncheddataengine.go | 810 |

### GetQueueStats / GetQueuePendingMessages -- local
| tdns-mp file | line |
|---|---|
| apihandler\_agent.go | 1008, 1009 |

### GetDistributionRecipients -- local
| tdns-mp file | line |
|---|---|
| syncheddataengine.go | 213 |

### TrackDnskeyPropagation -- local
| tdns-mp file | line |
|---|---|
| syncheddataengine.go | 251 |

### OnAgentDiscoveryComplete -- local
| tdns-mp file | line |
|---|---|
| agent\_utils.go | 398 |

### StartReliableQueue -- local
| tdns-mp file | line |
|---|---|
| start\_agent.go | 73 |

---

## 4. Dependencies on legacy\_agent\_authorization.go

Source: `tdns/v2/legacy_agent_authorization.go`

**All re-defined locally in tdns-mp/v2/agent\_authorization.go.**
NOT cross-repo dependencies.

| Symbol | tdns-mp file | line |
|---|---|---|
| IsPeerAuthorized | apihandler\_agent.go | 265 |
| IsPeerAuthorized | apihandler\_agent\_distrib.go | 273, 345 |
| IsPeerAuthorized | hsync\_transport.go | 332-333 |

---

## 5. Dependencies on legacy\_agent\_utils.go

Source: `tdns/v2/legacy_agent_utils.go`

**All re-defined locally in tdns-mp/v2/agent\_utils.go.**
NOT cross-repo dependencies.

| Symbol | tdns-mp file | line |
|---|---|---|
| AddZoneToAgent | agent\_utils.go | 146, 403, 507 |
| GetAgentsForZone | agent\_utils.go | 44 (def) |
| RecomputeSharedZonesAndSyncState | agent\_utils.go | 59 (def), 958 |
| NewAgentRegistry | agent\_utils.go | 97 (def) |
| NewAgentRegistry | main\_init.go | 432 |
| NewAgentRegistry | cli/agent\_debug\_cmds.go | 257 |
| LocateAgent | agent\_utils.go | 133 (def) |
| FetchSVCB | agent\_utils.go | 255, 275, 432 (def) |
| MarkAgentAsNeeded | agent\_utils.go | 495 (def), 675, 878, 903, 929 |
| DiscoverAgentAsync | apihandler\_agent.go | 274, 288, 296, 317 |
| DiscoverAgentAsync | agent\_utils.go | 665 (def) |
| GetAgentInfo | apihandler\_agent.go | 245, 285 |
| GetAgentInfo | agent\_utils.go | 679 (def), 794 |
| AddRemoteAgent | agent\_utils.go | 40, 702 (def) |
| AddRemoteAgent | cli/agent\_debug\_cmds.go | 263, 267 |
| RemoveRemoteAgent | agent\_utils.go | 714 (def), 949 |
| GetZoneAgentData | apihandler\_agent\_hsync.go | 79 |
| GetZoneAgentData | hsync\_transport.go | 1922 |
| GetZoneAgentData | hsyncengine.go | 398, 689 |
| GetZoneAgentData | parentsync\_leader.go | 1155, 1344 |
| GetZoneAgentData | start\_agent.go | 95, 231 |
| CleanupZoneRelationships | agent\_utils.go | 813 (def), 946 |
| UpdateAgents | hsyncengine.go | 259 |
| UpdateAgents | agent\_utils.go | 818 (def) |

---

## 6. Dependencies on legacy\_agent\_discovery.go

Source: `tdns/v2/legacy_agent_discovery.go`

**All re-defined locally in tdns-mp/v2/agent\_discovery.go.**
NOT cross-repo dependencies.

| Symbol | tdns-mp file | line |
|---|---|---|
| DiscoverAgentAPI | agent\_discovery.go | 44 (def) |
| DiscoverAgentAPI | agent\_utils.go | 575 |
| DiscoverAgentDNS | agent\_discovery.go | 83 (def) |
| DiscoverAgentDNS | agent\_utils.go | 578 |
| DiscoverAgent | agent\_discovery.go | 129 (def), 361 |
| RegisterDiscoveredAgent | agent\_discovery.go | 148 (def), 370 |
| RegisterDiscoveredAgent | agent\_utils.go | 607 |
| DiscoverAndRegisterAgent | agent\_discovery.go | 349 (def) |
| DiscoverAndRegisterAgent | apihandler\_agent\_distrib.go | 286, 358 |
| DiscoverAndRegisterAgent | hsync\_transport.go | 405, 584, 810 |

---

## 7. Dependencies on legacy\_agent\_discovery\_common.go

Source: `tdns/v2/legacy_agent_discovery_common.go`
Methods on `*tdns.Imr` -- these are TRUE cross-repo dependencies.

### Imr.LookupAgentAPIEndpoint()
| tdns-mp file | line | usage |
|---|---|---|
| agent\_discovery.go | 47 | `imr.LookupAgentAPIEndpoint(ctx, identity)` |

### Imr.LookupServiceAddresses()
| tdns-mp file | line | usage |
|---|---|---|
| agent\_discovery.go | 54 | `imr.LookupServiceAddresses(ctx, apiServiceName)` |
| agent\_discovery.go | 92 | `imr.LookupServiceAddresses(ctx, dnsServiceName)` |

### Imr.LookupAgentTLSA()
| tdns-mp file | line | usage |
|---|---|---|
| agent\_discovery.go | 63 | `imr.LookupAgentTLSA(ctx, apiServiceName, apiPort)` |

### Imr.LookupAgentDNSEndpoint()
| tdns-mp file | line | usage |
|---|---|---|
| agent\_discovery.go | 86 | `imr.LookupAgentDNSEndpoint(ctx, identity)` |

### Imr.LookupAgentJWK()
| tdns-mp file | line | usage |
|---|---|---|
| agent\_discovery.go | 101 | `imr.LookupAgentJWK(ctx, identity)` |

### Imr.LookupAgentKEY()
| tdns-mp file | line | usage |
|---|---|---|
| agent\_discovery.go | 111 | `imr.LookupAgentKEY(ctx, identity)` |

---

## 8. Dependencies on legacy\_hsync\_beat.go

Source: `tdns/v2/legacy_hsync_beat.go`

**All re-defined locally in tdns-mp/v2/hsync\_beat.go.**
NOT cross-repo dependencies.

| Symbol | tdns-mp file | line |
|---|---|---|
| HeartbeatHandler | hsyncengine.go | 105 |
| SendHeartbeats | hsyncengine.go | 118 |
| CheckState | hsync\_beat.go | 159 |
| SendApiBeat | hsync\_beat.go | 119, 250 (def) |

---

## 9. Dependencies on legacy\_hsync\_hello.go

Source: `tdns/v2/legacy_hsync_hello.go`

**All re-defined locally in tdns-mp/v2/hsync\_hello.go.**
NOT cross-repo dependencies.

| Symbol | tdns-mp file | line |
|---|---|---|
| HelloHandler | hsyncengine.go | 102 |
| HelloRetrier | hsync\_hello.go | 50 (def) |
| HelloRetrierNG | hsync\_hello.go | 72 (def) |
| HelloRetrierNG | agent\_utils.go | 417, 658 |
| FastBeatAttempts | hsync\_hello.go | 106, 117, 138, 174 (def) |
| SingleHello | hsync\_hello.go | 55, 168, 271 (def) |
| EvaluateHello | hsync\_hello.go | 323 (def) |
| EvaluateHello | apihandler\_agent.go | 1113 |
| SendApiHello | hsync\_hello.go | 292, 375 (def) |
| SendApiHello | apihandler\_agent.go | 329 |

---

## 10. Dependencies on legacy\_hsyncengine.go

Source: `tdns/v2/legacy_hsyncengine.go`

**All re-defined locally in tdns-mp/v2/hsyncengine.go.**
NOT cross-repo dependencies.

| Symbol | tdns-mp file | line |
|---|---|---|
| HsyncEngine | start\_agent.go | 332-333 |
| DiscoveryRetrierNG | hsyncengine.go | 195 (def) |
| DiscoveryRetrierNG | start\_agent.go | 338-339 |
| SyncRequestHandler | hsyncengine.go | 99, 177, 252 (def) |
| MsgHandler | hsyncengine.go | 108, 368 (def) |
| CommandHandler | hsyncengine.go | 111, 115, 647 (def) |
| CommandHandler | agent\_utils.go | 896, 921 |
| HandleStatusRequest | hsyncengine.go | 121, 998 (def) |
| SendApiMsg | hsyncengine.go | 733, 991, 1031 (def) |

---

## 11. Dependencies on legacy\_combiner\_chunk.go

Source: `tdns/v2/legacy_combiner_chunk.go`

**Most re-defined locally in tdns-mp/v2/combiner\_chunk.go.**
NOT cross-repo dependencies except where noted.

| Symbol | tdns-mp file | line | cross-repo? |
|---|---|---|---|
| RegisterCombinerChunkHandler | main\_init.go | 308 | no (local) |
| RegisterSignerChunkHandler | main\_init.go | 207 | no (local) |
| ChunkHandler() getter | main\_init.go | 214, 399 | no (local) |
| SetRouter | main\_init.go | 231, 415 | no (local) |
| SetGetPeerAddress | main\_init.go | 389 | no (local) |
| NewCombinerSyncHandler | main\_init.go | 406 | no (local) |
| CombinerProcessUpdate | apihandler\_combiner.go | 198 | no (local) |
| CombinerProcessUpdate | combiner\_msg\_handler.go | 229 | no (local) |
| ProcessUpdate (on ZDR) | syncheddataengine.go | 199, 305 | no (local) |
| IsNoOpOperations | combiner\_msg\_handler.go | 163 | no (local) |
| RecordCombinerError | combiner\_msg\_handler.go | 236 | no (local) |
| SendToCombiner | combiner\_chunk.go | 1401 (def) | no (local) |
| ConvertZoneUpdateToSyncRequest | combiner\_chunk.go | 1449 (def) | no (local) |
| ParseAgentMsgNotify | (not found) | -- | dead |

---

## 12. Dependencies on legacy\_combiner\_utils.go

Source: `tdns/v2/legacy_combiner_utils.go`

**Most re-defined locally in tdns-mp/v2/combiner\_utils.go.**

| Symbol | tdns-mp file | line | cross-repo? |
|---|---|---|---|
| RegisterProviderZoneRRtypes | main\_init.go | 286 | no (local) |
| GetProviderZoneRRtypes | combiner\_chunk.go | 225, 652, 844 | no (local) |
| GetProviderZoneRRtypes | config.go | 152 | no (local) |
| CombineWithLocalChanges | config.go | 143 | **YES** -- method on `*tdns.ZoneData` |
| CombineWithLocalChanges | hsync\_utils.go | 1132 | **YES** -- via MPZoneData wrapper |
| RebuildCombinerData | apihandler\_combiner.go | 391, 400 | **YES** -- method on `*tdns.ZoneData` |
| RebuildCombinerData | config.go | 137 | **YES** -- method on `*tdns.ZoneData` |
| AddCombinerDataNG | apihandler\_combiner.go | 56 | **YES** -- method on `*tdns.ZoneData` |
| AddCombinerDataNG | combiner\_chunk.go | 1005 | **YES** -- via MPZoneData |
| GetCombinerDataNG | apihandler\_combiner.go | 70 | **YES** -- method on `*tdns.ZoneData` |
| RemoveCombinerDataNG | combiner\_chunk.go | 1034 | **YES** -- via MPZoneData |
| ReplaceCombinerDataByRRtype | combiner\_chunk.go | 387, 401, 497, 525, 527, 630, 759, 959, 965 | **YES** -- via MPZoneData |
| InjectSignatureTXT | hsync\_utils.go | 1139 | **YES** -- via MPZoneData |
| AddCombinerData | (not found in callers) | -- | dead? |
| RemoveCombinerDataByRRtype | (not found in callers) | -- | dead? |
| CombinerReapplyContributions | apihandler\_combiner.go | 334 | no (local pkg func) |

**These combiner\_utils methods on `*tdns.ZoneData` are the largest
remaining cluster of true cross-repo dependencies.** They access
`zd.MultiProviderData` fields directly.

---

## 13. Dependencies on legacy\_db\_combiner\_edits.go

Source: `tdns/v2/legacy_db_combiner_edits.go`

**All re-defined locally (operate on local HsyncDB type).**
NOT cross-repo dependencies.

| Symbol | tdns-mp file | line |
|---|---|---|
| NextEditID | combiner\_msg\_handler.go | 136 |
| SavePendingEdit | combiner\_msg\_handler.go | 151 |
| ResolvePendingEdit | combiner\_msg\_handler.go | 168, 268 |
| ListPendingEdits | apihandler\_combiner.go | 141 |
| ApprovePendingEdit | apihandler\_combiner.go | 157 |
| RejectPendingEdit | apihandler\_combiner.go | 234 |
| ListApprovedEdits | apihandler\_combiner.go | 275 |
| ListRejectedEdits | apihandler\_combiner.go | 286 |
| ClearPendingEdits | apihandler\_combiner.go | 355 |
| ClearApprovedEdits | apihandler\_combiner.go | 363 |
| ClearRejectedEdits | apihandler\_combiner.go | 371 |
| ClearContributions | apihandler\_combiner.go | 379 |

---

## 14. Dependencies on legacy\_db\_combiner\_contributions.go

Source: `tdns/v2/legacy_db_combiner_contributions.go`

**Re-defined locally (operate on local HsyncDB type).**

| Symbol | tdns-mp file | line |
|---|---|---|
| LoadAllContributions | combiner\_utils.go | 829 |
| LoadAllContributions | config.go | 99 |
| SaveContributions | config.go | 127 |

---

## 15. Dependencies on legacy\_db\_combiner\_publish\_instructions.go

Source: `tdns/v2/legacy_db_combiner_publish_instructions.go`

**Re-defined locally (operate on local HsyncDB type).**

| Symbol | tdns-mp file | line |
|---|---|---|
| GetPublishInstruction | combiner\_chunk.go | 493, 568 |
| DeletePublishInstruction | combiner\_chunk.go | 504 |
| SavePublishInstruction | combiner\_chunk.go | 555, 596 |
| ToPublishInstruction | combiner\_chunk.go | 595 |
| LoadAllPublishInstructions | combiner\_chunk.go | 702 |
| LoadAllPublishInstructions | combiner\_utils.go | 851, 893 |

---

## 16. Dependencies on legacy\_gossip.go

Source: `tdns/v2/legacy_gossip.go`

**All re-defined locally in tdns-mp/v2/gossip.go.**
NOT cross-repo dependencies.

| Symbol | tdns-mp file | line |
|---|---|---|
| NewGossipStateTable | agent\_utils.go | 123 |
| SetOnGroupOperational | hsyncengine.go | 32 |
| SetOnGroupDegraded | hsyncengine.go | 62 |
| SetOnElectionUpdate | hsyncengine.go | 69 |
| MergeGossip | hsync\_beat.go | 34 |
| MergeGossip | hsync\_transport.go | 669, 1630 |
| CheckGroupState | hsync\_beat.go | 42, 64 |
| CheckGroupState | hsync\_transport.go | 678, 1634 |
| RefreshLocalStates | hsync\_beat.go | 57 |
| GetGroupState | apihandler\_gossip.go | 74 |
| BuildGossipForPeer | hsync\_transport.go | 420, 1543 |
| UpdateLocalState | gossip.go | 361 |
| GetGroupElectionState | gossip.go | 188 |

---

## 17. Dependencies on legacy\_provider\_groups.go

Source: `tdns/v2/legacy_provider_groups.go`

**All re-defined locally in tdns-mp/v2/provider\_groups.go.**
NOT cross-repo dependencies.

| Symbol | tdns-mp file | line |
|---|---|---|
| NewProviderGroupManager | agent\_utils.go | 122 |
| ComputeGroupHash | provider\_groups.go | 114 |
| RecomputeGroups | agent\_utils.go | 978 |
| GetGroups | agent\_utils.go | 979 |
| GetGroups | apihandler\_gossip.go | 148 |
| GetGroup | apihandler\_gossip.go | 66 |
| GetGroup | hsync\_beat.go | 40 |
| GetGroup | hsync\_transport.go | 676, 1632 |
| GetGroup | hsyncengine.go | 38 |
| GetGroup | parentsync\_leader.go | 171, 554, 709 |
| GetGroupByName | apihandler\_gossip.go | 64 |
| GetGroupForZone | agent\_utils.go | 969 |
| GetGroupForZone | apihandler\_agent.go | 441 |
| GetGroupForZone | parentsync\_leader.go | 602, 678, 751, 825, 1077, 1220 |
| GetGroupForZone | start\_agent.go | 185 |

---

## 18. Dependencies on legacy\_parentsync\_leader.go

Source: `tdns/v2/legacy_parentsync_leader.go`

**All re-defined locally in tdns-mp/v2/parentsync\_leader.go.**
NOT cross-repo dependencies.

| Symbol | tdns-mp file | line |
|---|---|---|
| NewLeaderElectionManager | start\_agent.go | 84 |
| SetProviderGroupManager | start\_agent.go | 131 |
| SetOperationalPeersFunc | start\_agent.go | 94 |
| SetConfiguredPeersFunc | start\_agent.go | 109 |
| SetOnLeaderElected | start\_agent.go | 199 |
| StartGroupElection | apihandler\_agent.go | 443 |
| StartGroupElection | hsyncengine.go | 56 |
| DeferGroupElection | agent\_utils.go | 971 |
| DeferGroupElection | start\_agent.go | 187 |
| HandleGroupMessage | hsyncengine.go | 519 |
| HandleMessage | hsyncengine.go | 521 |
| GetGroupLeader | parentsync\_leader.go | 680 |
| GetLeader | parentsync\_leader.go | 687 |
| InvalidateGroupLeader | hsyncengine.go | 66 |
| GetGroupElectionState | apihandler\_gossip.go | 106 |
| ApplyGossipElection | hsyncengine.go | 72 |
| StartElection | agent\_utils.go | 967 |
| StartElection | apihandler\_agent.go | 459 |
| StartElection | start\_agent.go | 182 |
| DeferElection | start\_agent.go | 191 |
| NotifyPeerOperational | hsync\_transport.go | 659 |
| IsLeader | apihandler\_agent.go | 498 |
| IsLeader | delegation\_sync.go | 77, 118 |
| IsLeader | hsyncengine.go | 132 |
| IsLeader | parentsync\_bootstrap.go | 21 |
| GetAllLeaders | apihandler\_agent\_distrib.go | 196 |
| GetPendingElections | apihandler\_agent\_distrib.go | 209 |
| GetParentSyncStatus | apihandler\_agent.go | 427 |
| Sig0KeyOwnerName | combiner\_chunk.go | 606, 716 |
| Sig0KeyOwnerName | combiner\_utils.go | 863 |
| Sig0KeyOwnerName | parentsync\_leader.go | 1300 |
| PublishKeyToCombiner | parentsync\_leader.go | 1370 (def) |

---

## 19. Dependencies on legacy\_signer\_msg\_handler.go

**Re-defined locally in tdns-mp/v2/signer\_msg\_handler.go.**
NOT a cross-repo dependency.

| Symbol | tdns-mp file | line |
|---|---|---|
| SignerMsgHandler | start\_signer.go | 40-41 |

---

## 20. Dependencies on legacy\_apihandler\_transaction.go

**Re-defined locally.** NOT cross-repo dependencies.

| Symbol | tdns-mp file | line |
|---|---|---|
| APIcombinerTransaction | apihandler\_combiner\_routes.go | 30 |
| APIagentTransaction | apihandler\_agent\_routes.go | 22 |

---

## 21. Type Aliases in tdns-mp/v2/types.go

These are `= tdns.Foo` aliases that create dependencies on type
definitions in tdns/v2/mptypes.go (and some non-legacy files):

| Alias | Source type | tdns-mp file:line |
|---|---|---|
| CombinerPost | tdns.CombinerPost | types.go:17 |
| CombinerResponse | tdns.CombinerResponse | types.go:18 |
| CombinerEditPost | tdns.CombinerEditPost | types.go:19 |
| CombinerEditResponse | tdns.CombinerEditResponse | types.go:20 |
| CombinerDebugPost | tdns.CombinerDebugPost | types.go:21 |
| CombinerDebugResponse | tdns.CombinerDebugResponse | types.go:22 |
| CombinerDistribPost | tdns.CombinerDistribPost | types.go:23 |
| CombinerSyncRequest | tdns.CombinerSyncRequest | types.go:36 |
| CombinerSyncResponse | tdns.CombinerSyncResponse | types.go:37 |
| RejectedItem | tdns.RejectedItem | types.go:38 |
| CombinerSyncRequestPlus | tdns.CombinerSyncRequestPlus | types.go:39 |
| PendingEditRecord | tdns.PendingEditRecord | types.go:42 |
| ApprovedEditRecord | tdns.ApprovedEditRecord | types.go:43 |
| RejectedEditRecord | tdns.RejectedEditRecord | types.go:44 |
| CombinerOption | tdns.CombinerOption | types.go:47 |
| KeyInventoryItem | tdns.KeyInventoryItem | types.go:52 |
| DnssecKeyWithTimestamps | tdns.DnssecKeyWithTimestamps | types.go:53 |
| AgentId | tdns.AgentId | types.go:56 |
| ZoneName | tdns.ZoneName | types.go:57 |
| ZoneUpdate | tdns.ZoneUpdate | types.go:58 |
| OwnerData | tdns.OwnerData | types.go:59 |
| CombinerState | tdns.CombinerState | types.go:65 |
| TransactionPost | tdns.TransactionPost | types.go:68 |
| TransactionResponse | tdns.TransactionResponse | types.go:69 |
| TransactionSummary | tdns.TransactionSummary | types.go:70 |
| TransactionErrorSummary | tdns.TransactionErrorSummary | types.go:71 |

Plus 5 aliases in agent\_structs.go:349-353 (HsyncPeerInfo, etc.)
Plus 5 aliases in sde\_types.go:175-206 (SyncRequest, etc.)

**Note**: `AgentId`, `ZoneName`, `OwnerData`, `ZoneUpdate` are
pervasive and deeply embedded. These will likely be the last
aliases to migrate.

---

## 22. Direct `tdns.` Type References (not via alias)

These are places where code uses `tdns.TypeName` directly:

| Type | tdns-mp file | lines |
|---|---|---|
| tdns.Agent | db\_hsync.go:480 |
| tdns.Agent | cli/hsync\_cmds.go:532 |
| tdns.Agent | cli/agent\_debug\_cmds.go:259,263,267 |
| tdns.AgentDetails | cli/hsync\_cmds.go:543 |
| tdns.AgentState (constants) | db\_hsync.go:587-601 |
| tdns.AgentStateToString | cli/hsync\_cmds.go:533,554 |
| tdns.AgentMgmtPost | cli/ (many files, 30+ refs) |
| tdns.AgentMgmtResponse | cli/ (many files, 15+ refs) |
| tdns.AgentMsgNotify | cli/agent\_debug\_cmds.go:60 |
| tdns.AgentMsgRfi | combiner\_msg\_handler.go:117 |
| tdns.AgentMsgRfi | cli/agent\_debug\_cmds.go:93 |
| tdns.AgentMsgRfi | cli/agent\_cmds.go:219 |
| tdns.ZoneUpdate | start\_agent.go:290,309 |
| tdns.ZoneUpdate | combiner\_chunk.go:1449,1485 |
| tdns.ZoneUpdate | hsync\_transport.go:1719,1798,1823,1859 |
| tdns.CombinerState | main\_init.go:443 |
| tdns.CombinerState | combiner\_chunk.go:1366-1367,1401 |
| tdns.CombinerState | signer\_chunk\_handler.go:23-24 |
| tdns.CombinerSyncRequest | combiner\_chunk.go:1413-1414 |
| tdns.DnskeyStatus | hsync\_utils.go:85-86,159,164,185 |
| tdns.HsyncStatus | hsync\_utils.go:22-23 |
| tdns.SyncRequest | apihandler\_agent.go:361 |
| tdns.SyncRequest | hsync\_utils.go:1177,1194 |
| tdns.OwnerData | combiner\_utils.go:144,186,661,722,947,972,975 |
| tdns.OwnerData | mp\_extension.go:25-26 |
| tdns.OwnerData | hsync\_utils.go:974,978 |
| tdns.HsyncPeerInfo | db\_hsync.go:634-635 |
| tdns.HsyncSyncOpInfo | db\_hsync.go:659-660 |
| tdns.HsyncConfirmationInfo | db\_hsync.go:679-680 |
| tdns.HsyncTransportEvent | db\_hsync.go:829,861,863 |
| tdns.HsyncMetricsInfo | db\_hsync.go:885,889,925 |
| tdns.CombinerDebugPost | apihandler\_combiner\_mp.go:21 |
| tdns.CombinerDebugResponse | apihandler\_combiner\_mp.go:31 |
| tdns.CombinerDebugPost | apihandler\_signer.go:20 |
| tdns.CombinerDebugResponse | apihandler\_signer.go:30 |

---

## Summary: TRUE Cross-Repo Dependencies

**Updated 2026-04-14** after the MP field migration.

After filtering out all the locally-redefined functions (which are
NOT cross-repo calls), the actual dependencies from tdns-mp into
tdns/v2 legacy code are:

### A. Methods on `*tdns.ZoneData` (defined in mpmethods.go) -- RESOLVED

~~EnsureMP, Get/SetLastKeyInventory, Get/SetKeystateOK,
Get/SetKeystateError, Get/SetKeystateTime~~ (was 46 call sites)

**Status**: All migrated to `*MPZoneData` receiver methods in
`tdns-mp/v2/mp_extension.go`. `Zones.Get()` returns `*MPZoneData`,
so all call sites resolve to the local implementations. The
`mpzd.MP` field (local `MPState`) shadows the promoted
`tdns.ZoneData.MP`, ensuring all field accesses go through the
local type. **Zero cross-repo method calls remain.**

The tdns/v2/mpmethods.go definitions still exist but are unused
by tdns-mp. They can be deleted once tdns/v2 itself no longer
needs them (i.e. when legacy\_\*.go files are removed).

### B. Methods on `*tdns.ZoneData` (legacy\_hsync\_utils.go) -- RESOLVED

~~LocalDnskeysFromKeystate~~ (was 4 call sites)

**Status**: Migrated to `*MPZoneData` receiver method in
`tdns-mp/v2/hsync_utils.go`. All call sites use the local
version. **Zero cross-repo method calls remain.**

### C. Methods on `*tdns.ZoneData` (legacy\_combiner\_utils.go) -- RESOLVED

~~CombineWithLocalChanges, RebuildCombinerData, AddCombinerDataNG,
GetCombinerDataNG, RemoveCombinerDataNG, ReplaceCombinerDataByRRtype,
InjectSignatureTXT~~ (was 19 call sites)

**Status**: All 7 methods are now self-contained receiver methods
on `*MPZoneData` in `tdns-mp/v2/combiner_utils.go`. They operate
on `mpzd.MP` (local `MPState`), not on the promoted
`tdns.ZoneData.MultiProviderData`. `CombineWithLocalChanges` is
an enhanced reimplementation with role-based filtering.
**Zero cross-repo method calls remain.**

The only remaining reference to tdns from these methods is
`tdns.Conf.MultiProvider` (a config global, not a method
dependency).

### D. Methods on `*tdns.Imr` (legacy\_agent\_discovery\_common.go) -- RESOLVED

~~LookupAgentAPIEndpoint, LookupAgentDNSEndpoint, LookupAgentJWK,
LookupAgentKEY, LookupAgentTLSA, LookupServiceAddresses~~
(was 7 call sites)

**Status**: All 6 methods migrated to `*tdnsmp.Imr` receiver
methods in `tdns-mp/v2/agent_discovery_common.go`. The
`tdnsmp.Imr` type embeds `*tdns.Imr`, so core methods
(`ImrQuery`, `Cache`, etc.) promote through. The 3 standalone
discovery functions (`DiscoverAgentAPI`, `DiscoverAgentDNS`,
`DiscoverAgent`) were also converted to `*Imr` receivers.
The tdns/v2 file was renamed to `deadcode_agent_discovery_common.go`.
**Zero cross-repo method calls remain.**

See `2026-04-14-imr-embedding-plan.md` for full details.

### E. Type aliases in types.go (26 aliases) -- STILL ACTIVE

All 26 type aliases remain in `tdns-mp/v2/types.go`, plus
5 in `agent_structs.go` and 5 in `sde_types.go`. See
section 21 above.

### F. Direct tdns.Type references (many) -- STILL ACTIVE

See section 22 above. These include `tdns.AgentMgmtPost`,
`tdns.AgentMgmtResponse`, `tdns.ZoneUpdate`, `tdns.OwnerData`,
`tdns.CombinerState`, etc. scattered across tdns-mp/v2 and
tdns-mp/v2/cli/.

---

## Implications for Cleanup (updated)

1. **deadcode\_\*.go files**: Safe to delete immediately. Zero
   callers anywhere.

2. **Most legacy\_\*.go files**: The functions have been copied to
   tdns-mp. The tdns/v2 copies are dead code WITHIN tdns/v2.
   However, they cannot be deleted until the tdns/v2 build no
   longer references their types. Since the functions reference
   types from mptypes.go, deleting mptypes.go would cascade
   into compile errors in the legacy files. But since the legacy
   files are also being deleted, this is a non-issue -- delete
   them together.

3. **mpmethods.go**: All methods that tdns-mp called have been
   migrated. mpmethods.go is only still needed if legacy\_\*.go
   files in tdns/v2 reference it. Once those legacy files are
   deleted, mpmethods.go can be deleted too.

4. **legacy\_hsync\_utils.go**: `LocalDnskeysFromKeystate()` has
   been migrated. No longer a cross-repo dependency.

5. **legacy\_combiner\_utils.go**: All 7 combiner data methods
   have been migrated to self-contained `*MPZoneData` methods.
   No longer a cross-repo dependency.

6. **legacy\_agent\_discovery\_common.go**: DONE. All 6
   Imr.Lookup\* methods migrated to `*tdnsmp.Imr` receivers.
   File renamed to `deadcode_agent_discovery_common.go`.
   **No cross-repo method dependencies remain.**

7. **mptypes.go + type aliases**: The 26 type aliases in
   types.go (plus ~10 more in agent\_structs.go and
   sde\_types.go) are the **primary remaining coupling**. Each
   alias must be converted to a local struct definition to
   fully decouple tdns-mp from tdns/v2 MP types.

8. **Direct tdns.Type references**: Beyond aliases, tdns-mp
   code directly uses `tdns.AgentMgmtPost`,
   `tdns.AgentMgmtResponse`, `tdns.ZoneUpdate`,
   `tdns.OwnerData`, `tdns.CombinerState`, and many others.
   These are the deepest coupling and will be the last to
   migrate.

9. **Sequencing**: The method migration is complete. What
   remains is:
   (a) Rename legacy\_agent\_discovery\_common.go (trivial).
   (b) Convert type aliases to local struct definitions.
   (c) Eliminate direct tdns.Type references.
   (d) Delete legacy\_\*.go + mpmethods.go + mptypes.go from
       tdns/v2 (all at once, since they reference each other).
