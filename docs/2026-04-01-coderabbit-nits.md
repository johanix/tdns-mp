# CodeRabbit Nits — tdns-mp/v2 Issues

Issues identified via CodeRabbit review that exist in tdns-mp/v2/
files. The corresponding tdns/v2/legacy_* versions have been
fixed; these tdns-mp copies still need the same fixes applied.

## 1. hsync_utils.go: Boolean return values discarded

**File**: `v2/hsync_utils.go`, lines ~973, ~981
**Severity**: Medium

`LocalDnskeysFromKeystate()` and `LocalDnskeysChanged()` return
`(bool, *DnskeyStatus, error)` but the boolean is discarded
with `_`. This means `dnskeyschanged` retains the value from
the earlier `DnskeysChangedNG` call rather than reflecting
the keystate-based analysis.

**Fix**: Change `_, analysis.DnskeyStatus, err =` to
`dnskeyschanged, analysis.DnskeyStatus, err =` at both sites.

## 2. hsync_utils.go: Combiner contributions lost on refresh

**File**: `v2/hsync_utils.go`, lines ~1027-1048
**Severity**: HIGH

The combiner path calls `new_zd.CombineWithLocalChanges()`
without first copying `zd.MP.AgentContributions` and
`zd.MP.CombinerData` onto `new_zd`. Since `new_zd` comes from
a fresh zone load with an empty MP struct, all accumulated
contributions are lost during zone refresh.

**Fix**: Before `CombineWithLocalChanges()`, copy contributions:
```go
new_zd.EnsureMP()
if zd.MP.AgentContributions != nil {
    new_zd.MP.AgentContributions = zd.MP.AgentContributions
}
if zd.MP.CombinerData != nil {
    new_zd.MP.CombinerData = zd.MP.CombinerData
}
```

## 3. signer_msg_handler.go: context.Background() in keystate sends

**File**: `v2/signer_msg_handler.go`, line ~228
**Severity**: Low

`sendKeystateInventoryToAgent` creates a timeout from
`context.Background()` instead of accepting a caller-provided
context. This prevents shutdown signals from cancelling
KEYSTATE sends.

**Fix**: Accept `ctx context.Context` as first parameter and
derive the timeout from it instead of `context.Background()`.

## 4. cli/agent_debug_cmds.go: log.Fatalf in closure

**File**: `v2/cli/agent_debug_cmds.go`, line ~594
**Severity**: Low

The closure in `DebugAgentQueueStatusCmd` calls `log.Fatalf`
on API client error, killing the process instead of returning
an error.

**Fix**: Replace `log.Fatalf(...)` with
`return nil, nil, fmt.Errorf(...)` so the error propagates
to the caller.
