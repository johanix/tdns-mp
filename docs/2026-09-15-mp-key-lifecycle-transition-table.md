# The multi-provider key lifecycle as a transition table

**Status:** implemented, and kept current with the code (r11): S3's state machine as merged in tdns-mp #76, with the lab findings of #82 (r8), the foreign rows of #83 (r9) and what the leader is asked of #86. It began as the spec of S3's state machine, written before its code, as §3.4's table was for S1b (design `docs/2026-09-13-key-lifecycle-ownership-design.md`, test plan `docs/2026-09-14-key-lifecycle-ownership-test-plan.md` T3.1).
**Scope:** one provider's view of one owned zone: its own keys, and what it records of the other providers' keys. tdns keeps the keystore, signs from `sign=1`, serves `pub=1`, publishes CDS and pushes DS from the owner's DS intent (from S5). tdns-mp writes state and the three columns at every transition, through tdns's write function.

## Revision history

| Rev | Date | Change |
|---|---|---|
| r1 | 2026-09-15 | First version, from design §3.4 (tdns-mp's states), §5, tdns-mp #57 and #58, and the machine tdns-mp runs through the hooks today (mpdist, mpremove, foreign, the propagation record). |
| r2 | 2026-09-15 | T9's guard admits a same-algorithm rollover: the active key retires in the same step, so P5 holds after it. Found by the driver's rollover test. |
| r3 | 2026-09-15 | From the harness's seeded runs: a rejection sticks to a distribution (G1, P8); E12, a resend timer, with T6' (P6 under message loss); E10 catches a joining signer up with a record it must confirm before the key may sign (T9), and its rejection of a served key is reported and left to the operator's retry or withdraw (T6, T7', T7''); the distributions in flight are persisted, so a restart resumes them and never re-sends a rejected one (T15). |
| r4 | 2026-09-15 | From more seeded runs (T3.3): a rejection sticks to a served key's record too, so a standby key a signer that joined rejected is not promoted (T9, P1) until retried or withdrawn; a retry on a key being removed sends the removal again (T6); an answer to a key's distribution that arrives after its removal went out is stale and refused (§3, after the table). |
| r5 | 2026-09-16 | From the S3 review: T1 also mints for a rollover requested with nothing in the pipeline (T16 with a standby count of 0, the default for KSKs); the RRSIGs are stripped before the row enters mpremove, so a strip that fails leaves the row where it was; an aggregated confirmation counts for the signers the record expects, and one that answers a distribution sent before the record's is stale; a retired KSK whose DS the parent goes on serving is reported after three margins (the withdrawal at the parent is S5's); the withdrawal margin is the owner's, not the clamp's; the machine runs multi-provider zones this provider signs, no other. |
| r6 | 2026-09-16 | From the re-review: the body now says what r5's row promised (T7 strips before the row moves; T16 names T1's mint for a standby count of 0); a resend keeps the record's first send time (T6'), and the staleness rule is by that time with a tolerance for the agent's clock, beside the kind. |
| r7 | 2026-09-16 | From the re-re-review: the aggregated signal names the kind of distribution it answers ("propagated" a key's, "removed" its removal), so an answer of the other kind than the record's is stale whatever the times say; the time rule stays beside it. |
| r8 | 2026-09-17 | From the lab run of S3 and S5's first half and its review (tdns-mp #82): what the agent reads out of a confirmation, E3 and O5. An "ignored" answer is final: from a provider that does not sign the zone it is no obstacle (its combiner applies no key of ours), from a signing provider it is a rejection (the two sides disagree about who signs). A success covers every key of the distribution that is not rejected: the combiner's `ok` says the whole REPLACE is in effect, and the `done` list is the delta, so a key it does not list was already there; a partial answer still counts only the keys it lists. O6: a zone taken with keys tdns minted. |
| r9 | 2026-09-17 | §3's foreign rows as implemented with tdns-mp #58 (Q9 decided): where a provider's word comes from, the rule that writes `ds` from it, and when it runs. |
| r10 | 2026-09-17 | Status: implemented, not a proposal. No rule changed. |
| r11 | 2026-09-17 | E7 names its observer. Found while preparing the testbed run of S5: the machine asked the signer's resolver, and the signer started none, so E7 never came and T11 never fired anywhere. A signer that owns a zone now starts a resolver (tdns-mp #87). No rule changed. |

## 1. States and columns

The columns are the design's §3.4 table for tdns-mp's states. A ZSK has `ds=0` in every state. "KSK" below means a key with the SEP bit.

| state | pub | sign | ds (KSK) | meaning |
|---|---|---|---|---|
| created | 0 | 0 | 0 | minted, not yet sent to the peers |
| mpdist | 1 | 0 | 0 | in this provider's RRset, distributed, not yet applied by every signing provider |
| published | 1 | 0 | 0 | applied by every signing provider, the RRset not yet propagated |
| standby | 1 | 0 | 1 | propagated: may be promoted; its DS belongs at the parent |
| active | 1 | 1 | 1 | signs |
| retired | 1 | 0 | 1, then 0 | no longer signs; its DS is withdrawn during this state |
| mpremove | 0 | 0 | 0 | out of the RRset, the removal distributed, awaiting the peers |
| removed | 0 | 0 | 0 | history |
| foreign | 1 | 0 | per D4 | another provider's DNSKEY, served here, never signing; `ds=1` only while its provider signs the zone and holds it standby, active or retired-not-withdrawn; NULL until that provider says (#58) |

## 2. Events

| id | event | source |
|---|---|---|
| E1 | mint | the policy's standby count, a lifetime due, a rollover requested, or no active key of a role |
| E2 | distributed | the agent sent the DNSKEY (a REPLACE of this provider's DNSKEYs) to the peers |
| E3 | applied | a signing provider's final confirmation that its combiner applied the key (#57: "pending" is not this; "partial" counts only if the key is among the applied items; a success counts for every key of the distribution it does not reject, listed or not: the list is what changed, and an unlisted key was already there, r8) |
| E4 | rejected | a signing provider's rejection; also a signing provider's "ignored": its combiner does not take this provider for a signer, so the key is not there (r8) |
| E5 | propagated | propagation delay plus the served DNSKEY TTL have passed since `published` (the clock is injectable, T3.0) |
| E6 | promote | the rollover fires: scheduled, or requested now |
| E7 | DS gone | the parent no longer serves the key's DS: observed by the signer's own resolver, which a signer starts when it owns a zone (`imrengine:` in its config says how it resolves; `active: false` turns it off). No resolver, a resolver not ready yet, or a lookup that fails is "unknown": the key waits, and the machine reports that it needs the operator (r11) |
| E8 | margin | the withdrawal margin has passed since `retired` lost `sign`: every RRSIG by the key has expired from caches |
| E9 | removal applied | every signing provider confirmed the removal |
| E10 | signers changed | the zone's HSYNCPARAM signers set changed: a signing provider joined or left |
| E11 | restart | the process starts and reloads the keystore |
| E12 | resend | a distribution has waited for confirmations longer than the policy's resend interval |
| C1 | retry | command: distribute a stuck key again |
| C2 | withdraw | command: give up on a key |
| C3 | rollover now / cancel | command |

## 3. Transitions

Each row: the state a key is in, the event, the guard that must hold, the next state with its columns, and what else happens. A row that is not here is "no change, log".

| # | from | event | guard | to | side effects |
|---|---|---|---|---|---|
| T1 | — | E1 mint | fewer keys of the role in created..standby than the policy's standby count, or a lifetime due, or no active key of the role, or a rollover requested (C3) with no key of the role in created..standby | created (0,0,0) | key generated through tdns's keystore (`GenerateKeypair` with the state and columns named) |
| T2 | created | E2 distributed | the key is in this provider's served RRset | mpdist (1,0,0) | the distribution recorded with the set of signing providers expected to confirm |
| T3 | mpdist | E3 applied | every signing provider other than this one has confirmed applied, and none rejected (G1) | published (1,0,0) | `published_at` stamped |
| T3' | mpdist | E2 distributed | no other signing provider (G2, §5.5) | published (1,0,0) | as T3, at once |
| T4 | mpdist | E3 with status pending | — | mpdist | nothing (P9) |
| T5 | mpdist | E4 rejected | — | mpdist | the rejection recorded and surfaced: log, zone status, CLI (P8); no automatic retreat |
| T6 | any key with a distribution in flight | C1 retry | — | same | a fresh distribution: the expected set recomputed from the current signers, the rejection forgotten. On a key already serving it is the record a signer that joined must confirm; on a key in mpremove it is the removal sent again |
| T6' | any state with a distribution in flight | E12 resend | a confirmation is outstanding and nobody rejected | same | the distribution sent again (a removal, or a served key a joiner has yet to apply, included); the confirmations received stay, and so does the record's first send time (the answer to the first send is not stale); the timer runs from the last send |
| T7 | mpdist | C2 withdraw | — | mpremove (0,0,0) | the key's RRSIGs stripped first (a strip that fails leaves the row where it is), then the removal distributed |
| T7', T7'' | published, standby | C2 withdraw | — | mpremove (0,0,0) | a served key given up on, a signer that joined having rejected it, say: the removal distributed. An active key is not withdrawn; it is rolled |
| T8 | published | E5 propagated | (G3) | standby (1,0, KSK 1) | a KSK's `ds=1` is what puts its DS into the zone's DS set (D4) |
| T9 | standby | E6 promote | the key is standby (P1, P2); its distribution is complete: every signer expected has applied it (a signer that joined since included) and none rejected it; and no other key of the role and algorithm is active on this provider, or the promotion is a rollover (requested or due: the active key goes T10 in the same step), or an algorithm rollover is in flight (P5) | active (1,1, KSK 1) | the previous active key of the role goes T10; resign asked of tdns |
| T10 | active | E6 promote (of its successor) | — | retired (1,0, KSK 1) | `retired_at` stamped |
| T11 | retired (KSK) | E7 DS gone, after the owner set `ds=0` on entering retired | — | retired (1,0,0) | the DS withdrawal is the first thing that happens in retired: `ds=0` on entry (the DS set shrinks, the parent follows), then wait for E7 |
| T12 | retired | E8 margin | a KSK's DS is gone (E7 seen) | mpremove (0,0,0) | tdns asked to strip the key's RRSIGs, then the removal distributed |
| T13 | mpremove | E9 removal applied | every signing provider confirmed (G1) | removed (0,0,0) | the propagation record dropped |
| T13' | mpremove | E2 | no other signing provider (G2) | removed | as T13, at once |
| T14 | mpdist, mpremove | E10 signers changed | — | same | the expected set recomputed; T3/T13 re-evaluated against it. A signer that joined gets this provider's served keys again (what a REPLACE of the local DNSKEYs carries) |
| T15 | any | E11 restart | — | same | the distributions in flight are read back from `MPKeyDistribution` (who must confirm, who has, who rejected): what is outstanding is sent again, a rejected one waits for the operator (P8); timers re-armed from the row stamps (P4) |
| T16 | — | C3 rollover now | a standby key of the role exists; with none in created..standby (a standby count of 0) T1 mints one first and the request waits for it | — | E6 for that key |
| T17 | — | C3 cancel | a rollover is requested and not yet fired | — | the request cleared |

A confirmation answers the distribution in flight for the key, and one kind of distribution is in flight at a time: the key's, or its removal. An answer to the key's distribution that arrives after its removal went out (a slow signer, a duplicate on the wire) is stale: refused, the removal's record untouched. The signals the agent aggregates today (§6 O5) name the kind they answer: "propagated" for a key's distribution, "removed" for its removal, so an answer of the other kind than the record in flight is stale whatever the times say. Beside that the signer tells a stale answer by time: the agent stamps the moment it started tracking the distribution it answers, and an answer older than the record's first send by more than a tolerance (two minutes: the agent's tracking follows the signer's push, on its own clock) is stale. A resend keeps the first send time, so the answer to the first send counts after a resend. A rejection on a served key's record stays on it as it does in mpdist (G1): the record is not dropped when everyone else applied, so T9 does not promote a standby key a signer that joined rejected, and T6' does not resend it; the operator's retry (T6) or withdraw (T7'') resolves it.

Foreign rows are not driven by this table. They follow the other providers' distributions: a DNSKEY arriving with its provider's state (#58) is upserted as `foreign` with `pub=1`, `sign=0`, and `ds` per §1; a DNSKEY the provider no longer sends is deleted; a foreign row whose provider stops signing the zone (E10) gets `ds=0`.

As implemented (r9): the row itself still comes from the zone as the signer receives it (every DNSKEY not its own), and only `ds` is decided here. The provider's word (its state for the key and its own `ds`) reaches the signer from its agent as the zone's complete latest set, kept in a table so a restart keeps it. The rule: `ds=1` only for a SEP key whose provider is one of the zone's other signers, holds the key standby, active or retired, and says its DS belongs at the parent; `ds=0` otherwise; **no write at all** while the provider has not said (an older release, or a key nobody mentioned), so the row stays undecided and the zone's DS set unknown. It runs when the word arrives, on every tick (the row may appear after the word, with the next transfer), on a reload, and when the signers change. The latest word replaces the one before: a key its provider mentioned and now leaves out, while it still speaks of others, is one it has stopped serving, and gets `ds=0` until its row goes; a provider that is not in the word at all has said nothing new. One case this cannot tell apart: a provider whose whole word becomes an explicit empty list ("none of my keys") looks, in the flat set the signer gets, like a provider that has not spoken, so its rows keep their `ds` until they go with its DNSKEYs. tdns-mp's own sender never says that (an empty list is not encoded, and a provider with no served key sends no key states at all); telling the two apart needs the hand-over to name the providers that have spoken, which is left for when it matters. A KSK that stays undecided for three margins is reported to the operator once, with its provider when that is known: it is what keeps the zone's DS set unknown (design R9).

## 4. Invariants the table keeps (test plan §4.4, P1–P9)

| P | how the table keeps it |
|---|---|
| P1 no `sign=1` before every signing provider applied the key and the RRset propagated | only T9 sets `sign`, only from standby; standby only via T8 from published; published only via T3/T3' |
| P2 no KSK `ds=1` before standby | only T8 sets `ds` |
| P3 a foreign KSK has `ds=1` only if its provider signs and holds it standby, active or retired-not-withdrawn | §1's foreign row, from the provider's state on the wire (#58); NULL when the provider does not say |
| P4 no key lost | every state has a way out; T15 re-sends what was in flight |
| P5 one `sign=1` per role and algorithm per provider, except during an algorithm rollover | T9's guard |
| P6 a started rollover completes within its policy's bound under fair delivery | every wait is a bounded timer (T8, T12) or a confirmation that fair delivery brings (T3, T13); a lost distribution is sent again on the resend timer (T6') |
| P7 no other signing provider: mpdist → published at once | T3', T13' |
| P8 a rejected key stays in mpdist, is reported, never promoted | T5; no row leaves mpdist on E4; the rejection sticks to the distribution (G1), so a later applied from the rejecter does not lift it, only C1 |
| P9 pending never counts as applied | T4 |

## 5. What this replaces

| today | in the table |
|---|---|
| `StagedState` hook: a new standby key starts in mpdist | T1 + T2 |
| `MayPromote` hook + `MPKeyPropagation`: confirmed, and the DNSKEY TTL elapsed | T3 (applied, not "any confirmation") + T8 (the timer) + T9 |
| `MayGenerate` hook: mint only with no key of the role | T1's guard, per the policy's standby count |
| `RetiredState` hook: retired keys go to mpremove on the margin | T11 + T12, with the DS withdrawn first |
| KEYSTATE `propagated` at the signer: mpdist → published, mpremove → removed | T3, T13, from the agent's per-provider confirmations |
| `rejected` logged and forgotten | T5, T6, T7 |
| `syncForeignDNSKEYs`: every DNSKEY not ours is `foreign` with no provider | §1's foreign row with provider and state (#58) |
| tdns's rollover engines, standby maintenance and worker on multi-provider zones | none: tdns skips an owned zone (S2); the table is the whole machine |

## 6. Open

| # | question | proposal |
|---|---|---|
| O1 | Where does the DNSKEY TTL for E5 come from on a multi-provider zone: this provider's served TTL, or the largest among the providers? | the largest the inventory reports; this provider's until the others report (#58) |
| O2 | E7 on a zone whose DS the parent never had (the zone is being signed for the first time): wait forever? | E7 is satisfied at once when the parent serves no DS for the key |
| O3 | Does a signing provider that leaves (E10) while a key is in mpremove still owe a confirmation? | no: the expected set is the current signers |
| O4 | An algorithm rollover by the machine: T9's guard admits a key of the policy's new algorithm beside the active one (P5's exception), but no row mints one, and T10 retires the old key as soon as the new one signs, which is not the conservative order (new DS at the parent before the old signatures go). S3's scenarios (test plan T3.4) do not ask for one; the owner's policy binding refuses an algorithm change so nothing pretends. | a later step: T1 mints a key of the policy's algorithm when the active one differs; T10 waits for the new KSK's DS at the parent; the old algorithm's keys withdraw together |
| O5 | The confirmations arrive aggregated: the agent tracks a distribution per remote agent and sends one "propagated" once every one confirmed (tdns-mp #57), so the signer's engine records every other signer as applied on that one signal, and a rejection as one from "peers". The machine wants them per provider (E3 per signer). | S3 fixes the agent's count (only a final applied status counts, #57 item 1); per-provider confirmations come with the DNSKEY distribution carrying provider and state (#58, S5) **r8, from the lab:** the agent waits on every HSYNC agent of the zone, the providers that do not sign it too; those answer "ignored", a final answer that is neither applied nor rejected, and the aggregated "propagated" goes out once every agent has answered and no signing provider ignored or rejected the key (for a zone with no other signer that is T3' by another door). The agent knows who signs from the zone's HSYNC3 labels and the HSYNCPARAM signers; where it cannot tell, an ignored answer counts as it comes. |
| O6 | A zone is taken with keys tdns minted before the take (the first owned zone on the lab): their `ds` is NULL, so the DS intent is unknown and no CDS is served. | the driver adopts such own rows on Reload, which every take runs: each gets the columns its state prescribes (design Q5: the owner writes `ds`); a retired KSK is adopted as not withdrawn. Foreign SEP rows stay unset until #58 tells their DS status, so a taken zone with other signers still states no DS intent, and serves no CDS, until then (Q9). |
