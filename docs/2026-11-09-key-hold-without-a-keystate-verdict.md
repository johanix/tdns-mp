# The key hold when the parent gives no KeyState verdict

**Date:** 2026-11-09. Based on main `71ad6a66`. Refs #404.
**Status:** implemented (branch `fix/404-key-hold-no-verdict`), with tdns
branch `fix/404-update-noerror-trusts-key`.
**Revised 2026-11-10:** a key with no verdict holds until a poll of it has
run to its end in this lead (keys-k3: a key published before its poll got
BADKEY). Was: holds only while a poll runs.

## The reading, and its cost

Ruling (a) on #404: an UPDATE signed with the zone's SIG(0) key that the
parent answers NOERROR proves that the parent trusts the key. A KeyState
answer stays the other proof.

The hold stops every sync the leader asks for until the key is trusted, so a
held zone never sends the UPDATE that would prove it. So the reading is:

- A key the parent never gave a verdict on (`parent_state` 0, or tdns's
  uninitialised sentinel 255) holds the leader's sync until a poll of that
  key has run to its end in this agent's present lead. After that it does
  not: the next sync tests the key. NOERROR records it trusted (tdns), and
  BADKEY starts tdns's re-bootstrap, which waits for the key to be served
  (tdns #917).
- Until that poll ends, the parent has not been asked about the key: one
  just made or taken up and published before its poll starts, or one whose
  poll a freeze held. A new lead, and a restart, start unpolled again.
- Any verdict the parent did give that is not trusted (unknown, invalid,
  refused, validation failed, manual bootstrap, ...) holds, as before.
- `keyPending` follows `keyHold`. Until the poll ends the key rounds offer
  the key again (every 5 minutes, the backstop when a poll was held); after
  it they do not, and the status shows no line for it.

**The cost:** one sync may be signed with a key the parent has not verified
yet, which the S14 hold was meant to avoid. That happens only where the
parent never says, by KeyState, whether it trusts the key.

## 1. Problem

`keyHold` held every leader-requested delegation sync until the zone's key
had `parent_state == KeyStateTrusted`. Only a KeyState answer from the
parent recorded that. Two cases never got there, although the parent accepts
the key:

- a key from before S14, whose row has `parent_state` 0;
- a parent that accepts SIG(0)-signed UPDATEs but does not return the
  KeyState option, as most parents don't. The poll's inquiries fail, it gives
  up, and nothing is recorded.

The key rounds kept offering the key, and every offer ended the same way.

## 2. What changed

- tdns-mp: `parentHoldsKey(parent_state, polledInLead)` decides. Trusted does
  not hold. 0 and 255 hold until a poll of the key has ended in this lead
  (`keyPolledInLead`: the key and lead that `pollEnded` notes when a poll
  runs to its end in the lead it started in). Every other value holds.
  `keyHold` and `keyPending` both use it.
- tdns: a NOERROR to an UPDATE signed with the zone's key records the key
  trusted (`recordUpdateAccepted`, in the delegation sync and the DS
  delivery). The tdns-mp change does not need it to release the hold. It
  makes `parent_state`, and the status built on it, say what the parent did.

## 3. Tests

- `TestTheHoldFollowsTheParentsVerdict`: before a poll ends, only trusted
  does not hold; after a poll ended in this lead, 0 and 255 do not hold
  either; unknown, refused, invalid, validation failed and manual bootstrap
  hold throughout, and `keyPending` agrees. A key with no verdict and a
  running poll is held ("poll running").
- `TestASyncTestsAKeyTheParentNeverGaveAVerdictOn`: the explicit sync of
  such a zone is held until a poll of the key ends without a verdict, and
  then reaches the parent (keys-parent-down K7).
- `TestAFreshKeyPublishedBeforeItsPollHoldsTheSync` (keys-k3 a): a fresh key
  with no poll is held although a poll of the key before it ended in this
  lead, and released once its own poll ends.
- `TestANewLeadHoldsAKeyWithNoVerdictUntilItsPollEnds`: a new lead holds the
  key again until a poll of it ends in that lead.
- Without the poll test in the rule all four fail; without the key test the
  fresh-key test fails; without the lead test the new-lead test fails.
- Three earlier tests that stood for "the parent has not taken the key" with
  a never-asked key now record the parent's "unknown" verdict.
- NOERROR recording trusted, and REFUSED or BADKEY recording nothing, are
  tdns's tests.
