# The key hold when the parent gives no KeyState verdict

**Date:** 2026-11-09. Based on main `71ad6a66`. Refs #404.
**Status:** implemented (branch `fix/404-key-hold-no-verdict`), with tdns
branch `fix/404-update-noerror-trusts-key`.

## The reading, and its cost

Ruling (a) on #404: an UPDATE signed with the zone's SIG(0) key that the
parent answers NOERROR proves that the parent trusts the key. A KeyState
answer stays the other proof.

The hold stops every sync the leader asks for until the key is trusted, so a
held zone never sends the UPDATE that would prove it. So the reading is:

- A key the parent never gave a verdict on (`parent_state` 0, or tdns's
  uninitialised sentinel 255) does not hold the leader's sync, unless a poll
  of the key runs. The next sync tests the key: NOERROR records it trusted
  (tdns), and BADKEY starts tdns's re-bootstrap, which waits for the key to
  be served (tdns #917).
- Any verdict the parent did give that is not trusted (unknown, invalid,
  refused, validation failed, manual bootstrap, ...) holds, as before.
- `keyPending` follows `keyHold`. The key rounds no longer offer a key with no
  verdict again, and the status shows no line for it.

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

- tdns-mp: `parentHoldsKey(parent_state)` decides. Trusted, 0 and 255 do not
  hold; every other value does. `keyHold` and `keyPending` both use it.
- tdns: a NOERROR to an UPDATE signed with the zone's key records the key
  trusted (`recordUpdateAccepted`, in the delegation sync and the DS
  delivery). The tdns-mp change does not need it to release the hold. It
  makes `parent_state`, and the status built on it, say what the parent did.

## 3. Tests

- `TestTheHoldFollowsTheParentsVerdict`: 0, 255 and trusted do not hold;
  unknown, refused, invalid, validation failed and manual bootstrap do, and
  `keyPending` agrees. A key with no verdict and a running poll is held
  ("poll running").
- `TestASyncTestsAKeyTheParentNeverGaveAVerdictOn`: the explicit sync of
  such a zone is not held and reaches the parent.
- Three earlier tests that stood for "the parent has not taken the key" with
  a never-asked key now record the parent's "unknown" verdict.
- NOERROR recording trusted, and REFUSED or BADKEY recording nothing, are
  tdns's tests.
