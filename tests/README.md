# tests/ — rigs

Committed rigs that stand the mp daemons up in a known topology and assert
what they do, following the conventions of `tdns/tests/README.md`: a fixed
work root under `/var/tmp/<rigname>/`, no key material in the repo
(`setup.sh` mints it), `run.sh verify` prints one PASS/FAIL per assertion
and exits non-zero on failure, negative cases are part of the rig, binary
paths overridable by environment.

| Rig | Covers |
|---|---|
| `mp-policy-matrix/` | who may change the NS and DNSKEY RRsets of a customer zone, and where a change ends up, across 1–3 providers × 1–2 signers × `nsmgmt=owner|agent`; one loopback deployment carries every cell as one zone |

Rigs are the mechanised form of `docs/2026-03-30-mp-regression-test-plan.md`
for the scenarios they cover; the design of the first one is
`docs/2026-09-10-mp-scenario-test-rigs-design.md`.
