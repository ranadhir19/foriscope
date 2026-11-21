# foriscope

**A verified black-box explainer for web/API systems.**

Point foriscope at an API you are authorized to examine. It discovers the
surface (from an OpenAPI document, supplied or fetched), runs **replayable
probes** against it, and writes an explanation in which **every behavioral
claim cites the probe that backs it**. Claims it cannot probe are emitted
as **reason-coded refusals** — never as confident prose. Every report closes
with a **coverage ledger** (what was probed, what was not, and why) and a
**signed, hash-chained clean-room audit log** of every request made.

The explanation is assembled from probe evidence by deterministic logic.
**No language model is used at any point** — that is the point: every
sentence in the report is evidence-backed, or it is a refusal.

> *foris* (Latin): outside, out of doors. foriscope examines a system
> strictly from outside, and says only what the outside view can prove.

## Why

Explainers and reverse-engineering tools emit fluent explanations whose
correctness is asserted, never tested — their own disclaimers concede the
output "may be incomplete or incorrect." foriscope applies the opposite
discipline, the one rigorous idea in the field (re-executability as a truth
test), to system explanation:

- **Claim → probe → replay → keep, downgrade, or refuse.** A claim is
  `verified` only when the same request, issued twice, returns agreeing
  responses. Disagreement downgrades it to a *single observation*.
- **Refusals are data.** A claim about server-side computation, currency
  semantics, sync cadence, or anything behind authentication the operator
  didn't unlock is printed as `REFUSED: <REASON_CODE>`, not smoothed over.
- **Coverage is measured, not implied.** The ledger accounts for every
  discovered endpoint and names the *unknown remainder* explicitly:
  behavior outside the exercised surface is unverified, full stop.
- **The process is provable.** The audit log is a hash chain (any edit,
  deletion, or reorder breaks it) signed with HMAC-SHA256, recording the
  operator's authorization attestation and a clean-room method statement:
  the target was examined only through the requests in the log.

## Quickstart

Pure Python standard library. No dependencies, no model calls, works
offline against local targets. Python ≥ 3.9.

```bash
# 1. See it work: explain the bundled fixture API (a small local shop
#    service with known ground-truth behavior, incl. behaviors that must
#    be refused). Starts and stops a local server by itself.
python -m foriscope demo --out fixture-report

# 2. Explain an API you operate or are authorized to examine.
python -m foriscope explain \
    --base-url http://127.0.0.1:8765 \
    --authorized \
    --attestation "I operate this staging API." \
    --out my-report

#    With write probing (spec-declared POST endpoints only):
python -m foriscope explain --base-url <url> --authorized --allow-post --out my-report

# 3. Verify a report's audit log (chain always; signature with the key).
python -m foriscope verify-audit --audit my-report.json --key my-report.key

# Serve the fixture yourself, e.g. to explore:
python -m foriscope fixture --port 8765
```

Each run writes three files: `<out>.md` (the report), `<out>.json`
(machine-readable claims, ledger, and the full audit log), and `<out>.key`
(the run's audit signing key — the operator's proof the log is theirs).

An optional OpenAPI document can be supplied with `--spec spec.json`
(JSON; if omitted, foriscope tries `<base-url>/openapi.json`, and otherwise
limits itself to the root resource and says so). Extra request headers
(e.g. an API key for an auth-gated area you are entitled to inspect) can be
passed with `--header "Name: value"`.

## What a report contains

1. **Behavioral explanation** — verified claims (statuses, content types,
   response shapes, field types, error behavior, pagination behavior,
   create-and-fetch behavior for POST endpoints), each cited like
   `[probes: P-006, P-007]`, plus any single-observation claims, marked.
2. **Refused claims** — candidate claims taken from the target's own
   documentation that no probe in the run could establish, each with a
   reason code:

   | Code | Meaning |
   |---|---|
   | `AUTH_CONTEXT_UNAVAILABLE` | behavior sits behind authentication; no credentials supplied |
   | `INTERNAL_STATE_NOT_OBSERVABLE` | server-side state/computation no response exposes |
   | `TEMPORAL_BEHAVIOR_NOT_PROBEABLE` | change over time beyond a bounded probing session |
   | `UNIT_SEMANTICS_NOT_PROBEABLE` | real-world meaning (currency/units) assigned to a value |
   | `ORDER_SEMANTICS_NOT_VERIFIABLE` | an order is visible; the claimed criterion is not |
   | `WRITE_PROBES_NOT_ENABLED` | state-changing operation; write probing not enabled |
   | `NOT_PROBEABLE_FROM_OUTSIDE` | no probe in the run's repertoire could falsify it |

3. **Coverage ledger** — every discovered endpoint: probed or not, with
   reasons; the exercised fraction; and the unknown-remainder statement.
4. **Clean-room audit log summary** — entry count, head hash, signature,
   and key fingerprint, verifiable offline with `verify-audit`.

Worked examples are in [`examples/`](examples/): the fixture report
(23 verified claims, 4 refusals — exactly the fixture's four unprobable
documented behaviors) and a labeled run against JSONPlaceholder, a public
demo API. Note the JSONPlaceholder root page is HTML that varies between
replays, so foriscope honestly downgrades those claims to single
observations rather than calling them verified.

## Scope (v1) and non-goals

- HTTP APIs only. GET-heavy probing; POST probes only where the target's
  own spec declares them and `--allow-post` is given. Other methods are
  accounted for in the ledger, not probed.
- No binaries, no decompilation, no cloning or rebuild output.
- No probing of systems you are not authorized to examine: `explain`
  refuses to run without `--authorized`, and the attestation is recorded
  in the signed audit log. Do not point foriscope at third-party
  production systems.
- OpenAPI input is JSON (the stdlib-only build ships no YAML parser).

## Development

```bash
python validate.py   # full suite against the fixture's ground truth
```

`validate.py` checks, among other things: every asserted claim cites
probes recorded in the audit log; the fixture's unprobable behaviors are
refused with the exact reason codes; ground-truth behaviors appear as
verified claims; the audit chain detects tampering and deletion; the CLI
refuses to run unattested; and the package imports nothing outside the
standard library. Exit code 0 only when all checks pass.

## License

MIT. See [LICENSE](LICENSE). Name and compliance records:
[NAME_CHECK.md](NAME_CHECK.md), [COMPLIANCE.md](COMPLIANCE.md).
