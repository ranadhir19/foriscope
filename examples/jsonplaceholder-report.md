# foriscope report - https://jsonplaceholder.typicode.com

- Tool: foriscope 0.1.0 (verified black-box explainer; no language model used)
- Target: https://jsonplaceholder.typicode.com
- OpenAPI source: none (root resource only)
- Attestation: Demo run against JSONPlaceholder, a public fake-data API published for testing (labeled demo target).
- Claims: 0 verified, 2 single-observation, 0 refused

## Behavioral explanation

Each claim below is backed by the cited probes - replayable HTTP requests recorded in the audit log. Claims observed only once, or whose replay disagreed, are marked as single observations, not settled facts.

- [C-001] GET / returns HTTP 200. [probes: P-002, P-003] _(single observation)_
- [C-002] GET / responds with Content-Type 'text/html; charset=UTF-8'. [probes: P-002, P-003] _(single observation)_

## Refused claims

The following claims - drawn from the target's own documentation - could not be established by any probe available to this run. They are reported as refusals with reason codes, not as findings.

- None.

## Coverage ledger

| Method | Path | Probed | Probes | Notes |
|---|---|---|---|---|
| GET | / | yes | P-002, P-003 |  |

- Surface discovered: 1 endpoint(s) (OpenAPI source: none (root resource only)).
- Surface exercised: 1 of 1 endpoint(s).
- Unknown remainder: black-box analysis cannot enumerate endpoints that are not in the OpenAPI document and do not answer at the root. Behavior outside the exercised surface above is unverified, and this report claims nothing about it.
- State-changing operations are probed only when the spec declares them and write probing is explicitly enabled; unauthenticated probing cannot observe behavior behind authentication.

## Clean-room audit log

- Clean-room method: the target was examined only through the HTTP requests recorded in this log. No source code, binaries, credentials beyond those the operator supplied, or circumvention techniques were used.
- Requests recorded: 5 log entries (every HTTP request this run made, in order).
- Head hash: `136c92f5d145947799ece396c4f65e635ab5f4a2ad5031f847609a49bc8a7aa3`
- Signature: `856278ffe6f2e7b814e25558fa211c8155c9e2b30c15588889177175da18adb4` (HMAC-SHA256 over head_hash; chain = SHA-256 over canonical JSON entries)
- Key fingerprint: `a418f2855d4625c0e2552316f8352b688110f24c5452f6e39a9120cf52e71272` (the signing key is exported separately to the operator; `foriscope verify-audit` checks the chain with or without it).
