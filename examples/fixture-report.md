# foriscope report - http://127.0.0.1:34601

- Tool: foriscope 0.1.0 (verified black-box explainer; no language model used)
- Target: http://127.0.0.1:34601
- OpenAPI source: fetched /openapi.json
- Attestation: Demo run against the bundled local fixture API (operator's own system).
- Claims: 23 verified, 0 single-observation, 4 refused

## Behavioral explanation

Each claim below is backed by the cited probes - replayable HTTP requests recorded in the audit log. Claims observed only once, or whose replay disagreed, are marked as single observations, not settled facts.

- [C-001] GET / returns HTTP 200. [probes: P-002, P-003]
- [C-002] GET / responds with Content-Type 'application/json'. [probes: P-002, P-003]
- [C-003] GET / returns a JSON object with keys: endpoints, service. [probes: P-002, P-003]
- [C-004] GET /admin/stats returns HTTP 401. [probes: P-004, P-005]
- [C-005] GET /admin/stats responds with Content-Type 'application/json'. [probes: P-004, P-005]
- [C-006] GET /admin/stats returns a JSON object with keys: error. [probes: P-004, P-005]
- [C-007] GET /admin/stats refuses unauthenticated access with HTTP 401. [probes: P-004, P-005]
- [C-008] GET /items returns HTTP 200. [probes: P-006, P-007]
- [C-009] GET /items responds with Content-Type 'application/json'. [probes: P-006, P-007]
- [C-010] GET /items returns a JSON array of 5 element(s). [probes: P-006, P-007]
- [C-011] Array elements of GET /items are JSON objects with keys: id, name, price, stock. [probes: P-006, P-007]
- [C-012] In GET /items responses, element field 'id' has JSON type integer. [probes: P-006, P-007]
- [C-013] In GET /items responses, element field 'name' has JSON type string. [probes: P-006, P-007]
- [C-014] In GET /items responses, element field 'price' has JSON type number. [probes: P-006, P-007]
- [C-015] In GET /items responses, element field 'stock' has JSON type integer. [probes: P-006, P-007]
- [C-016] The 'limit' query parameter of GET /items controls page size: limit=2 returned 2 of the 5 elements returned without it. [probes: P-008, P-009]
- [C-017] GET /items/{id} returns HTTP 200. [probes: P-010, P-011]
- [C-018] GET /items/{id} responds with Content-Type 'application/json'. [probes: P-010, P-011]
- [C-019] GET /items/{id} returns a JSON object with keys: id, name, price, stock. [probes: P-010, P-011]
- [C-020] GET /items/999999999 (a non-existent resource) returns HTTP 404. [probes: P-012, P-013]
- [C-021] The error response of GET /items/{id} is a JSON object containing an 'error' key. [probes: P-012, P-013]
- [C-022] POST /items with a valid JSON body returns HTTP 201 and creates a resource that can then be fetched with GET /items/{id}. [probes: P-014, P-015, P-016, P-017]
- [C-023] POST /items with a body missing its required fields returns HTTP 400. [probes: P-018, P-019]

## Refused claims

The following claims - drawn from the target's own documentation - could not be established by any probe available to this run. They are reported as refusals with reason codes, not as findings.

- [C-024] Documented claim about GET /admin/stats: "Returns aggregate revenue totals computed from every order in the database." - REFUSED: AUTH_CONTEXT_UNAVAILABLE (behind authentication; no credentials supplied for this run)
- [C-025] Documented claim about GET /items: "Items are ranked by an internal popularity score that is maintained server-side and never exposed." - REFUSED: INTERNAL_STATE_NOT_OBSERVABLE (concerns server-side state or computation no response exposes)
- [C-026] Documented claim about GET /items: "Prices are amounts in the store's local currency." - REFUSED: UNIT_SEMANTICS_NOT_PROBEABLE (assigns real-world meaning (currency/units) to a value; probes see values, not meanings)
- [C-027] Documented claim about GET /items: "Inventory counts are synchronised with the warehouse every hour." - REFUSED: TEMPORAL_BEHAVIOR_NOT_PROBEABLE (concerns change over time beyond a bounded probing session)

## Coverage ledger

| Method | Path | Probed | Probes | Notes |
|---|---|---|---|---|
| GET | / | yes | P-002, P-003 |  |
| GET | /admin/stats | yes | P-004, P-005 |  |
| GET | /items | yes | P-006, P-007, P-008, P-009 |  |
| GET | /items/{id} | yes | P-010, P-011, P-012, P-013 |  |
| POST | /items | yes | P-014, P-015, P-016, P-017, P-018, P-019 |  |

- Surface discovered: 5 endpoint(s) (OpenAPI source: fetched /openapi.json).
- Surface exercised: 5 of 5 endpoint(s).
- Unknown remainder: black-box analysis cannot enumerate endpoints that are not in the OpenAPI document and do not answer at the root. Behavior outside the exercised surface above is unverified, and this report claims nothing about it.
- State-changing operations are probed only when the spec declares them and write probing is explicitly enabled; unauthenticated probing cannot observe behavior behind authentication.

## Clean-room audit log

- Clean-room method: the target was examined only through the HTTP requests recorded in this log. No source code, binaries, credentials beyond those the operator supplied, or circumvention techniques were used.
- Requests recorded: 20 log entries (every HTTP request this run made, in order).
- Head hash: `27326fed153a3660fe6c500c52a3214e9a092df5820336530cde69f3a41dc3bb`
- Signature: `c64360bb450de668a9f043ccc5b3d09de9727cd4a2fd47f04b722ac035fabc4f` (HMAC-SHA256 over head_hash; chain = SHA-256 over canonical JSON entries)
- Key fingerprint: `4c322de7c6e07167857067932dfb69595959240bffbaf13656133a4cd74fc1da` (the signing key is exported separately to the operator; `foriscope verify-audit` checks the chain with or without it).
