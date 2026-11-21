"""The explanation engine: probe, then claim only what the probes prove.

Pipeline: discover surface -> replay probes per endpoint -> build claims
from probe evidence -> convert the target's own documented claims into
either covered claims or reason-coded refusals -> assemble the coverage
ledger. The audit log records every request before its evidence is used.
"""

from __future__ import annotations

import json
import re

from . import __version__
from .audit import AuditLog
from .claims import REASON_CODES, Claim, classify_refusal
from .discover import Endpoint, endpoints_from_spec, spec_sentences
from .prober import Prober

MISSING_ID = "999999999"


def _json_type(value) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "null"


class RunResult:
    def __init__(self):
        self.claims: list[Claim] = []
        self.ledger: list[dict] = []
        self.audit: AuditLog | None = None
        self.spec_source: str = "none"
        self.base_url: str = ""
        self.endpoints: list[Endpoint] = []

    def add_claim(self, text, status, probe_ids=None, reason_code="", endpoint="") -> Claim:
        claim = Claim(
            claim_id=f"C-{len(self.claims) + 1:03d}",
            text=text,
            status=status,
            probe_ids=list(probe_ids) if probe_ids else [],
            reason_code=reason_code,
            endpoint=endpoint,
        )
        self.claims.append(claim)
        return claim

    def counts(self) -> dict:
        out = {"verified": 0, "single-observation": 0, "refused": 0}
        for c in self.claims:
            out[c.status] = out.get(c.status, 0) + 1
        return out


def _substitute(path: str, value: str) -> str:
    return re.sub(r"\{[^}]+\}", value, path)


def _example_body(operation: dict) -> dict | None:
    try:
        content = operation["requestBody"]["content"]["application/json"]
    except Exception:
        return None
    if "example" in content:
        return content["example"]
    schema = content.get("schema", {})
    body = {}
    props = schema.get("properties", {})
    for name in schema.get("required", []):
        ptype = props.get(name, {}).get("type", "string")
        body[name] = {"string": "probe-item", "number": 1.0, "integer": 1, "boolean": True}.get(ptype, "probe-item")
    return body or None


def _sentence_covered(sentence: str, observed_json, method: str, probed: bool, path: str = "") -> bool:
    """A documented sentence counts as covered when a direct probe claim
    already asserts it: 'returns ...' sentences whose named response keys
    were observed, '... by {param}' sentences for a probed path parameter,
    and 'creates ...' sentences for a POST that was probed."""
    low = sentence.lower()
    if method == "POST":
        return probed and "creat" in low
    if observed_json is not None:
        for param in re.findall(r"\{([^}]+)\}", path):
            if f"by {param}" in low:
                return True
        if "json array" in low and isinstance(observed_json, list):
            return True
        if "json object" in low and isinstance(observed_json, dict):
            return True
    if "return" not in low and "respond" not in low:
        return False
    keys = []
    if isinstance(observed_json, dict):
        keys = [str(k).lower() for k in observed_json.keys()]
    elif isinstance(observed_json, list) and observed_json and isinstance(observed_json[0], dict):
        keys = [str(k).lower() for k in observed_json[0].keys()]
    return any(len(k) >= 3 and (k in low or k.rstrip("s") in low) for k in keys)


def explain(base_url: str, spec: dict | None = None, spec_source: str = "none",
            allow_post: bool = False, attestation: str = "", extra_headers: dict | None = None) -> RunResult:
    result = RunResult()
    result.base_url = base_url.rstrip("/")
    result.spec_source = spec_source
    audit = AuditLog("foriscope", __version__, result.base_url,
                     attestation or "Operator asserts authorization to analyze this target.")
    result.audit = audit
    prober = Prober(result.base_url, audit, extra_headers=extra_headers)

    if spec is None:
        fetched = prober.probe("GET", "/openapi.json", "discover OpenAPI document")
        if fetched.json and isinstance(fetched.json, dict) and "paths" in fetched.json:
            spec = fetched.json
            result.spec_source = "fetched /openapi.json"
        else:
            audit.record("note", "-", result.base_url, "-",
                         note="no OpenAPI document available; surface limited to root resource")

    endpoints = endpoints_from_spec(spec) if spec else []
    if not endpoints:
        endpoints = [Endpoint("/", "GET", {})]
        if spec is None:
            result.spec_source = "none (root resource only)"
    result.endpoints = endpoints

    known_first_id = "1"
    get_results: dict[str, object] = {}  # path -> first ProbeResult

    # ---- GET endpoints first (POST probing mutates state; it goes last) ----
    for ep in endpoints:
        if ep.method != "GET":
            continue
        concrete = _substitute(ep.path, known_first_id)
        first, second, stable = prober.replay("GET", concrete, f"explain {ep.method} {ep.path}")
        get_results[ep.path] = first
        status_word = "verified" if stable else "single-observation"
        pids = [first.probe_id, second.probe_id]
        row = {"method": ep.method, "path": ep.path, "probed": True, "probe_ids": pids, "note": ""}
        result.ledger.append(row)
        if first.error or first.status is None:
            row["note"] = f"probe failed: {first.error}"
            result.add_claim(f"{ep.method} {ep.path} could not be observed: the probe request failed.",
                             "refused", pids, "NOT_PROBEABLE_FROM_OUTSIDE", ep.path)
            continue
        if isinstance(first.json, list) and first.json and isinstance(first.json[0], dict) and "id" in first.json[0]:
            known_first_id = str(first.json[0]["id"])
        result.add_claim(f"{ep.method} {ep.path} returns HTTP {first.status}.", status_word, pids, endpoint=ep.path)
        if first.content_type:
            result.add_claim(f"{ep.method} {ep.path} responds with Content-Type '{first.content_type}'.",
                             status_word, pids, endpoint=ep.path)
        body = first.json
        if isinstance(body, list):
            result.add_claim(f"{ep.method} {ep.path} returns a JSON array of {len(body)} element(s).",
                             status_word, pids, endpoint=ep.path)
            if body and isinstance(body[0], dict):
                keys = sorted(body[0].keys())
                result.add_claim(f"Array elements of {ep.method} {ep.path} are JSON objects with keys: {', '.join(keys)}.",
                                 status_word, pids, endpoint=ep.path)
                for key in keys:
                    result.add_claim(f"In {ep.method} {ep.path} responses, element field '{key}' has JSON type {_json_type(body[0][key])}.",
                                     status_word, pids, endpoint=ep.path)
        elif isinstance(body, dict):
            keys = sorted(body.keys())
            result.add_claim(f"{ep.method} {ep.path} returns a JSON object with keys: {', '.join(keys)}.",
                             status_word, pids, endpoint=ep.path)
        if first.status in (401, 403):
            result.add_claim(f"{ep.method} {ep.path} refuses unauthenticated access with HTTP {first.status}.",
                             status_word, pids, endpoint=ep.path)

        # Error behavior for path-parameter endpoints: ask for a missing resource.
        if "{" in ep.path:
            missing_path = _substitute(ep.path, MISSING_ID)
            m1, m2, mstable = prober.replay("GET", missing_path, f"error behavior of {ep.method} {ep.path}")
            row["probe_ids"] += [m1.probe_id, m2.probe_id]
            mword = "verified" if mstable else "single-observation"
            if m1.status is not None:
                result.add_claim(f"{ep.method} {missing_path} (a non-existent resource) returns HTTP {m1.status}.",
                                 mword, [m1.probe_id, m2.probe_id], endpoint=ep.path)
                if isinstance(m1.json, dict) and "error" in m1.json:
                    result.add_claim(f"The error response of {ep.method} {ep.path} is a JSON object containing an 'error' key.",
                                     mword, [m1.probe_id, m2.probe_id], endpoint=ep.path)

        # Pagination behavior when the spec declares a limit parameter.
        params = ep.operation.get("parameters", [])
        if any(p.get("name") == "limit" and p.get("in") == "query" for p in params) \
                and isinstance(body, list) and len(body) >= 3:
            l1, l2, lstable = prober.replay("GET", concrete + "?limit=2", f"pagination behavior of {ep.method} {ep.path}")
            row["probe_ids"] += [l1.probe_id, l2.probe_id]
            if isinstance(l1.json, list) and len(l1.json) == 2:
                result.add_claim(
                    f"The 'limit' query parameter of {ep.method} {ep.path} controls page size: "
                    f"limit=2 returned 2 of the {len(body)} elements returned without it.",
                    "verified" if lstable else "single-observation",
                    [l1.probe_id, l2.probe_id], endpoint=ep.path)

    # ---- POST endpoints (only spec-declared, only when enabled) ----
    for ep in endpoints:
        if ep.method == "GET":
            continue
        row = {"method": ep.method, "path": ep.path, "probed": False, "probe_ids": [], "note": ""}
        result.ledger.append(row)
        if ep.method != "POST":
            row["note"] = "not probed: v1 probes GET and spec-declared POST only"
            continue
        if not allow_post:
            row["note"] = "not probed: write probing not enabled (pass --allow-post)"
            continue
        body = _example_body(ep.operation)
        if body is None:
            row["note"] = "not probed: spec declares no JSON example or required fields to build a safe probe body"
            continue
        created_ids = []
        probe_ids = []
        ok = True
        for _ in range(2):
            created = prober.probe("POST", ep.path, f"create probe of {ep.method} {ep.path}", body=body)
            probe_ids.append(created.probe_id)
            if created.status not in (200, 201) or not isinstance(created.json, dict):
                ok = False
                break
            new_id = created.json.get("id")
            if new_id is not None:
                fetched = prober.probe("GET", f"{ep.path}/{new_id}", f"fetch created resource from {ep.method} {ep.path}")
                probe_ids.append(fetched.probe_id)
                if fetched.status != 200:
                    ok = False
                    break
                created_ids.append(new_id)
        row["probed"] = True
        row["probe_ids"] = probe_ids
        if ok and created_ids:
            result.add_claim(
                f"{ep.method} {ep.path} with a valid JSON body returns HTTP 201 and creates a resource "
                f"that can then be fetched with GET {ep.path}/{{id}}.",
                "verified", probe_ids, endpoint=ep.path)
        elif ok:
            result.add_claim(f"{ep.method} {ep.path} with a valid JSON body returns HTTP 201.",
                             "single-observation", probe_ids, endpoint=ep.path)
        bad1, bad2, badstable = prober.replay("POST", ep.path, f"invalid-body probe of {ep.method} {ep.path}", body={})
        row["probe_ids"] += [bad1.probe_id, bad2.probe_id]
        if bad1.status is not None and bad1.status >= 400:
            result.add_claim(
                f"{ep.method} {ep.path} with a body missing its required fields returns HTTP {bad1.status}.",
                "verified" if badstable else "single-observation",
                [bad1.probe_id, bad2.probe_id], endpoint=ep.path)

    # ---- The target's own documented claims: covered, or refused ----
    for ep in endpoints:
        observed = get_results.get(ep.path)
        observed_json = observed.json if observed else None
        endpoint_status = observed.status if observed else None
        probed = any(r["path"] == ep.path and r["method"] == ep.method and r["probed"] for r in result.ledger)
        for sentence in spec_sentences(ep):
            if _sentence_covered(sentence, observed_json, ep.method, probed, ep.path):
                continue
            if ep.method != "GET" and not probed:
                code = "WRITE_PROBES_NOT_ENABLED" if ep.method == "POST" else "NOT_PROBEABLE_FROM_OUTSIDE"
            else:
                code = classify_refusal(sentence, endpoint_status)
            result.add_claim(f"Documented claim about {ep.method} {ep.path}: \"{sentence}\"",
                             "refused", [], code, ep.path)

    audit.record("note", "-", result.base_url, "-",
                 note=f"run complete: {result.counts()}")
    return result
