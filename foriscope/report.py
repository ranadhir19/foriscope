"""Report rendering: explanation, refusals, coverage ledger, audit summary.

The Markdown report is the product. Its contract:

- every claim in the explanation sections carries its probe citations;
- refused claims are printed as refusals, with reason codes, never as prose;
- the coverage ledger accounts for every discovered endpoint, probed or
  not, and names the unknown remainder explicitly;
- the audit summary lets a reader verify the clean-room log offline.
"""

from __future__ import annotations

import json

from . import __version__
from .claims import REASON_CODES


def render_markdown(result, audit_export: dict) -> str:
    counts = result.counts()
    lines = []
    lines.append(f"# foriscope report - {result.base_url}")
    lines.append("")
    lines.append(f"- Tool: foriscope {__version__} (verified black-box explainer; no language model used)")
    lines.append(f"- Target: {result.base_url}")
    lines.append(f"- OpenAPI source: {result.spec_source}")
    lines.append(f"- Attestation: {audit_export['meta']['attestation']}")
    lines.append(f"- Claims: {counts.get('verified', 0)} verified, "
                 f"{counts.get('single-observation', 0)} single-observation, "
                 f"{counts.get('refused', 0)} refused")
    lines.append("")
    lines.append("## Behavioral explanation")
    lines.append("")
    lines.append("Each claim below is backed by the cited probes - replayable HTTP requests "
                 "recorded in the audit log. Claims observed only once, or whose replay "
                 "disagreed, are marked as single observations, not settled facts.")
    lines.append("")
    for claim in result.claims:
        if claim.status == "refused":
            continue
        cites = ", ".join(claim.probe_ids)
        marker = "" if claim.status == "verified" else " _(single observation)_"
        lines.append(f"- [{claim.claim_id}] {claim.text} [probes: {cites}]{marker}")
    lines.append("")
    lines.append("## Refused claims")
    lines.append("")
    lines.append("The following claims - drawn from the target's own documentation - could not be "
                 "established by any probe available to this run. They are reported as refusals "
                 "with reason codes, not as findings.")
    lines.append("")
    refused = [c for c in result.claims if c.status == "refused"]
    if not refused:
        lines.append("- None.")
    for claim in refused:
        lines.append(f"- [{claim.claim_id}] {claim.text} - REFUSED: {claim.reason_code} "
                     f"({REASON_CODES.get(claim.reason_code, '')})")
    lines.append("")
    lines.append("## Coverage ledger")
    lines.append("")
    lines.append("| Method | Path | Probed | Probes | Notes |")
    lines.append("|---|---|---|---|---|")
    for row in result.ledger:
        lines.append(f"| {row['method']} | {row['path']} | {'yes' if row['probed'] else 'NO'} | "
                     f"{', '.join(row['probe_ids']) or '-'} | {row['note']} |")
    lines.append("")
    discovered = len(result.ledger)
    probed_n = sum(1 for r in result.ledger if r["probed"])
    lines.append(f"- Surface discovered: {discovered} endpoint(s) "
                 f"(OpenAPI source: {result.spec_source}).")
    lines.append(f"- Surface exercised: {probed_n} of {discovered} endpoint(s).")
    not_probed = [r for r in result.ledger if not r["probed"]]
    if not_probed:
        lines.append("- Not probed: " + "; ".join(
            f"{r['method']} {r['path']} ({r['note']})" for r in not_probed) + ".")
    lines.append("- Unknown remainder: black-box analysis cannot enumerate endpoints that are "
                 "not in the OpenAPI document and do not answer at the root. Behavior outside "
                 "the exercised surface above is unverified, and this report claims nothing about it.")
    lines.append("- State-changing operations are probed only when the spec declares them and "
                 "write probing is explicitly enabled; unauthenticated probing cannot observe "
                 "behavior behind authentication.")
    lines.append("")
    lines.append("## Clean-room audit log")
    lines.append("")
    lines.append(f"- {audit_export['meta']['method_statement']}")
    lines.append(f"- Requests recorded: {len(audit_export['entries'])} log entries "
                 f"(every HTTP request this run made, in order).")
    lines.append(f"- Head hash: `{audit_export['head_hash']}`")
    lines.append(f"- Signature: `{audit_export['signature']}` ({audit_export['signature_scheme']})")
    lines.append(f"- Key fingerprint: `{audit_export['key_fingerprint']}` "
                 f"(the signing key is exported separately to the operator; "
                 f"`foriscope verify-audit` checks the chain with or without it).")
    lines.append("")
    return "\n".join(lines)


def render_json(result, audit_export: dict) -> str:
    payload = {
        "tool": "foriscope",
        "version": __version__,
        "target": result.base_url,
        "spec_source": result.spec_source,
        "claims": [c.to_dict() for c in result.claims],
        "coverage_ledger": result.ledger,
        "counts": result.counts(),
        "audit": audit_export,
    }
    return json.dumps(payload, indent=2, sort_keys=True)
