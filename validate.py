#!/usr/bin/env python3
"""foriscope validation harness.

Runs the full suite against the bundled fixture API (known ground truth):

 1. every non-refused claim cites probes that exist in the audit log;
 2. every claim bullet in the rendered report carries a probe citation;
 3. the fixture's unprobable behaviors are REFUSED with the exact reason
    codes the ground truth specifies;
 4. ground-truth behaviors (statuses, shapes, 404 handling, pagination,
    POST creation) appear as verified claims;
 5. with write probing disabled, POST is accounted for in the coverage
    ledger and its documented claim is refused WRITE_PROBES_NOT_ENABLED;
 6. the coverage ledger accounts for every endpoint in the fixture spec
    and names the unknown remainder;
 7. the audit log's hash chain verifies, with and without the signing key,
    and tampering with a copy is detected;
 8. the refusal classifier assigns the documented codes to sample claims;
 9. the CLI refuses to run without --authorized, and `demo` +
    `verify-audit` work end to end as subprocesses;
10. the package imports nothing outside the standard library.

Exit code 0 only if every check passes. Failures are fixed, never waived.
"""

from __future__ import annotations

import ast
import copy
import json
import os
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from foriscope.audit import verify_export  # noqa: E402
from foriscope.claims import classify_refusal  # noqa: E402
from foriscope.engine import explain  # noqa: E402
from foriscope.fixture import SPEC, serve  # noqa: E402
from foriscope.report import render_markdown  # noqa: E402

RESULTS = []


def check(name: str, ok: bool, detail: str = ""):
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail and not ok else ""))


def find_claim(result, needle: str, status: str | None = None):
    for c in result.claims:
        if needle in c.text and (status is None or c.status == status):
            return c
    return None


def main() -> int:
    server = serve(0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        run = explain(base, allow_post=True, attestation="validate.py run against the bundled fixture.")
        audit_export = run.audit.export()
        md = render_markdown(run, audit_export)

        # 1. probe citations exist and are recorded in the audit log
        audit_notes = " ".join(e.get("note", "") for e in audit_export["entries"])
        uncited = [c.claim_id for c in run.claims if c.status != "refused" and not c.probe_ids]
        check("every non-refused claim cites at least one probe", not uncited, str(uncited))
        missing = [pid for c in run.claims for pid in c.probe_ids if pid not in audit_notes]
        check("every cited probe id appears in the audit log", not missing, str(missing))

        # 2. rendered report: claim bullets carry citations
        bad_bullets = [ln for ln in md.splitlines()
                       if ln.startswith("- [C-") and "REFUSED" not in ln and "[probes:" not in ln]
        check("every claim bullet in the report carries a probe citation", not bad_bullets,
              str(bad_bullets[:2]))

        # 3. designated refusals with exact reason codes
        designated = [
            ("popularity score", "INTERNAL_STATE_NOT_OBSERVABLE"),
            ("local currency", "UNIT_SEMANTICS_NOT_PROBEABLE"),
            ("synchronised with the warehouse every hour", "TEMPORAL_BEHAVIOR_NOT_PROBEABLE"),
            ("aggregate revenue totals", "AUTH_CONTEXT_UNAVAILABLE"),
        ]
        for needle, code in designated:
            c = find_claim(run, needle, "refused")
            check(f"unprobable behavior refused: '{needle}' -> {code}",
                  c is not None and c.reason_code == code,
                  f"got {c.reason_code if c else 'no refusal'}")
        leaked = [c.claim_id for c in run.claims if c.status != "refused"
                  and any(n in c.text for n, _ in designated)]
        check("no unprobable behavior leaks into asserted claims", not leaked, str(leaked))

        # 4. ground-truth verified claims
        truth = [
            "GET /items returns HTTP 200",
            "returns a JSON array of 5 element(s)",
            "element field 'price' has JSON type number",
            "GET /items/999999999 (a non-existent resource) returns HTTP 404",
            "containing an 'error' key",
            "'limit' query parameter",
            "POST /items with a valid JSON body returns HTTP 201",
            "GET /admin/stats refuses unauthenticated access with HTTP 401",
        ]
        for needle in truth:
            c = find_claim(run, needle, "verified")
            check(f"verified claim present: {needle}", c is not None)

        # 4b. citations point at the right probes (no leakage from later probes)
        note_by_pid = {}
        for e in audit_export["entries"]:
            parts = e.get("note", "").split(" ", 1)
            if len(parts) == 2 and parts[0].startswith("P-"):
                note_by_pid[parts[0]] = parts[1]
        post_claim = find_claim(run, "POST /items with a valid JSON body returns HTTP 201", "verified")
        leaked_pids = [pid for pid in (post_claim.probe_ids if post_claim else [])
                       if "invalid-body" in note_by_pid.get(pid, "")]
        check("claim citations cite only their own probes", not leaked_pids, str(leaked_pids))

        # 5. write probing disabled
        run2 = explain(base, allow_post=False, attestation="validate.py no-post run.")
        post_rows = [r for r in run2.ledger if r["method"] == "POST"]
        check("coverage ledger accounts for POST when disabled",
              len(post_rows) == 1 and not post_rows[0]["probed"] and "--allow-post" in post_rows[0]["note"])
        c = find_claim(run2, "Creates a new catalogue item", "refused")
        check("documented POST claim refused WRITE_PROBES_NOT_ENABLED when disabled",
              c is not None and c.reason_code == "WRITE_PROBES_NOT_ENABLED",
              f"got {c.reason_code if c else 'no refusal'}")

        # 6. coverage completeness
        spec_paths = {(m.upper(), p) for p, item in SPEC["paths"].items() for m in item}
        ledger_paths = {(r["method"], r["path"]) for r in run.ledger}
        check("coverage ledger accounts for every spec endpoint", spec_paths == ledger_paths,
              f"missing {spec_paths - ledger_paths}, extra {ledger_paths - spec_paths}")
        check("report names the unknown remainder", "Unknown remainder" in md)

        # 7. audit chain
        ok, detail = verify_export(audit_export)
        check("audit hash chain verifies (no key)", ok, detail)
        ok, detail = verify_export(audit_export, run.audit.key_bytes())
        check("audit signature verifies (with key)", ok, detail)
        tampered = copy.deepcopy(audit_export)
        tampered["entries"][1]["status"] = 999
        ok, _ = verify_export(tampered, run.audit.key_bytes())
        check("tampered audit log is detected", not ok)
        tampered2 = copy.deepcopy(audit_export)
        del tampered2["entries"][2]
        ok, _ = verify_export(tampered2)
        check("audit log with a deleted entry is detected", not ok)

        # 8. classifier unit checks
        cases = [
            ("computed from every order in the database", 200, "INTERNAL_STATE_NOT_OBSERVABLE"),
            ("results are synchronised every hour", 200, "TEMPORAL_BEHAVIOR_NOT_PROBEABLE"),
            ("amounts are in the local currency", 200, "UNIT_SEMANTICS_NOT_PROBEABLE"),
            ("ranked by a relevance score", 200, "ORDER_SEMANTICS_NOT_VERIFIABLE"),
            ("anything at all", 401, "AUTH_CONTEXT_UNAVAILABLE"),
            ("the moon is made of cheese", 200, "NOT_PROBEABLE_FROM_OUTSIDE"),
        ]
        for sentence, status, code in cases:
            got = classify_refusal(sentence, status)
            check(f"classifier: '{sentence[:38]}...' -> {code}", got == code, f"got {got}")

        # 9. CLI behavior
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, "-m", "foriscope", "explain", "--base-url", base],
                capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
            check("CLI explain refuses to run without --authorized",
                  proc.returncode == 2 and "REFUSED" in proc.stderr)
            out_prefix = os.path.join(tmp, "demo")
            proc = subprocess.run(
                [sys.executable, "-m", "foriscope", "demo", "--out", out_prefix],
                capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
            check("CLI demo runs end to end", proc.returncode == 0
                  and os.path.exists(out_prefix + ".md") and os.path.exists(out_prefix + ".json"),
                  proc.stderr[-300:])
            proc = subprocess.run(
                [sys.executable, "-m", "foriscope", "verify-audit",
                 "--audit", out_prefix + ".json", "--key", out_prefix + ".key"],
                capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
            check("CLI verify-audit accepts the demo log", proc.returncode == 0 and "OK:" in proc.stdout,
                  proc.stdout + proc.stderr)

        # 10. stdlib-only imports
        pkg_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "foriscope")
        offenders = []
        for fname in os.listdir(pkg_dir):
            if not fname.endswith(".py"):
                continue
            tree = ast.parse(open(os.path.join(pkg_dir, fname), encoding="utf-8").read())
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    mods = [node.module.split(".")[0]]
                for m in mods:
                    if m not in sys.stdlib_module_names and m != "foriscope":
                        offenders.append(f"{fname}: {m}")
        check("package imports only the standard library", not offenders, str(offenders))
    finally:
        server.shutdown()

    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    if failed:
        print("FAILED CHECKS:")
        for name, _, detail in failed:
            print(f"  - {name} {detail}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
