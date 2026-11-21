"""foriscope command line.

Commands:
  explain       probe a target and write a verified explanation report
  verify-audit  verify an exported audit log's hash chain (and signature)
  fixture       serve the bundled fixture API locally
  demo          run the explainer against a local fixture instance

Safety posture: `explain` refuses to run without --authorized, which records
the operator's attestation in the audit log. Write (POST) probes run only
with --allow-post, and only where the target's own spec declares them.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import threading

from . import __version__
from .audit import verify_export
from .discover import load_spec_file
from .engine import explain as run_explain
from .report import render_json, render_markdown


def _write_run(result, out_prefix: str) -> dict:
    audit_export = result.audit.export()
    md = render_markdown(result, audit_export)
    js = render_json(result, audit_export)
    with open(out_prefix + ".md", "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(out_prefix + ".json", "w", encoding="utf-8") as fh:
        fh.write(js)
    with open(out_prefix + ".key", "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(result.audit.key_bytes()).decode("ascii"))
    return {"md": out_prefix + ".md", "json": out_prefix + ".json", "key": out_prefix + ".key"}


def cmd_explain(args) -> int:
    if not args.authorized:
        print("REFUSED: foriscope only analyzes systems you are authorized to examine. "
              "Re-run with --authorized to record your attestation in the audit log.",
              file=sys.stderr)
        return 2
    spec = None
    spec_source = "none"
    if args.spec:
        spec = load_spec_file(args.spec)
        spec_source = f"supplied file {args.spec}"
    headers = {}
    if args.header:
        for h in args.header:
            name, _, value = h.partition(":")
            headers[name.strip()] = value.strip()
    result = run_explain(
        args.base_url,
        spec=spec,
        spec_source=spec_source,
        allow_post=args.allow_post,
        attestation=args.attestation or "Operator attests authorization to analyze this target.",
        extra_headers=headers or None,
    )
    files = _write_run(result, args.out)
    counts = result.counts()
    print(f"report: {files['md']}")
    print(f"machine-readable: {files['json']}")
    print(f"audit signing key: {files['key']}")
    print(f"claims: {counts.get('verified', 0)} verified, "
          f"{counts.get('single-observation', 0)} single-observation, "
          f"{counts.get('refused', 0)} refused")
    return 0


def cmd_verify_audit(args) -> int:
    with open(args.audit, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if "audit" in data:  # a full report JSON
        data = data["audit"]
    key = None
    if args.key:
        with open(args.key, "r", encoding="utf-8") as fh:
            key = base64.b64decode(fh.read().strip())
    ok, detail = verify_export(data, key)
    print(("OK: " if ok else "FAILED: ") + detail)
    return 0 if ok else 1


def cmd_fixture(args) -> int:
    from .fixture import serve

    server = serve(args.port)
    print(f"fixture API on http://127.0.0.1:{server.server_address[1]} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_demo(args) -> int:
    from .fixture import serve

    server = serve(0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_explain(
            f"http://127.0.0.1:{port}",
            allow_post=True,
            attestation="Demo run against the bundled local fixture API (operator's own system).",
        )
    finally:
        server.shutdown()
    files = _write_run(result, args.out)
    counts = result.counts()
    print(f"fixture demo report: {files['md']}")
    print(f"claims: {counts.get('verified', 0)} verified, "
          f"{counts.get('single-observation', 0)} single-observation, "
          f"{counts.get('refused', 0)} refused")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="foriscope",
                                     description="Verified black-box explainer for web/API systems.")
    parser.add_argument("--version", action="version", version=f"foriscope {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_explain = sub.add_parser("explain", help="probe a target and write a verified explanation")
    p_explain.add_argument("--base-url", required=True)
    p_explain.add_argument("--spec", help="path to an OpenAPI JSON document (else fetched from /openapi.json)")
    p_explain.add_argument("--out", default="foriscope-report", help="output prefix (default: foriscope-report)")
    p_explain.add_argument("--allow-post", action="store_true",
                           help="enable safe spec-declared POST probes (state-changing)")
    p_explain.add_argument("--authorized", action="store_true",
                           help="attest you are authorized to analyze this target (required)")
    p_explain.add_argument("--attestation", default="", help="attestation text recorded in the audit log")
    p_explain.add_argument("--header", action="append", help="extra request header 'Name: value' (repeatable)")
    p_explain.set_defaults(func=cmd_explain)

    p_verify = sub.add_parser("verify-audit", help="verify an exported audit log")
    p_verify.add_argument("--audit", required=True, help="report JSON or audit export file")
    p_verify.add_argument("--key", help="base64 signing key file produced by the run (optional)")
    p_verify.set_defaults(func=cmd_verify_audit)

    p_fixture = sub.add_parser("fixture", help="serve the bundled fixture API")
    p_fixture.add_argument("--port", type=int, default=8765)
    p_fixture.set_defaults(func=cmd_fixture)

    p_demo = sub.add_parser("demo", help="explain the bundled fixture API")
    p_demo.add_argument("--out", default="foriscope-fixture-report")
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
