"""Hash-chained, HMAC-signed clean-room audit log.

Every HTTP request foriscope makes is recorded here, in order, before its
result is used. Each entry links to the previous entry's hash, so deleting,
editing, or reordering any entry breaks the chain and is detected by
:func:`verify_export`. The final head hash is signed with HMAC-SHA256 under
a per-run key; the key is exported separately so the log's owner can prove
the log is theirs and complete, while a reader who only has the log can
still verify the internal chain.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entry_hash(entry_body: dict) -> str:
    return hashlib.sha256(_canonical(entry_body)).hexdigest()


class AuditLog:
    """Append-only, hash-chained record of every request a run makes."""

    def __init__(self, tool: str, version: str, target: str, attestation: str):
        self._key = secrets.token_bytes(32)
        self.meta = {
            "tool": tool,
            "version": version,
            "target": target,
            "attestation": attestation,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "method_statement": (
                "Clean-room method: the target was examined only through the "
                "HTTP requests recorded in this log. No source code, binaries, "
                "credentials beyond those the operator supplied, or "
                "circumvention techniques were used."
            ),
        }
        self.entries: list[dict] = []

    def record(self, kind: str, method: str, url: str, status, note: str = "") -> dict:
        prev_hash = self.entries[-1]["hash"] if self.entries else "GENESIS"
        body = {
            "seq": len(self.entries),
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kind": kind,
            "method": method,
            "url": url,
            "status": status,
            "note": note,
            "prev_hash": prev_hash,
        }
        entry = dict(body)
        entry["hash"] = _entry_hash(body)
        self.entries.append(entry)
        return entry

    @property
    def head_hash(self) -> str:
        return self.entries[-1]["hash"] if self.entries else "GENESIS"

    def key_bytes(self) -> bytes:
        return self._key

    def key_fingerprint(self) -> str:
        return hashlib.sha256(self._key).hexdigest()

    def signature(self) -> str:
        return hmac.new(self._key, self.head_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    def export(self) -> dict:
        return {
            "meta": self.meta,
            "entries": self.entries,
            "head_hash": self.head_hash,
            "signature": self.signature(),
            "key_fingerprint": self.key_fingerprint(),
            "signature_scheme": "HMAC-SHA256 over head_hash; chain = SHA-256 over canonical JSON entries",
        }


def verify_export(data: dict, key: bytes | None = None) -> tuple[bool, str]:
    """Verify an exported audit log. Returns (ok, detail).

    The hash chain is always checked. If ``key`` is supplied, the HMAC
    signature over the head hash is checked as well.
    """
    entries = data.get("entries", [])
    prev = "GENESIS"
    for i, entry in enumerate(entries):
        if entry.get("seq") != i:
            return False, f"entry {i}: sequence mismatch"
        if entry.get("prev_hash") != prev:
            return False, f"entry {i}: prev_hash does not match previous entry hash"
        body = {k: entry[k] for k in ("seq", "ts", "kind", "method", "url", "status", "note", "prev_hash")}
        if _entry_hash(body) != entry.get("hash"):
            return False, f"entry {i}: hash mismatch (entry was modified)"
        prev = entry["hash"]
    if data.get("head_hash") != prev:
        return False, "head_hash does not match the last entry"
    if key is not None:
        expected = hmac.new(key, prev.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, data.get("signature", "")):
            return False, "HMAC signature does not match head hash"
        if hashlib.sha256(key).hexdigest() != data.get("key_fingerprint"):
            return False, "key fingerprint does not match supplied key"
    return True, f"chain intact: {len(entries)} entries, head {prev[:16]}..."
