"""HTTP probing: every request goes through the audit log, twice.

A probe is one HTTP request made for one stated purpose. Verification
probes are *replayed*: the same request is issued twice and the two
responses must agree (status and body hash) before a claim built on them
can be called ``verified``. A claim built on a single observation, or on
two disagreeing observations, is downgraded - never silently upgraded.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

MAX_BODY = 256 * 1024  # bytes of any single response body retained as evidence


@dataclass
class ProbeResult:
    probe_id: str
    purpose: str
    method: str
    url: str
    status: int | None
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    error: str = ""

    @property
    def body_hash(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    @property
    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except Exception:
            return None

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")


class Prober:
    def __init__(self, base_url: str, audit, timeout: float = 10.0, extra_headers: dict | None = None):
        self.base_url = base_url.rstrip("/")
        self.audit = audit
        self.timeout = timeout
        self.extra_headers = extra_headers or {}
        self._counter = 0
        self.results: dict[str, ProbeResult] = {}

    def url_for(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return self.base_url + "/" + path.lstrip("/")

    def probe(self, method: str, path: str, purpose: str, body: dict | None = None) -> ProbeResult:
        self._counter += 1
        probe_id = f"P-{self._counter:03d}"
        url = self.url_for(path)
        data = None
        headers = {"Accept": "application/json", "User-Agent": "foriscope/0.1 (black-box explainer)"}
        headers.update(self.extra_headers)
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        status = None
        resp_headers: dict = {}
        resp_body = b""
        error = ""
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                resp_body = resp.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            try:
                resp_body = exc.read(MAX_BODY)
            except Exception:
                resp_body = b""
        except Exception as exc:  # connection refused, DNS, timeout, ...
            error = f"{type(exc).__name__}: {exc}"
        self.audit.record(
            "probe",
            method,
            url,
            status if status is not None else f"error: {error}",
            note=f"{probe_id} {purpose}",
        )
        result = ProbeResult(
            probe_id=probe_id,
            purpose=purpose,
            method=method,
            url=url,
            status=status,
            headers=resp_headers,
            body=resp_body,
            error=error,
        )
        self.results[probe_id] = result
        return result

    def replay(self, method: str, path: str, purpose: str, body: dict | None = None):
        """Issue the same request twice. Returns (first, second, stable)."""
        first = self.probe(method, path, purpose, body=body)
        second = self.probe(method, path, purpose + " (replay)", body=body)
        stable = (
            first.status == second.status
            and first.body_hash == second.body_hash
            and not first.error
            and not second.error
        )
        return first, second, stable
