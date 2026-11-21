"""Claims and refusals.

A claim is a single behavioral sentence about the target system. foriscope
emits exactly three kinds:

- ``verified``         - backed by a probe replayed twice with agreement.
- ``single-observation`` - backed by one probe, or by a replay whose two
  responses disagreed; reported as observed once, never as settled fact.
- ``refused``          - a candidate claim (usually from the target's own
  documentation) that no black-box probe available to this run could
  establish. Refusals always carry a machine-readable reason code.

Reason codes
------------
AUTH_CONTEXT_UNAVAILABLE
    The behavior sits behind authentication the operator did not supply
    credentials for, so only the refusal of access itself is observable.
INTERNAL_STATE_NOT_OBSERVABLE
    The claim concerns server-side state, storage, or computation that no
    response exposes; a black-box probe cannot distinguish it from its
    negation.
TEMPORAL_BEHAVIOR_NOT_PROBEABLE
    The claim concerns change over time (sync cadence, freshness, update
    frequency) beyond what a bounded probing session can establish.
UNIT_SEMANTICS_NOT_PROBEABLE
    The claim assigns real-world meaning (currency, units, timezone) to a
    value; the probe sees the value, not its meaning.
ORDER_SEMANTICS_NOT_VERIFIABLE
    An ordering is visible in responses, but the criterion claimed to
    produce it is not; many criteria produce the same observed order.
NOT_PROBEABLE_FROM_OUTSIDE
    Default: no probe in this run's repertoire could falsify the claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field

REASON_CODES = {
    "AUTH_CONTEXT_UNAVAILABLE": "behind authentication; no credentials supplied for this run",
    "INTERNAL_STATE_NOT_OBSERVABLE": "concerns server-side state or computation no response exposes",
    "TEMPORAL_BEHAVIOR_NOT_PROBEABLE": "concerns change over time beyond a bounded probing session",
    "UNIT_SEMANTICS_NOT_PROBEABLE": "assigns real-world meaning (currency/units) to a value; probes see values, not meanings",
    "ORDER_SEMANTICS_NOT_VERIFIABLE": "an order is observable but the claimed criterion producing it is not",
    "NOT_PROBEABLE_FROM_OUTSIDE": "no probe in this run's repertoire could falsify the claim",
    "WRITE_PROBES_NOT_ENABLED": "the operation changes state and write probing was not enabled for this run",
}

_INTERNAL_HINTS = ("server-side", "server side", "internal", "stored", "database", "computed from every", "maintained")
_TEMPORAL_HINTS = ("every hour", "hourly", "daily", "every day", "real-time", "real time", "synchronis", "synchroniz", "syncs", "updated at", "freshness")
_UNIT_HINTS = ("currency", "in dollars", "usd", "unit of", "kilogram", "timezone", "time zone")
_ORDER_HINTS = ("ranked by", "sorted by", "ordered by", "popularity", "relevance score", "ranking")


def classify_refusal(sentence: str, endpoint_status: int | None) -> str:
    """Choose the reason code for a candidate claim that cannot be probed.

    Deterministic keyword logic over the claim text plus the one hard fact
    the run does own: the status the endpoint returned without credentials.
    Authentication wins first, because it is a fact, not an inference.
    """
    low = sentence.lower()
    if endpoint_status in (401, 403):
        return "AUTH_CONTEXT_UNAVAILABLE"
    if any(h in low for h in _INTERNAL_HINTS):
        return "INTERNAL_STATE_NOT_OBSERVABLE"
    if any(h in low for h in _TEMPORAL_HINTS):
        return "TEMPORAL_BEHAVIOR_NOT_PROBEABLE"
    if any(h in low for h in _UNIT_HINTS):
        return "UNIT_SEMANTICS_NOT_PROBEABLE"
    if any(h in low for h in _ORDER_HINTS):
        return "ORDER_SEMANTICS_NOT_VERIFIABLE"
    return "NOT_PROBEABLE_FROM_OUTSIDE"


@dataclass
class Claim:
    claim_id: str
    text: str
    status: str  # verified | single-observation | refused
    probe_ids: list = field(default_factory=list)
    reason_code: str = ""
    endpoint: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.claim_id,
            "text": self.text,
            "status": self.status,
            "probe_ids": list(self.probe_ids),
            "reason_code": self.reason_code,
            "endpoint": self.endpoint,
        }
