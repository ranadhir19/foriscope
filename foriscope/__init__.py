"""foriscope - a verified black-box explainer for web/API systems.

Every behavioral claim in a foriscope report is backed by a replayed probe
(the actual HTTP request/response recorded in a hash-chained audit log), or
it is emitted as a reason-coded refusal. No claim is ever asserted as prose
without evidence. The explanation is assembled from probe evidence by
deterministic logic - no language model is involved at any point.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
