"""Surface discovery: OpenAPI spec (supplied or fetched) plus the root path.

Discovery is deliberately literal. foriscope reports on the surface it can
enumerate - from an OpenAPI document when one is available, otherwise just
the root resource - and its coverage ledger states plainly that endpoints
outside the enumerated surface are an unknown remainder, not a silent zero.
"""

from __future__ import annotations

import json
import os

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


class Endpoint:
    def __init__(self, path: str, method: str, operation: dict):
        self.path = path
        self.method = method.upper()
        self.operation = operation or {}

    @property
    def summary(self) -> str:
        return self.operation.get("summary", "")

    @property
    def description(self) -> str:
        return self.operation.get("description", "")

    @property
    def text(self) -> str:
        return (self.summary + ". " + self.description).strip()

    def __repr__(self):
        return f"<Endpoint {self.method} {self.path}>"


def load_spec_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if os.path.splitext(path)[1].lower() in (".yaml", ".yml"):
        raise ValueError(
            "YAML specs are not supported by the stdlib-only build; "
            "convert the spec to JSON (e.g. `python -m json.tool` after a YAML->JSON conversion) "
            "and pass the .json file."
        )
    return json.loads(text)


def endpoints_from_spec(spec: dict) -> list[Endpoint]:
    endpoints = []
    for path, item in sorted((spec or {}).get("paths", {}).items()):
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            if method in item:
                endpoints.append(Endpoint(path, method, item[method]))
    return endpoints


def spec_sentences(endpoint: Endpoint) -> list[str]:
    """Split an operation's description into candidate-claim sentences.

    The description is the claim-bearing prose; the summary is a heading and
    is used only when no description exists.
    """
    text = (endpoint.description or endpoint.summary).replace("\n", " ")
    out = []
    for chunk in text.split("."):
        s = chunk.strip(" .")
        if len(s) >= 12:  # ignore fragments and headings
            out.append(s + ".")
    return out
