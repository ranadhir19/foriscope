"""The fixture API: a small shop service with known ground-truth behavior.

foriscope is developed and validated against this fixture. Its behavior is
fixed and documented here - this docstring is the ground truth the test
suite checks the explainer against:

- ``GET /``                 service descriptor (JSON).
- ``GET /openapi.json``     this API's OpenAPI document (JSON).
- ``GET /items``            the catalogue: a JSON array of 5 items, each an
                            object with keys id, name, price, stock.
- ``GET /items?limit=N``    at most N items (the limit parameter works).
- ``GET /items/{id}``       one item as JSON; unknown ids return 404 with a
                            JSON body containing an ``error`` key.
- ``POST /items``           creates an item (201, the created item as JSON);
                            a body without ``name`` returns 400.
- ``GET /admin/stats``      401 without the admin token; aggregate totals
                            with it.

Behaviors the explainer must REFUSE to claim (they are asserted in the
fixture's own OpenAPI prose, and none of them is black-box probeable):

- items are ranked by an internal popularity score maintained server-side
  (INTERNAL_STATE_NOT_OBSERVABLE),
- prices are amounts in the store's local currency
  (UNIT_SEMANTICS_NOT_PROBEABLE),
- inventory counts are synchronised with the warehouse every hour
  (TEMPORAL_BEHAVIOR_NOT_PROBEABLE),
- /admin/stats returns aggregate revenue totals computed from every order
  (AUTH_CONTEXT_UNAVAILABLE to an unauthenticated run).

All responses are deterministic: identical requests return byte-identical
bodies, which is what makes probe replay meaningful.
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ADMIN_TOKEN = "fixture-admin-token"

_ITEMS = [
    {"id": 1, "name": "brass compass", "price": 42.5, "stock": 7},
    {"id": 2, "name": "linen map case", "price": 18.0, "stock": 12},
    {"id": 3, "name": "field notebook", "price": 6.75, "stock": 40},
    {"id": 4, "name": "enamel mug", "price": 11.25, "stock": 23},
    {"id": 5, "name": "waxed canvas roll", "price": 29.9, "stock": 3},
]

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "FixtureMart", "version": "1.0.0"},
    "paths": {
        "/": {
            "get": {
                "summary": "Service descriptor",
                "description": "Returns the service name and a list of its endpoint paths.",
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/items": {
            "get": {
                "summary": "List the catalogue",
                "description": (
                    "Returns the catalogue as a JSON array. "
                    "Items are ranked by an internal popularity score that is maintained server-side and never exposed. "
                    "Prices are amounts in the store's local currency. "
                    "Inventory counts are synchronised with the warehouse every hour."
                ),
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer"},
                     "description": "Maximum number of items to return."}
                ],
                "responses": {"200": {"description": "OK"}},
            },
            "post": {
                "summary": "Create an item",
                "description": "Creates a new catalogue item from a JSON body with name and price.",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name", "price"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "price": {"type": "number"},
                                    "stock": {"type": "integer"},
                                },
                                "example": {"name": "spare pencil", "price": 1.5, "stock": 9},
                            }
                        }
                    },
                },
                "responses": {"201": {"description": "Created"}},
            },
        },
        "/items/{id}": {
            "get": {
                "summary": "Fetch one item",
                "description": "Returns a single catalogue item by id.",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                ],
                "responses": {"200": {"description": "OK"}, "404": {"description": "Not found"}},
            }
        },
        "/admin/stats": {
            "get": {
                "summary": "Aggregate statistics",
                "description": "Returns aggregate revenue totals computed from every order in the database.",
                "responses": {"200": {"description": "OK"}, "401": {"description": "Unauthorized"}},
            }
        },
    },
}


class _State:
    def __init__(self):
        self.items = [dict(it) for it in _ITEMS]
        self.next_id = 6


def make_handler(state: _State):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep the fixture silent
            pass

        def _send(self, status: int, obj):
            body = json.dumps(obj, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            path, query = parsed.path, parse_qs(parsed.query)
            if path == "/":
                self._send(200, {"service": "FixtureMart",
                                 "endpoints": ["/items", "/items/{id}", "/admin/stats", "/openapi.json"]})
            elif path == "/openapi.json":
                self._send(200, SPEC)
            elif path == "/items":
                items = state.items
                if "limit" in query:
                    try:
                        items = items[: int(query["limit"][0])]
                    except ValueError:
                        self._send(400, {"error": "invalid_limit"})
                        return
                self._send(200, items)
            elif re.fullmatch(r"/items/\d+", path):
                item_id = int(path.rsplit("/", 1)[1])
                for it in state.items:
                    if it["id"] == item_id:
                        self._send(200, it)
                        return
                self._send(404, {"error": "item_not_found", "id": item_id})
            elif path == "/admin/stats":
                if self.headers.get("X-Admin-Token") == ADMIN_TOKEN:
                    total = round(sum(it["price"] * it["stock"] for it in state.items), 2)
                    self._send(200, {"orders_total_value": total, "item_count": len(state.items)})
                else:
                    self._send(401, {"error": "unauthorized"})
            else:
                self._send(404, {"error": "not_found", "path": path})

        def do_POST(self):
            parsed = urlparse(self.path)
            if parsed.path == "/items":
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    payload = json.loads(raw.decode("utf-8")) if raw else {}
                except Exception:
                    self._send(400, {"error": "invalid_json"})
                    return
                if "name" not in payload:
                    self._send(400, {"error": "name_required"})
                    return
                item = {
                    "id": state.next_id,
                    "name": payload["name"],
                    "price": payload.get("price", 0),
                    "stock": payload.get("stock", 0),
                }
                state.next_id += 1
                state.items.append(item)
                self._send(201, item)
            else:
                self._send(404, {"error": "not_found", "path": parsed.path})

    return Handler


def serve(port: int = 0) -> ThreadingHTTPServer:
    """Start the fixture on a local port (0 = ephemeral). Caller shuts down."""
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(_State()))
    return server
