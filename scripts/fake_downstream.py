"""Tiny local mock of a downstream LLM/API, for manual verification only.

This is NOT part of the Protection Agent -- it stands in for "the LLM" so
you can see, with your own eyes, exactly what data a downstream service
would receive after the Protection API has processed it.

The Protection API (Phase 5) does NOT call this, or any downstream service,
itself -- it only returns a decision + safe text. YOUR calling application
is responsible for checking `allowed` and, if true, forwarding `text` here
(or to a real LLM) itself. That boundary is intentional (see README).

Usage: uv run python scripts/fake_downstream.py [port]
Then POST JSON like {"text": "..."} to it and watch this terminal.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"raw": body.decode(errors="replace")}

        print("=" * 60, flush=True)
        print("FAKE DOWNSTREAM SERVICE RECEIVED:", flush=True)
        print(json.dumps(payload, indent=2), flush=True)
        print("=" * 60, flush=True)

        response = {"received": payload, "note": "This is the fake downstream service, not a real LLM."}
        response_bytes = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def log_message(self, format, *args):  # noqa: A002 -- quiet the default access log
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Fake downstream service listening on http://127.0.0.1:{port}", flush=True)
    print("Waiting for requests... (Ctrl+C to stop)", flush=True)
    server.serve_forever()
