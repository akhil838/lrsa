#!/usr/bin/env python3
"""
Relay server that sits between LRSA and lsa.lenovo.com.
Logs all requests/responses including auth headers.
LRSA's BaseHttpUrl is changed to http://127.0.0.1:9999
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
import json
import urllib3
import sys

urllib3.disable_warnings()

REAL_BASE = "https://lsa.lenovo.com"
LISTEN_PORT = 9999


class RelayHandler(BaseHTTPRequestHandler):
    def _relay(self, method):
        # Build the real URL
        real_url = REAL_BASE + self.path

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        # Log request
        print(f"\n{'=' * 60}")
        print(f">>> {method} {self.path}")
        print(f">>> Real URL: {real_url}")
        for k, v in self.headers.items():
            if k.lower() not in ["host", "accept-encoding"]:
                print(f">>> {k}: {v}")
        if body:
            try:
                print(f">>> Body: {body.decode('utf-8')[:500]}")
            except Exception:
                print(f">>> Body: ({len(body)} bytes binary)")

        # Forward to real server
        headers = dict(self.headers)
        headers.pop("Host", None)
        headers.pop("host", None)

        try:
            if method == "GET":
                r = requests.get(real_url, headers=headers, verify=False, timeout=10)
            else:
                r = requests.post(
                    real_url, headers=headers, data=body, verify=False, timeout=10
                )

            # Log response
            print(f"\n<<< Status: {r.status_code}")
            for k, v in r.headers.items():
                if k.lower() in [
                    "set-cookie",
                    "authorization",
                    "location",
                    "content-type",
                ]:
                    print(f"<<< {k}: {v}")
            if r.text and len(r.text) < 1000:
                print(f"<<< Body: {r.text}")
            else:
                print(f"<<< Body: ({len(r.text)} chars)")

            # Check for token in response
            try:
                data = r.json()
                if "token" in str(data).lower() or "bearer" in str(data).lower():
                    print("\n!!! TOKEN FOUND IN RESPONSE !!!")
                    print(f"!!! {json.dumps(data, indent=2)}")
            except Exception:
                pass

            # Send response back to LRSA
            self.send_response(r.status_code)
            for k, v in r.headers.items():
                if k.lower() not in [
                    "content-encoding",
                    "transfer-encoding",
                    "content-length",
                ]:
                    self.send_header(k, v)
            response_body = r.content
            self.send_header("Content-Length", len(response_body))
            self.end_headers()
            self.wfile.write(response_body)

        except Exception as e:
            print(f"\n!!! ERROR: {e}")
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"Relay error")

        sys.stdout.flush()

    def do_GET(self):
        self._relay("GET")

    def do_POST(self):
        self._relay("POST")

    def log_message(self, format, *args):
        pass  # Suppress default logging


if __name__ == "__main__":
    print(f"LRSA Relay Server starting on :{LISTEN_PORT}")
    print(f"Forwarding to {REAL_BASE}")
    print("Waiting for LRSA connections...\n")
    server = HTTPServer(("127.0.0.1", LISTEN_PORT), RelayHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
