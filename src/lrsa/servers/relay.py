#!/usr/bin/env python3
"""
Relay server that sits between LRSA and lsa.lenovo.com.
Logs all requests/responses including auth headers.
LRSA's BaseHttpUrl is changed to http://127.0.0.1:9999
"""

from lrsa.logging import get_logger

from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
import json
import urllib3
import sys

from .constants import HTTP_RELAY_PORT, REAL_BASE

urllib3.disable_warnings()


class RelayHandler(BaseHTTPRequestHandler):
    def _relay(self, method):
        # Build the real URL
        real_url = REAL_BASE + self.path

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        # Log request
        get_logger(__name__).debug("\n%s", "=" * 60)
        get_logger(__name__).debug(">>> %s %s", method, self.path)
        get_logger(__name__).debug(">>> Real URL: %s", real_url)
        for k, v in self.headers.items():
            if k.lower() not in ["host", "accept-encoding"]:
                get_logger(__name__).debug(">>> %s: %s", k, v)
        if body:
            try:
                get_logger(__name__).debug(">>> Body: %s", body.decode("utf-8")[:500])
            except Exception:
                get_logger(__name__).debug(">>> Body: (%s bytes binary)", len(body))

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
            get_logger(__name__).info("Relay response status: %s", r.status_code)
            for k, v in r.headers.items():
                if k.lower() in [
                    "set-cookie",
                    "authorization",
                    "location",
                    "content-type",
                ]:
                    get_logger(__name__).debug("<<< %s: %s", k, v)
            if r.text and len(r.text) < 1000:
                get_logger(__name__).debug("<<< Body: %s", r.text)
            else:
                get_logger(__name__).debug("<<< Body: (%s chars)", len(r.text))

            # Check for token in response
            try:
                data = r.json()
                if "token" in str(data).lower() or "bearer" in str(data).lower():
                    get_logger(__name__).warning(
                        "Possible token found in relay response"
                    )
                    get_logger(__name__).debug(
                        "Token response payload: %s", json.dumps(data, indent=2)
                    )
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
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        except Exception:
            get_logger(__name__).exception("Relay request failed")
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
    get_logger(__name__).info(f"LRSA Relay Server starting on :{HTTP_RELAY_PORT}")
    get_logger(__name__).info(f"Forwarding to {REAL_BASE}")
    get_logger(__name__).info("Waiting for LRSA connections...\n")
    server = HTTPServer(("127.0.0.1", HTTP_RELAY_PORT), RelayHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        get_logger(__name__).info("\nShutting down.")
