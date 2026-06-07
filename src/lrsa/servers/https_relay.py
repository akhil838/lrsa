#!/usr/bin/env python3
"""HTTPS relay — intercepts LRSA traffic, logs everything, forwards to real server."""

from lrsa.logging import get_logger

import ssl
import sys
from typing import Any
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
import urllib3

from .constants import (
    HTTPS_RELAY_CERT_FILE,
    HTTPS_RELAY_KEY_FILE,
    HTTPS_RELAY_LOG_FILE,
    HTTPS_RELAY_PORT,
    REAL_BASE,
)

urllib3.disable_warnings()


class RelayHandler(BaseHTTPRequestHandler):
    def _relay(self, method):
        real_url = REAL_BASE + self.path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        # LOG REQUEST
        log = f"\n{'=' * 60}\n"
        log += f">>> {method} {self.path}\n"
        for k, v in self.headers.items():
            if k.lower() not in ["host", "accept-encoding"]:
                log += f">>> {k}: {v}\n"
        if body:
            try:
                log += f">>> Body: {body.decode()[:500]}\n"
            except Exception:
                log += f">>> Body: ({len(body)} bytes)\n"

        # FORWARD
        headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}
        try:
            if method == "GET":
                r = requests.get(real_url, headers=headers, verify=False, timeout=15)
            else:
                r = requests.post(
                    real_url, headers=headers, data=body, verify=False, timeout=15
                )

            log += f"\n<<< Status: {r.status_code}\n"
            log += f"<<< Body: {r.text[:500]}\n"

            # CHECK FOR TOKEN
            if (
                "token" in r.text.lower()
                or "bearer" in r.text.lower()
                or r.text.startswith("eyJ")
            ):
                get_logger(__name__).warning(
                    "Possible token found in HTTPS relay response"
                )

            # SEND BACK
            self.send_response(r.status_code)
            for k, v in r.headers.items():
                if k.lower() not in [
                    "content-encoding",
                    "transfer-encoding",
                    "content-length",
                ]:
                    self.send_header(k, v)
            resp = r.content
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        except Exception:
            get_logger(__name__).exception("HTTPS relay request failed")
            self.send_response(502)
            self.end_headers()

        get_logger(__name__).debug(log)
        sys.stdout.flush()
        with open(HTTPS_RELAY_LOG_FILE, "a") as f:
            f.write(log)

    def do_GET(self):
        self._relay("GET")

    def do_POST(self):
        self._relay("POST")

    def log_message(self, format: str, *args: Any) -> None:
        pass


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(HTTPS_RELAY_CERT_FILE, HTTPS_RELAY_KEY_FILE)

    server = HTTPServer(("127.0.0.1", HTTPS_RELAY_PORT), RelayHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    get_logger(__name__).info(
        f"HTTPS Relay running on https://127.0.0.1:{HTTPS_RELAY_PORT}"
    )
    get_logger(__name__).info(f"Forwarding to {REAL_BASE}")
    get_logger(__name__).info("Traffic log: %s", HTTPS_RELAY_LOG_FILE)
    get_logger(__name__).info("Waiting for LRSA connections...\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        get_logger(__name__).info("\nDone.")
