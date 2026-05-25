#!/usr/bin/env python3
"""HTTPS relay — intercepts LRSA traffic, logs everything, forwards to real server."""

import ssl
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
import urllib3

urllib3.disable_warnings()

REAL_BASE = "https://lsa.lenovo.com"
PORT = 9443


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
                log += "\n!!! POSSIBLE TOKEN IN RESPONSE !!!\n"

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
            self.send_header("Content-Length", len(resp))
            self.end_headers()
            self.wfile.write(resp)
        except Exception as e:
            log += f"\n!!! ERROR: {e}\n"
            self.send_response(502)
            self.end_headers()

        print(log)
        sys.stdout.flush()
        with open("/tmp/relay_traffic.log", "a") as f:
            f.write(log)

    def do_GET(self):
        self._relay("GET")

    def do_POST(self):
        self._relay("POST")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/tmp/relay_cert.pem", "/tmp/relay_key.pem")

    server = HTTPServer(("127.0.0.1", PORT), RelayHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"HTTPS Relay running on https://127.0.0.1:{PORT}")
    print(f"Forwarding to {REAL_BASE}")
    print("Traffic log: /tmp/relay_traffic.log")
    print("Waiting for LRSA connections...\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDone.")
