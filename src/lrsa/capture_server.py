#!/usr/bin/env python3
"""OAuth callback monitor for Lenovo ID.

This temporarily intercepts ``https://lsa.lenovo.com/Tips/lenovoIdSuccess.html``
by running a local HTTPS server on port 443 while /etc/hosts maps that host to
127.0.0.1. It can also attempt to forward-capture ``passport-glb.lenovo.com``,
but HSTS browsers such as Brave/Chrome will reject a local self-signed
certificate for that host unless you run a separate test browser that ignores
certificate errors or install a trusted local certificate.

It is still intentionally narrow: it captures Lenovo ID OAuth hosts only,
exchanges the authorization code, saves the token response, probes the LRSA
Interface API, and then restores /etc/hosts.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import time
import uuid
import urllib.parse
import webbrowser
import random
import string
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
import urllib3

from .client import LRSAClient

urllib3.disable_warnings()

CLIENT_ID = "127cbff4e99dd5579db0627769509be972a3f38ad0dd11f2f2a7947516c923f0"
REDIRECT_URI = "https://lsa.lenovo.com/Tips/lenovoIdSuccess.html"
TOKEN_ENDPOINT = "https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/token"
INTERFACE_URL = "https://lsa.lenovo.com/Interface"
LENOVO_REALM = "lenovo.mbg.service.lmsa"
LENOVO_SOURCE = "Software Fix"
LENOVO_OAUTH_CALLBACK = (
    "https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/callback"
)
SOFTWARE_FIX_DEVICE_ID = "a70868156b51ce83858f33957f7a1c29"
HOSTS_FILE = "/etc/hosts"
PASSPORT_HOST = "passport-glb.lenovo.com"
DEFAULT_CAPTURE_HOSTS = ("lsa.lenovo.com",)
CAPTURE_HOSTS = DEFAULT_CAPTURE_HOSTS
CERT_FILE = "/tmp/lsa_cert.pem"
KEY_FILE = "/tmp/lsa_key.pem"
DEFAULT_OUT_DIR = Path("lrsa_work/capture")
FORWARD_TIMEOUT = 30


def redact(value):
    if not value:
        return value
    value = str(value)
    if len(value) <= 18:
        return "<redacted>"
    return f"{value[:10]}...{value[-6:]}"


def scrub_headers(headers):
    scrubbed = {}
    for key, value in headers.items():
        if key.lower() in {"authorization", "cookie", "set-cookie"}:
            scrubbed[key] = redact(value)
        else:
            scrubbed[key] = value
    return scrubbed


def save_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


class CaptureHandler(BaseHTTPRequestHandler):
    auth_code = None
    auth_state = None
    auth_scope = None
    auth_code_at = None
    softwarefix_callback_result = None
    softwarefix_callback = None
    events_path = None
    upstream_ips = {}

    def _send_capture_page(self, upstream_response=None):
        html = b"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Software Fix Login Capture</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background:#111; color:#eee; padding:48px; }
    .box { max-width:720px; margin:0 auto; border:1px solid #444; padding:28px; border-radius:10px; }
    h1 { margin-top:0; }
    #status { white-space:pre-wrap; line-height:1.5; color:#b8d7ff; }
    .ok { color:#9cffb2; }
    .err { color:#ff9c9c; }
    button { margin-top:18px; padding:10px 14px; background:#eee; border:0; border-radius:6px; }
  </style>
</head>
<body>
  <div class="box">
    <h1>Software Fix Login</h1>
    <div id="status">Starting callback...</div>
    <button id="retry">Retry callback</button>
  </div>
  <script>
    const statusEl = document.getElementById('status');
    function line(text, cls) {
      const span = document.createElement('div');
      if (cls) span.className = cls;
      span.textContent = text;
      statusEl.appendChild(span);
    }
    async function runCallback() {
      statusEl.textContent = '';
      try {
        const params = new URLSearchParams(window.location.search);
        if (!params.get('code') || !params.get('scope') || !params.get('state')) {
          throw new Error('Missing code/scope/state in callback URL');
        }
        line('1. Captured Lenovo OAuth code.');
        line('2. Asking Lenovo page API for Software Fix callback endpoint...');
        const urlResp = await fetch('/Tips/lmsa/tips/getOauth2Url.jhtml', {
          method: 'GET',
          cache: 'no-store',
          headers: {'Accept': 'application/json, text/plain, */*', 'Cache-Control': 'no-cache'}
        });
        const urlText = await urlResp.text();
        if (!urlResp.ok) throw new Error('getOauth2Url HTTP ' + urlResp.status + ': ' + urlText.slice(0, 200));
        const urlJson = JSON.parse(urlText);
        if (!urlJson.msg) throw new Error('getOauth2Url did not return msg: ' + urlText.slice(0, 200));
        const callbackUrl = urlJson.msg + window.location.search;
        line('3. Calling Software Fix callback...');
        const cbResp = await fetch(callbackUrl, {
          method: 'GET',
          cache: 'no-store',
          headers: {'Accept': 'application/json, text/plain, */*', 'Cache-Control': 'no-cache'}
        });
        const cbText = await cbResp.text();
        if (!cbResp.ok) throw new Error('callback HTTP ' + cbResp.status + ': ' + cbText.slice(0, 200));
        let cbJson = JSON.parse(cbText);
        if (cbJson.content && cbJson.content.startsWith('softwareFix://')) {
          line('4. Software Fix token captured. Return to terminal.', 'ok');
        } else {
          line('4. Callback returned without softwareFix URL: ' + cbText.slice(0, 300), 'err');
        }
      } catch (err) {
        line('Error: ' + err.message, 'err');
      }
    }
    document.getElementById('retry').addEventListener('click', runCallback);
    runCallback();
  </script>
</body>
</html>"""
        self.send_response(200)
        if upstream_response is not None:
            for key, value in upstream_response.headers.items():
                if key.lower() == "set-cookie":
                    self.send_header(key, value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def _record_event(self, body=None):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        host = self.headers.get("Host", "").split(":", 1)[0]
        event = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client": self.client_address[0],
            "method": self.command,
            "host": host,
            "path": parsed.path,
            "query": params,
            "headers": scrub_headers(dict(self.headers)),
            "body": body,
        }
        if self.events_path:
            with open(self.events_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, separators=(",", ":")))
                f.write("\n")
        return event

    def do_GET(self):
        event = self._record_event()
        print(f"[capture] GET {event['host']}{event['path']} query={event['query']}")

        if (
            event["host"] == "lsa.lenovo.com"
            and event["path"] == "/Tips/lenovoIdSuccess.html"
        ):
            params = event["query"]
            CaptureHandler.auth_code = params.get("code", [None])[0]
            CaptureHandler.auth_state = params.get("state", [None])[0]
            CaptureHandler.auth_scope = params.get("scope", [None])[0]
            CaptureHandler.auth_code_at = time.time()
            if CaptureHandler.auth_code:
                print(f"\n[+] CAPTURED CODE: {redact(CaptureHandler.auth_code)}")
                print(f"[+] STATE: {CaptureHandler.auth_state}")
            # Serve a self-contained page that performs the same browser-side
            # sequence as Lenovo's success page:
            #   /Tips/lmsa/tips/getOauth2Url.jhtml
            #   /Interface/user/oauth2/callback.jhtml?...code/scope/state
            # This avoids relying on external JS assets or the Software Fix
            # protocol button while preserving the required state setup.
            upstream_response = self._request_upstream(event, send_to_browser=False)
            self._send_capture_page(upstream_response=upstream_response)
        elif event["host"] in CAPTURE_HOSTS:
            self._forward_to_upstream(event)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b""
        body = raw.decode("utf-8", errors="replace") if raw else None
        event = self._record_event(body=body)
        print(f"[capture] POST {event['host']}{event['path']} bytes={length}")
        if event["host"] in CAPTURE_HOSTS:
            self._forward_to_upstream(event, raw_body=raw)
        else:
            self.send_response(404)
            self.end_headers()

    def _forward_to_upstream(self, event, raw_body=None):
        return self._request_upstream(event, raw_body=raw_body, send_to_browser=True)

    def _request_upstream(self, event, raw_body=None, send_to_browser=False):
        host = event["host"]
        upstream_ip = self.upstream_ips.get(host)
        if not upstream_ip:
            if send_to_browser:
                self.send_response(502)
                self.end_headers()
                self.wfile.write(f"No upstream IP cached for {host}".encode("utf-8"))
            return None

        target = f"https://{upstream_ip}{self.path}"
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower()
            not in {
                "host",
                "content-length",
                "connection",
                "accept-encoding",
                "proxy-connection",
            }
        }
        headers["Host"] = host
        try:
            response = requests.request(
                self.command,
                target,
                headers=headers,
                data=raw_body,
                verify=False,
                allow_redirects=False,
                timeout=FORWARD_TIMEOUT,
            )
        except Exception as exc:
            if send_to_browser:
                self.send_response(502)
                self.end_headers()
                self.wfile.write(str(exc).encode("utf-8", errors="replace"))
            print(f"[forward] {host}{event['path']} failed: {exc}")
            return None

        forwarded_event = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "upstream_for": f"{host}{event['path']}",
            "status": response.status_code,
            "headers": scrub_headers(dict(response.headers)),
            "body_preview": response.text[:1000],
        }
        if self.events_path:
            with open(self.events_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(forwarded_event, separators=(",", ":")))
                f.write("\n")
        print(
            f"[forward] {host}{event['path']} -> HTTP {response.status_code} "
            f"location={response.headers.get('Location', '')[:160]}"
        )
        if (
            host == "lsa.lenovo.com"
            and event["path"] == "/Interface/user/oauth2/callback.jhtml"
        ):
            self._capture_softwarefix_callback(response)

        if not send_to_browser:
            return response

        self.send_response(response.status_code)
        for key, value in response.headers.items():
            if key.lower() in {
                "content-encoding",
                "transfer-encoding",
                "connection",
                "content-length",
            }:
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response.content)))
        self.end_headers()
        self.wfile.write(response.content)
        return response

    def _capture_softwarefix_callback(self, response):
        try:
            payload = response.json()
        except ValueError:
            payload = None
        result = {
            "status": response.status_code,
            "raw": response.text,
            "json": payload,
        }
        callback = {}
        if isinstance(payload, dict) and isinstance(payload.get("content"), str):
            parsed = urllib.parse.urlparse(payload["content"])
            params = urllib.parse.parse_qs(parsed.query)
            callback = {
                "scheme": parsed.scheme,
                "fullName": params.get("fullName", [None])[0],
                "Authorization": params.get("Authorization", [None])[0],
                "raw": payload["content"],
            }
        result["softwarefix_callback"] = callback
        CaptureHandler.softwarefix_callback_result = result
        CaptureHandler.softwarefix_callback = callback
        token = callback.get("Authorization")
        if token:
            print(f"\n[+] CAPTURED SOFTWARE FIX TOKEN: {redact(token)}")
        else:
            code = payload.get("code") if isinstance(payload, dict) else None
            desc = (
                payload.get("desc")
                if isinstance(payload, dict)
                else response.text[:120]
            )
            print(
                f"\n[-] Software Fix callback response had no Authorization: code={code} desc={desc}"
            )

    def log_message(self, *args):
        pass


def generate_cert():
    """Generate self-signed cert for captured Lenovo OAuth hosts."""
    alt_names = ",".join(f"DNS:{host}" for host in CAPTURE_HOSTS)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            KEY_FILE,
            "-out",
            CERT_FILE,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=lsa.lenovo.com",
            "-addext",
            f"subjectAltName={alt_names}",
        ],
        capture_output=True,
    )
    print(f"[+] Generated self-signed cert for {', '.join(CAPTURE_HOSTS)}")


def resolve_upstream_hosts():
    resolved = {}
    for host in CAPTURE_HOSTS:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        for info in infos:
            ip = info[4][0]
            if ":" not in ip:
                resolved[host] = ip
                break
        if host not in resolved and infos:
            resolved[host] = infos[0][4][0]
    return resolved


def add_hosts_entry():
    with open(HOSTS_FILE, "r") as f:
        content = f.read()
    missing = [host for host in CAPTURE_HOSTS if f"127.0.0.1 {host}" not in content]
    if missing:
        with open(HOSTS_FILE, "a") as f:
            for host in missing:
                f.write(f"\n127.0.0.1 {host}\n")
                print(f"[+] Added '127.0.0.1 {host}' to /etc/hosts")
    # Flush DNS cache
    subprocess.run(["dscacheutil", "-flushcache"], capture_output=True)
    subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True)


def remove_hosts_entry():
    with open(HOSTS_FILE, "r") as f:
        lines = f.readlines()
    with open(HOSTS_FILE, "w") as f:
        for line in lines:
            if not any(f"127.0.0.1 {host}" in line for host in CAPTURE_HOSTS):
                f.write(line)
    subprocess.run(["dscacheutil", "-flushcache"], capture_output=True)
    subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True)
    print("[+] Removed hosts entry, restored DNS")


def generate_pkce():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


def generate_lenovoid_ctx():
    plain = "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(8)
    )
    encoded = base64.b64encode(plain.encode("ascii")).decode("ascii").rstrip("=")
    return plain, f"{encoded}encode"


def build_software_fix_google_url(ctx_encoded, device_id):
    params = {
        "thirdName": "google",
        "lenovoid.action": "uilogin",
        "lenovoid.realm": LENOVO_REALM,
        "lenovoid.ctx": ctx_encoded,
        "lenovoid.lang": "en_US",
        "lenovoid.uinfo": "null",
        "lenovoid.cb": LENOVO_OAUTH_CALLBACK,
        "lenovoid.vb": "null",
        "lenovoid.display": "null",
        "lenovoid.idp": "null",
        "lenovoid.source": LENOVO_SOURCE,
        "oldState": "null",
        "lenovoid.prompt": "login",
        "lenovoid.deviceId": device_id,
    }
    query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote, safe=":/")
    return f"https://passport-glb.lenovo.com/glbwebauthnv6/thirdOauth?{query}"


def build_software_fix_prelogin_url(ctx_encoded):
    # This mirrors the preLogin URL observed from Software Fix. The preLogin
    # page creates Lenovo's server-side cacheKey for lenovoid.ctx; opening
    # thirdOauth directly can fail with "cacheKey expired".
    params = {
        "lenovoid.action": "uilogin",
        "lenovoid.realm": LENOVO_REALM,
        "lenovoid.ctx": ctx_encoded,
        "lenovoid.lang": "en_US",
        "lenovoid.uinfo": "null",
        "lenovoid.cb": LENOVO_OAUTH_CALLBACK,
        "lenovoid.vp": "null",
        "lenovoid.display": "null",
        "lenovoid_idp": "null",
        "lenovoid.source": LENOVO_SOURCE,
        "lenovoid.thirdname": "null",
        "lenovoid.idreinfo": "null",
        "lenovoid.autologinname": "null",
        "lenovoid.userType": "null",
        "lenovoid.sdk": "null",
        "lenovoid.oauthstate": "null",
        "lenovoid.options": "null",
        "lenovoid.hidesocial": "null",
        "lenovoid.hideregphone": "1",
        "lenovoid.hideloginreg": "1",
        "lenovoid.hidephonelogin": "1",
        "lenovoid.zoom": "1",
        "lenovoid.privacy": "null",
        "lenovoid.Terms": "null",
        "lenovoid.hidelanguage": "1",
        "lenovoid.hidegoogle": "1",
        "lenovoid.hidemicrosoft": "1",
        "lenovoid.hidefacebook": "0",
        "lenovoid.hidetwitch": "0",
        "lenovoid.hidediscord": "0",
        "lenovoid.hidesteam": "0",
        "lenovoid.hidemoto": "null",
        "lenovoid.theme": "id",
        "lenovoid.deviceinfo": "null",
        "lenovoid.deviceId": "null",
        "lenovoid.prompt": "login",
        "username": "null",
    }
    query = urllib.parse.urlencode(params, safe=":/")
    return f"https://passport-glb.lenovo.com/glbwebauthnv6/preLogin?{query}"


def build_direct_oauth_url(state, challenge, device_id):
    params = {
        "state": state,
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "lenovoid.action": "uilogin",
        "lenovoid.realm": LENOVO_REALM,
        "lenovoid.lang": "en_US",
        "lenovoid.source": LENOVO_SOURCE,
        "lenovoid.deviceId": device_id,
        "prompt": "login",
    }
    return f"https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/authorize?{urllib.parse.urlencode(params)}"


def fetch_software_fix_login_url(client_uuid):
    """Ask the LRSA API for the same Lenovo ID login URL Software Fix uses."""
    client = LRSAClient(client_uuid=client_uuid)
    result = client.get_software_fix_login_url()
    payload = result.get("json")
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"TIP_URL response was not JSON: {result.get('raw', '')[:240]}"
        )
    if payload.get("code") != "0000" or not payload.get("content"):
        raise RuntimeError(
            f"TIP_URL lookup failed: code={payload.get('code')} desc={payload.get('desc')}"
        )
    return payload["content"], result


def exchange_code(code, verifier):
    """Exchange auth code for access token via PKCE."""
    # Need to bypass our own hosts redirect for the token endpoint
    # passport-glb.lenovo.com is NOT redirected, only lsa.lenovo.com
    r = requests.post(
        TOKEN_ENDPOINT,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": verifier,
        },
        verify=False,
    )
    print(f"\n[*] Token exchange: {r.status_code}")
    if r.status_code == 200:
        return r.json()
    print(f"    Response: {r.text[:500]}")
    return None


def test_firmware(token, client_uuid):
    """Test token on firmware API — need to remove hosts entry first so we hit real server."""
    remove_hosts_entry()
    print("\n[*] Testing token on real lsa.lenovo.com...")

    headers = {
        "Content-Type": "application/json",
        "Request-Tag": "lmsa",
        "Authorization": f"Bearer {token}",
        "clientVersion": "7.5.5.19",
        "clientUUID": client_uuid,
        "language": "en-US",
        "windowsInfo": base64.b64encode(b"Windows 10").decode("ascii"),
    }

    results = []
    for ep, body in [
        ("/user/getSFUserInfo.jhtml", None),
        (
            "/rescueDevice/getNewResource.jhtml",
            {"modelName": "Lenovo TB390FU", "sn": "HNQ06MHH"},
        ),
        ("/client/initToken.jhtml", {"clientVersion": "7.5.5.19"}),
        ("/rescueDevice/getRomMatchParams.jhtml", {"modelName": "Lenovo TB390FU"}),
        ("/priv/getRomList.jhtml", {"modelName": "TB390FU"}),
    ]:
        if body is None:
            r = requests.get(
                f"{INTERFACE_URL}{ep}",
                headers=headers,
                verify=False,
                allow_redirects=False,
                timeout=20,
            )
        else:
            wrapped = {
                "client": {"version": "7.5.5.19"},
                "dparams": body,
                "language": "en-US",
                "windowsInfo": "Windows 10, 64-bit",
            }
            r = requests.post(
                f"{INTERFACE_URL}{ep}",
                headers=headers,
                data=json.dumps(wrapped, separators=(",", ":")),
                verify=False,
                allow_redirects=False,
                timeout=20,
            )
        result = {"endpoint": ep, "status": r.status_code, "raw": r.text}
        try:
            result["json"] = r.json()
        except ValueError:
            result["json"] = None
        results.append(result)
        code = result["json"].get("code") if isinstance(result["json"], dict) else None
        desc = (
            result["json"].get("desc")
            if isinstance(result["json"], dict)
            else r.text[:80]
        )
        print(f"  {ep}: HTTP {r.status_code} code={code} desc={desc}")
        if isinstance(result["json"], dict):
            data = result["json"]
            if data.get("code") == "0000":
                print("\n[+] FIRMWARE DATA!")
                print(json.dumps(data, indent=2))
    return results


def main():
    global CAPTURE_HOSTS

    parser = argparse.ArgumentParser(
        description="Capture Lenovo ID OAuth callback for LRSA"
    )
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument(
        "--external-login",
        action="store_true",
        help="Only start the lsa.lenovo.com callback listener; initiate login from the real Software Fix client.",
    )
    parser.add_argument(
        "--login-url-mode",
        choices=[
            "software-fix-api",
            "software-fix-prelogin",
            "software-fix-google",
            "direct-oauth",
        ],
        default="software-fix-api",
        help=(
            "software-fix-api asks /dictionary/getApiInfo.jhtml for TIP_URL, matching Software Fix; "
            "software-fix-prelogin opens only the observed preLogin page; software-fix-google opens the Google "
            "thirdOauth URL directly; direct-oauth is a fallback."
        ),
    )
    parser.add_argument(
        "--capture-passport",
        action="store_true",
        help=(
            "Also map passport-glb.lenovo.com to this capture server. "
            "Normal Brave/Chrome will block this host because it uses HSTS."
        ),
    )
    parser.add_argument(
        "--test-token",
        action="store_true",
        help="After capture, probe a few LRSA API endpoints. Off by default so login returns immediately.",
    )
    args = parser.parse_args()
    if args.capture_passport:
        CAPTURE_HOSTS = DEFAULT_CAPTURE_HOSTS + (PASSPORT_HOST,)

    if os.geteuid() != 0:
        print("Need sudo to modify /etc/hosts and bind port 443")
        print("Run: sudo python3 -m lrsa.capture_server")
        sys.exit(1)

    print("=" * 60)
    print("LRSA OAuth Code Capture Server")
    print("=" * 60)
    CaptureHandler.auth_code = None
    CaptureHandler.auth_state = None
    CaptureHandler.auth_scope = None
    CaptureHandler.auth_code_at = None
    CaptureHandler.softwarefix_callback_result = None
    CaptureHandler.softwarefix_callback = None
    args.out_dir.mkdir(parents=True, exist_ok=True)
    CaptureHandler.events_path = args.out_dir / "events.jsonl"
    print(f"[+] Capture log: {CaptureHandler.events_path}")
    print(f"[+] Capturing hosts: {', '.join(CAPTURE_HOSTS)}")
    if args.capture_passport:
        print(
            "[!] passport-glb.lenovo.com uses HSTS; normal browsers will block the local cert."
        )

    CaptureHandler.upstream_ips = resolve_upstream_hosts()
    print(f"[+] Upstream IPs: {CaptureHandler.upstream_ips}")

    # Generate the browser login URL before /etc/hosts points lsa.lenovo.com at
    # this capture server. Software Fix obtains this URL from the LRSA API.
    verifier, challenge = generate_pkce()
    state = str(uuid.uuid4())
    client_uuid = str(uuid.uuid4())
    ctx_plain, ctx_encoded = generate_lenovoid_ctx()
    device_id = SOFTWARE_FIX_DEVICE_ID
    prelogin_url = build_software_fix_prelogin_url(ctx_encoded)
    google_url = build_software_fix_google_url(ctx_encoded, device_id)
    login_seed = None

    print(f"[+] PKCE generated, state: {state}")
    if args.login_url_mode == "software-fix-api":
        auth_url, login_seed = fetch_software_fix_login_url(client_uuid)
        save_json(args.out_dir / "login_url_response.json", login_seed)
        parsed_auth = urllib.parse.urlparse(auth_url)
        parsed_auth_query = urllib.parse.parse_qs(parsed_auth.query)
        state = parsed_auth_query.get("state", [state])[0]
        print(f"[+] Software Fix login URL fetched from TIP_URL, state: {state}")
    elif args.login_url_mode == "direct-oauth":
        auth_url = build_direct_oauth_url(state, challenge, device_id)
    elif args.login_url_mode == "software-fix-google":
        auth_url = google_url
    else:
        auth_url = prelogin_url
        print(f"[+] LenovoID context: {ctx_plain}")

    # Save PKCE / launch metadata for debugging.
    save_json(
        args.out_dir / "pkce.json",
        {
            "code_verifier": verifier,
            "state": state,
            "client_uuid": client_uuid,
            "lenovoid_ctx": ctx_plain,
            "lenovoid_ctx_encoded": ctx_encoded,
            "login_url_mode": args.login_url_mode,
            "login_seed": login_seed,
        },
    )

    # Generate cert
    generate_cert()

    # Add hosts entry
    add_hosts_entry()

    # Cleanup on exit
    def cleanup(sig=None, frame=None):
        print("\n[*] Cleaning up...")
        remove_hosts_entry()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        # Start HTTPS server on port 443
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT_FILE, KEY_FILE)

        server = HTTPServer(("0.0.0.0", 443), CaptureHandler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.timeout = 1
        print("[+] HTTPS server running on :443")

        # Open browser or wait for the real Software Fix client to do it.
        if args.external_login:
            print("\n[*] External Software Fix login mode.")
            print("[*] Start login from the installed Software Fix client now.")
            print("[*] This listener will capture the final lsa.lenovo.com callback.")
        else:
            print("\n[*] Login URL:")
            print(auth_url)
        if args.login_url_mode == "software-fix-api":
            print("[*] This URL was returned by Lenovo's Software Fix API (TIP_URL).")
            print(
                "[*] If lsa.lenovo.com shows a certificate warning, accept it for this test."
            )
        elif args.login_url_mode == "software-fix-prelogin":
            print(
                "\n[*] ThirdOauth URL (do not open directly unless preLogin does not navigate):"
            )
            print(google_url)
            print("\n[*] PreLogin URL:")
            print(prelogin_url)
            print(
                "[*] If lsa.lenovo.com shows a certificate warning, accept it for this test."
            )
        if not args.no_browser and not args.external_login:
            webbrowser.open(auth_url)

        # Wait for callback
        print("[*] Waiting for OAuth callback...")
        while CaptureHandler.softwarefix_callback_result is None:
            server.handle_request()
            if (
                CaptureHandler.auth_code_at
                and time.time() - CaptureHandler.auth_code_at > 45
            ):
                print("[!] Timed out waiting for browser-side Software Fix callback.")
                break

        code = CaptureHandler.auth_code
        if not code:
            print("\n[-] OAuth callback was not captured.")
            return
        print(f"\n[+] Got code: {code[:50]}...")

        # Restore DNS before making our own token/API calls, otherwise the
        # Python requests client would hit this local capture server.
        remove_hosts_entry()

        # The real Lenovo success page performs an intermediate state setup
        # before calling /Interface/user/oauth2/callback.jhtml. Prefer the
        # browser-captured callback response over a direct Python replay.
        callback_result = CaptureHandler.softwarefix_callback_result or {}
        callback = callback_result.get("softwarefix_callback") or {}
        access_token = callback.get("Authorization")
        save_json(args.out_dir / "callback_response.json", callback_result)
        print(
            f"[+] Software Fix callback response saved: {args.out_dir / 'callback_response.json'}"
        )
        if access_token:
            print(f"\n{'=' * 60}")
            print(f"[+] SOFTWARE FIX TOKEN: {redact(access_token)}")

            save_json(args.out_dir / "token_response.json", callback_result)
            print(
                f"[+] Callback response saved: {args.out_dir / 'token_response.json'}"
            )

            interface_results = []
            if args.test_token:
                interface_results = test_firmware(access_token, client_uuid)
            session = {
                "method": "lenovoid-capture",
                "client_uuid": client_uuid,
                "token": access_token,
                "token_response": callback_result,
                "fullName": callback.get("fullName"),
                "interface_results": interface_results,
            }
            save_json(args.out_dir / "login_session.json", session)
            print(f"[+] Session saved: {args.out_dir / 'login_session.json'}")
        else:
            print("\n[-] Software Fix callback did not return Authorization")
            raw = callback_result.get("raw") or callback_result.get("decrypted") or ""
            payload = callback_result.get("json")
            if isinstance(payload, dict):
                print(f"    code={payload.get('code')} desc={payload.get('desc')}")
                content = payload.get("content") or payload.get("msg")
                if content:
                    print(f"    content={str(content)[:240]}")
            elif raw:
                print(f"    response={raw[:240]}")

    finally:
        cleanup()


if __name__ == "__main__":
    main()
