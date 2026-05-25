#!/usr/bin/env python3
"""
LRSA OAuth2 PKCE Client — Lenovo ID login to get firmware download token.

Actual OAuth2 flow (captured from LRSA):
  Authorization endpoint: https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/authorize
  Token endpoint: https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/token
  Client ID: 127cbff4e99dd5579db0627769509be972a3f38ad0dd11f2f2a7947516c923f0
  Redirect URI: https://lsa.lenovo.com/Tips/lenovoIdSuccess.html
  Scope: openid
  PKCE: S256

Flow:
1. Generate code_verifier + code_challenge (PKCE)
2. Open browser → Lenovo ID login
3. User logs in → redirect to lsa.lenovo.com/Tips/lenovoIdSuccess.html?code=XXX
4. User copies the URL, pastes here
5. Exchange code + code_verifier for access_token
6. Use access_token as Bearer for /Interface/ API
"""

import webbrowser
import urllib.parse
import hashlib
import base64
import os
import json
import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# OAuth2 configuration (extracted from LRSA)
AUTH_ENDPOINT = "https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/authorize"
TOKEN_ENDPOINT = "https://passport-glb.lenovo.com/v1.0/utility/lenovoid/oauth2/token"
CLIENT_ID = "127cbff4e99dd5579db0627769509be972a3f38ad0dd11f2f2a7947516c923f0"
REDIRECT_URI = "https://lsa.lenovo.com/Tips/lenovoIdSuccess.html"
SCOPE = "openid"
INTERFACE_URL = "https://lsa.lenovo.com/Interface"


def generate_pkce():
    """Generate PKCE code_verifier and code_challenge."""
    # code_verifier: 43-128 chars, URL-safe
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    # code_challenge: SHA256(verifier), base64url-encoded
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return verifier, challenge


def build_auth_url(state, code_challenge):
    """Build the OAuth2 authorization URL."""
    params = {
        "state": state,
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "lenovoid.lang": "en_US",
        "prompt": "login",
    }
    return f"{AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"


def exchange_code_for_token(code, code_verifier):
    """Exchange authorization code for access token using PKCE."""
    print("\n[*] Exchanging code for access token...")

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": code_verifier,
    }

    r = requests.post(TOKEN_ENDPOINT, data=data, verify=False)
    print(f"    Status: {r.status_code}")
    print(f"    Response: {r.text[:500]}")

    if r.status_code == 200:
        try:
            token_data = r.json()
            if "access_token" in token_data:
                return token_data
            # Some OAuth servers return token differently
            if "id_token" in token_data:
                return token_data
        except Exception:
            pass

    # Try with JSON content type
    print("\n[*] Retry with JSON content type...")
    r = requests.post(TOKEN_ENDPOINT, json=data, verify=False)
    print(f"    Status: {r.status_code}")
    print(f"    Response: {r.text[:500]}")

    if r.status_code == 200:
        try:
            return r.json()
        except Exception:
            pass

    return None


def test_firmware_api(token):
    """Test the token against firmware download API."""
    print(f"\n{'=' * 60}")
    print("[*] Testing token on LRSA firmware API...")

    headers = {
        "Content-Type": "application/json",
        "Request-Tag": "lmsa",
        "Authorization": f"Bearer {token}",
        "clientVersion": "7.5.5.19",
        "clientUUID": "lrsa-python-001",
        "language": "en",
    }

    endpoints = [
        ("/client/initToken.jhtml", {"clientVersion": "7.5.5.19"}),
        ("/user/guestLogin.jhtml", {"clientVersion": "7.5.5.19"}),
        ("/rescueDevice/getRomMatchParams.jhtml", {"modelName": "Lenovo TB390FU"}),
        (
            "/rescueDevice/getNewResource.jhtml",
            {"modelName": "Lenovo TB390FU", "sn": "HNQ06MHH"},
        ),
        ("/priv/getRomList.jhtml", {"modelName": "TB390FU"}),
    ]

    for path, body in endpoints:
        r = requests.post(
            f"{INTERFACE_URL}{path}", headers=headers, json=body, verify=False
        )
        try:
            data = r.json()
            status_icon = "+" if data.get("code") == "0000" else "-"
            print(
                f"  [{status_icon}] {path}: code={data.get('code')} {str(data)[:150]}"
            )
            if data.get("code") == "0000":
                print(f"\n[+] SUCCESS on {path}!")
                print(json.dumps(data, indent=2))
                return data
        except Exception:
            print(f"  [?] {path}: {r.status_code} {r.text[:100]}")

    return None


def main():
    print("=" * 60)
    print("LRSA Python Client — OAuth2 PKCE Login")
    print("=" * 60)

    # Step 1: Generate PKCE
    code_verifier, code_challenge = generate_pkce()
    state = str(__import__("uuid").uuid4())

    print(f"[*] State: {state}")
    print(f"[*] Code verifier: {code_verifier[:20]}...")
    print(f"[*] Code challenge: {code_challenge}")

    # Step 2: Open browser
    auth_url = build_auth_url(state, code_challenge)
    print("\n[*] Opening browser for login...")
    webbrowser.open(auth_url)

    print()
    print("=" * 60)
    print("After logging in, you'll be redirected to a page that says:")
    print("  'Please go to the client to check the login process'")
    print()
    print("COPY the full URL from browser address bar and paste below.")
    print("It should look like:")
    print("  https://lsa.lenovo.com/Tips/lenovoIdSuccess.html?code=XXXXX&...")
    print("=" * 60)

    # Read from stdin if available, otherwise prompt
    if not sys.stdin.isatty():
        print("\n[!] Non-interactive mode. Pass URL as argument:")
        print("    python3 -m lrsa.oauth --url <CALLBACK_URL>")
        return

    url = input("\nPaste callback URL: ").strip()

    # Extract code from URL
    parsed = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    code = parsed.get("code", [None])[0]

    if not code:
        print("[-] No 'code' parameter found in URL!")
        return

    print(f"[+] Got authorization code: {code[:40]}...")

    # Step 3: Exchange for token
    token_data = exchange_code_for_token(code, code_verifier)

    if token_data:
        access_token = token_data.get("access_token") or token_data.get("id_token")
        print("\n[+] ACCESS TOKEN OBTAINED!")
        print(f"    Token: {str(access_token)[:80]}...")

        # Save
        with open("lrsa_token.json", "w") as f:
            json.dump(
                {
                    "token": access_token,
                    "full_response": token_data,
                    "code_verifier": code_verifier,
                    "state": state,
                },
                f,
                indent=2,
            )
        print("[+] Saved to lrsa_token.json")

        # Step 4: Test on firmware API
        test_firmware_api(access_token)
    else:
        print("\n[-] Token exchange failed.")
        print("[*] The code might have expired. Try again quickly after login.")


if __name__ == "__main__":
    if "--url" in sys.argv:
        idx = sys.argv.index("--url") + 1
        if idx < len(sys.argv):
            # Parse code from URL and use stored verifier
            url = sys.argv[idx]
            parsed = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            code = parsed.get("code", [None])[0]
            if code:
                # Try to load saved verifier
                try:
                    with open("lrsa_pkce.json") as f:
                        pkce = json.load(f)
                    result = exchange_code_for_token(code, pkce["code_verifier"])
                    if result:
                        token = result.get("access_token") or result.get("id_token")
                        test_firmware_api(token)
                except FileNotFoundError:
                    print("No saved PKCE state. Run without --url first.")
    elif "--token" in sys.argv:
        idx = sys.argv.index("--token") + 1
        if idx < len(sys.argv):
            test_firmware_api(sys.argv[idx])
    else:
        main()
