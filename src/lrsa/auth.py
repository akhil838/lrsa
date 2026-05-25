"""Authentication helpers for the LRSA standalone workflow."""

import json
import os
import urllib.parse
import webbrowser
from pathlib import Path

from .oauth import build_auth_url, generate_pkce


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def extract_token_from_file(path):
    data = load_json(path)
    for key in ("token", "access_token", "id_token"):
        value = data.get(key)
        if value:
            return value
    full_response = data.get("full_response")
    if isinstance(full_response, dict):
        for key in ("access_token", "id_token"):
            value = full_response.get(key)
            if value:
                return value
    raise ValueError(f"No token found in {path}")


def lenovo_id_login(open_browser=True):
    verifier, challenge = generate_pkce()
    state = os.urandom(16).hex()
    auth_url = build_auth_url(state, challenge)

    print("\nLenovo ID login URL:")
    print(auth_url)
    if open_browser:
        webbrowser.open(auth_url)

    callback_url = input("\nPaste final callback URL: ").strip()
    parsed = urllib.parse.parse_qs(urllib.parse.urlparse(callback_url).query)
    code = parsed.get("code", [None])[0]
    if not code:
        raise RuntimeError("Callback URL did not contain a code parameter")
    scope = parsed.get("scope", ["openid"])[0]
    callback_state = parsed.get("state", [state])[0]

    from .client import LRSAClient

    client = LRSAClient()
    callback_result = client.lenovo_id_oauth_callback(
        code, scope=scope, state=callback_state
    )
    callback = callback_result.get("softwarefix_callback") or {}
    token = callback.get("Authorization")
    if not token:
        raise RuntimeError(
            "Software Fix callback response did not include Authorization"
        )
    token_data = {
        "code": code,
        "scope": scope,
        "state": callback_state,
        "fullName": callback.get("fullName"),
        "callback_response": callback_result,
    }
    return token, token_data
