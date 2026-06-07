"""Authentication and session helpers for LRSA workflows."""

from __future__ import annotations

import json
import urllib.parse
import uuid
import webbrowser
from pathlib import Path
from typing import Any

from lrsa.logging import get_logger

from .constants import CLIENT_ID, REDIRECT_URI, SCOPE, TOKEN_ENDPOINT
from .oauth import build_auth_url, exchange_code_for_token, generate_pkce

SESSION_FILE_NAME = "login_session.json"


def load_json(path: str | Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str | Path, data: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def session_path(work_dir: str | Path) -> Path:
    return Path(work_dir) / SESSION_FILE_NAME


def load_session(path: str | Path) -> dict[str, Any] | None:
    path = Path(path)
    if not path.exists():
        return None
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"Session file {path} did not contain a JSON object")
    return data


def delete_session(path: str | Path) -> None:
    path = Path(path)
    if path.exists():
        path.unlink()


def extract_token_from_data(data: Any) -> str | None:
    if isinstance(data, dict):
        for key in (
            "token",
            "access_token",
            "id_token",
            "jwt",
            "jwtToken",
            "Authorization",
        ):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.removeprefix("Bearer ").strip()
        for key in (
            "softwarefix_callback",
            "token_response",
            "callback_response",
            "full_response",
            "user_info",
            "login_seed",
            "session",
            "response",
            "json",
            "content",
            "data",
            "desc",
        ):
            token = extract_token_from_data(data.get(key))
            if token:
                return token
    elif isinstance(data, list):
        for item in data:
            token = extract_token_from_data(item)
            if token:
                return token
    elif isinstance(data, str):
        stripped = data.strip()
        if not stripped:
            return None
        parts = stripped.removeprefix("Bearer ").strip().split(".")
        if len(parts) == 3 and parts[0].startswith("eyJ"):
            return stripped.removeprefix("Bearer ").strip()
        try:
            return extract_token_from_data(json.loads(stripped))
        except ValueError:
            return None
    return None


def extract_token_from_file(path: str | Path) -> str:
    data = load_json(path)
    token = extract_token_from_data(data)
    if token:
        return token
    raise ValueError(f"No token found in {path}")


def _parse_login_url_result(result: dict[str, Any]) -> tuple[str | None, str | None]:
    payload = result.get("json")
    if not isinstance(payload, dict):
        return None, None
    content = payload.get("content")
    if isinstance(content, str):
        return content, None
    if isinstance(content, dict):
        auth_url = content.get("login_url") or content.get("loginUrl")
        token_url = content.get("token_url") or content.get("tokenUrl")
        return (
            str(auth_url) if isinstance(auth_url, str) and auth_url else None,
            str(token_url) if isinstance(token_url, str) and token_url else None,
        )
    return None, None


def parse_callback_url(callback_url: str) -> dict[str, str | None]:
    parsed = urllib.parse.urlparse(callback_url.strip())
    query = urllib.parse.parse_qs(parsed.query)

    def first(name: str) -> str | None:
        values = query.get(name)
        if not values:
            return None
        value = values[0].strip()
        return value or None

    return {
        "raw": callback_url.strip(),
        "scheme": parsed.scheme or None,
        "host": parsed.netloc or None,
        "code": first("code"),
        "scope": first("scope"),
        "state": first("state"),
        "client_id": first("client_id"),
        "redirect_uri": first("redirect_uri"),
        "code_verifier": first("code_verifier"),
        "Authorization": first("Authorization"),
        "fullName": first("fullName"),
        "lenovoid_wust": first("lenovoid.wust"),
    }


def begin_lenovo_id_login(
    client_uuid: str | None = None, open_browser: bool = True
) -> dict[str, Any]:
    verifier, challenge = generate_pkce()
    state = str(uuid.uuid4())

    from ..api.client import LRSAClient

    client = LRSAClient(client_uuid=client_uuid)
    login_seed = client.get_software_fix_login_url()
    auth_url, token_url = _parse_login_url_result(login_seed)
    if not auth_url:
        auth_url = build_auth_url(state, challenge)
    seed = {
        "client_uuid": client.client_uuid,
        "state": state,
        "scope": SCOPE,
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
        "token_url": token_url or TOKEN_ENDPOINT,
        "auth_url": auth_url,
        "login_seed": login_seed,
    }
    if open_browser:
        webbrowser.open(auth_url)
    return seed


def complete_lenovo_id_login(
    callback_url: str,
    seed: dict[str, Any] | None = None,
    client_uuid: str | None = None,
) -> dict[str, Any]:
    parsed = parse_callback_url(callback_url)

    from ..api.client import LRSAClient

    effective_client_uuid = client_uuid or (
        str(seed.get("client_uuid"))
        if isinstance(seed, dict) and seed.get("client_uuid")
        else None
    )
    client = LRSAClient(client_uuid=effective_client_uuid)

    token_response: dict[str, Any] | None = None
    token = parsed.get("Authorization")
    full_name = parsed.get("fullName")

    code = parsed.get("code")
    if not token and code:
        token_response = client.lenovo_id_oauth_callback(
            code,
            scope=parsed.get("scope")
            or (
                str(seed.get("scope"))
                if isinstance(seed, dict) and seed.get("scope")
                else SCOPE
            ),
            state=parsed.get("state")
            or (
                str(seed.get("state"))
                if isinstance(seed, dict) and seed.get("state")
                else None
            ),
        )
        callback = token_response.get("softwarefix_callback") or {}
        if isinstance(callback, dict):
            callback_token = callback.get("Authorization")
            callback_name = callback.get("fullName")
            if isinstance(callback_token, str) and callback_token:
                token = callback_token
            if isinstance(callback_name, str) and callback_name:
                full_name = full_name or callback_name

    if not token and code:
        code_verifier = parsed.get("code_verifier") or (
            str(seed.get("code_verifier"))
            if isinstance(seed, dict) and seed.get("code_verifier")
            else None
        )
        if not code_verifier:
            raise RuntimeError(
                "Callback URL did not include code_verifier and no login seed was available."
            )
        oauth_response = exchange_code_for_token(code, code_verifier)
        token_response = {"oauth_token": oauth_response}
        if oauth_response:
            token = oauth_response.get("access_token") or oauth_response.get("id_token")

    if not token and parsed.get("lenovoid_wust"):
        token = parsed["lenovoid_wust"]

    if not token:
        raise RuntimeError(
            "Could not derive a Lenovo ID token from the callback URL or Software Fix callback response."
        )

    client.token = token
    user_info = client.lenovo_id_user_info()
    return {
        "method": "lenovoid",
        "client_uuid": client.client_uuid,
        "token": token,
        "fullName": full_name,
        "callback_url": callback_url.strip(),
        "callback_params": parsed,
        "login_seed": seed,
        "token_response": token_response,
        "user_info": user_info,
        "auto_login": True,
    }


def logout_session(session: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not session:
        return []

    from ..api.client import LRSAClient

    client = LRSAClient(
        client_uuid=str(session.get("client_uuid") or "") or None,
        token=extract_token_from_data(session),
    )
    results: list[dict[str, Any]] = []
    for name, action in (
        ("user_logout", client.user_logout),
        ("dispose_token", client.dispose_token),
    ):
        try:
            result = action()
        except Exception as exc:
            get_logger(__name__).warning("%s failed: %s", name, exc)
            results.append({"step": name, "ok": False, "error": str(exc)})
        else:
            results.append({"step": name, "ok": True, "result": result})
    return results


def lenovo_id_login(open_browser: bool = True) -> tuple[str, dict[str, Any]]:
    seed = begin_lenovo_id_login(open_browser=open_browser)
    get_logger(__name__).info("\nLenovo ID login URL:")
    get_logger(__name__).info(seed["auth_url"])
    callback_url = input("\nPaste final callback URL: ").strip()
    session = complete_lenovo_id_login(callback_url, seed=seed)
    token = extract_token_from_data(session)
    if not token:
        raise RuntimeError("Login completed without a usable token")
    return token, session
