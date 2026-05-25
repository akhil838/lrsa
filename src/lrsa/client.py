"""LRSA API client for Lenovo Software Fix / Rescue and Smart Assistant.

The .NET client builds API URLs from ``BaseHttpUrl + "/Interface"`` and wraps
POST parameters in ``WebApiModel.RequestModel`` before sending them. The older
version of this port talked to ``/lmsa-web`` and sent raw endpoint payloads,
which is why most calls were redirected or rejected.
"""

import argparse
import base64
import json
import platform
import urllib.parse
import uuid

import requests
import urllib3

from .crypto import LRSACrypto
from . import endpoints
from .config import BASE_URL, CLIENT_VERSION, DEFAULT_LANGUAGE, DEFAULT_WINDOWS_VERSION

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class LRSAClient:
    def __init__(
        self,
        client_uuid=None,
        token=None,
        base_url=BASE_URL,
        language=DEFAULT_LANGUAGE,
        windows_version=DEFAULT_WINDOWS_VERSION,
    ):
        self.base_url = base_url.rstrip("/")
        self.client_uuid = client_uuid or str(uuid.uuid4())
        self.language = language
        self.windows_version = windows_version
        self.windows_info = f"{windows_version}, {self._system_type()}"
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36"
                ),
                "Cache-Control": "no-cache",
                "Request-Tag": "lmsa",
                "clientVersion": CLIENT_VERSION,
                "windowsInfo": self._windows_version_b64(),
                "language": self.language,
            }
        )
        self.token = token
        self.crypto = LRSACrypto()

    @staticmethod
    def _system_type():
        machine = platform.machine().lower()
        return (
            "64-bit" if "64" in machine or machine in {"arm64", "aarch64"} else "32-bit"
        )

    def _windows_version_b64(self):
        return base64.b64encode(self.windows_version.encode("utf-8")).decode("ascii")

    def _request_model(self, data):
        return {
            "client": {"version": CLIENT_VERSION},
            "dparams": data,
            "language": self.language,
            "windowsInfo": self.windows_info,
        }

    def _auth_headers(self, author=True):
        headers = {}
        if author:
            headers["clientUUID"] = self.client_uuid
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
        return headers

    @staticmethod
    def _decode_response(response, crypto):
        result = {
            "status": response.status_code,
            "headers": dict(response.headers),
            "raw": response.text,
            "json": None,
            "decrypted": None,
        }

        if response.text:
            try:
                result["json"] = response.json()
            except ValueError:
                pass
            try:
                result["decrypted"] = crypto.decrypt(response.text.strip())
            except Exception:
                pass

        return result

    def _post(self, path, data=None, encrypted=False, author=True, wrap=True):
        url = f"{self.base_url}{path}"
        body = self._request_model(data) if wrap and data is not None else data
        headers = self._auth_headers(author)
        headers["Content-Type"] = "application/json"

        if encrypted and data:
            payload = self.crypto.encrypt(json.dumps(body, separators=(",", ":")))
            headers["Content-Type"] = "application/octet-stream"
            r = self.session.post(
                url, data=payload, headers=headers, allow_redirects=False
            )
        else:
            payload = None if body is None else json.dumps(body, separators=(",", ":"))
            r = self.session.post(
                url, data=payload, headers=headers, allow_redirects=False
            )

        result = self._decode_response(r, self.crypto)
        self._maybe_store_token(result)
        return result

    def _get(self, path, author=True, params=None):
        url = f"{self.base_url}{path}"
        r = self.session.get(
            url,
            headers=self._auth_headers(author),
            params=params,
            allow_redirects=False,
        )
        result = self._decode_response(r, self.crypto)
        self._maybe_store_token(result)
        return result

    def _maybe_store_token(self, result):
        candidates = []
        if result.get("json") is not None:
            candidates.append(result["json"])
        if result.get("decrypted"):
            try:
                candidates.append(json.loads(result["decrypted"]))
            except ValueError:
                pass

        for candidate in candidates:
            token = self._find_token(candidate)
            if token:
                self.token = token
                return token
        return None

    def _find_token(self, value):
        if isinstance(value, dict):
            for key in ("token", "jwt", "jwtToken", "access_token", "Authorization"):
                token = value.get(key)
                if isinstance(token, str) and token:
                    return token.removeprefix("Bearer ").strip()
            for key in ("content", "data", "desc", "resp"):
                token = self._find_token(value.get(key))
                if token:
                    return token
        elif isinstance(value, list):
            for item in value:
                token = self._find_token(item)
                if token:
                    return token
        elif isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("eyJ") or stripped.count(".") == 2:
                return stripped.removeprefix("Bearer ").strip()
            try:
                return self._find_token(json.loads(stripped))
            except ValueError:
                return None
        return None

    def get_rsa_key(self):
        return self._post(endpoints.RSA_PUBLIC_KEY)

    def init_token(self):
        return self._post(
            endpoints.INIT_TOKEN,
            {
                "clientVersion": CLIENT_VERSION,
                "clientUuid": self.client_uuid,
            },
        )

    def guest_login(self, account_id=None):
        """Log in as guest using the same payload shape as Software Fix.

        The .NET GuestLogin handler sends only {"accountId": UserData}; the
        client UUID is carried separately in the request headers.
        """
        return self._post(
            endpoints.GUEST_LOGIN,
            {
                "accountId": account_id or self.client_uuid,
            },
        )

    def guest_login_encrypted(self, account_id=None):
        return self._post(
            endpoints.GUEST_LOGIN,
            {
                "accountId": account_id or self.client_uuid,
            },
            encrypted=True,
        )

    def lenovo_id_user_info(self, token=None):
        """Fetch Lenovo ID account info after OAuth access-token capture."""
        if token:
            self.token = token
        return self._get(endpoints.LENOVOID_USER_INFO, author=True)

    def lenovo_id_oauth_callback(self, code, scope="openid", state=None):
        """Convert Lenovo ID OAuth code into the Software Fix API token."""
        params = {"code": code, "scope": scope}
        if state:
            params["state"] = state
        result = self._get(
            endpoints.LENOVOID_OAUTH2_CALLBACK, author=False, params=params
        )
        callback = self._parse_softwarefix_callback(result)
        token = callback.get("Authorization")
        if token:
            self.token = token
        result["softwarefix_callback"] = callback
        return result

    @staticmethod
    def _parse_softwarefix_callback(result):
        payload = result.get("json")
        if not isinstance(payload, dict):
            return {}
        content = payload.get("content")
        if not isinstance(content, str):
            return {}
        parsed = urllib.parse.urlparse(content)
        params = urllib.parse.parse_qs(parsed.query)
        return {
            "scheme": parsed.scheme,
            "fullName": params.get("fullName", [None])[0],
            "Authorization": params.get("Authorization", [None])[0],
            "raw": content,
        }

    def get_device_info(self, sn):
        return self._post(endpoints.GET_DEVICE_INFO, {"sn": sn})

    def get_rescue_rom(self, model_name, sn="", imei=""):
        if sn:
            return self.get_resources_by_sn(sn)
        if imei:
            return self.get_resources_by_imei(imei)
        return self._post(
            endpoints.RESCUE_GET_NEW_RESOURCE,
            {
                "modelName": model_name,
            },
        )

    def get_resources_by_sn(self, sn, category=None):
        data = {"sn": sn}
        if category:
            data["category"] = category
        return self._post(endpoints.RESCUE_GET_RESOURCE_BY_SN, data)

    def get_resources_by_imei(self, imei, imei2=None):
        data = {"imei": imei}
        if imei2:
            data["imei2"] = imei2
        return self._post(endpoints.RESCUE_GET_RESOURCE_BY_IMEI, data)

    def get_manual_resource(self, params):
        return self._post(endpoints.RESCUE_GET_RESOURCE, params)

    def get_rescue_market_names(self, category="tablet"):
        return self._post(endpoints.RESCUE_GET_MARKET_NAMES, {"category": category})

    def get_rescue_model_names(self, category="tablet"):
        return self._post(endpoints.RESCUE_GET_MODEL_NAMES, {"category": category})

    def get_models_by_market_name(self, market_name, category="tablet"):
        return self._post(
            endpoints.RESCUE_GET_MODELS_BY_MARKET_NAME,
            {
                "category": category,
                "marketName": market_name,
            },
        )

    def get_rom_match_params(self, model_name):
        return self._post(
            endpoints.RESCUE_GET_ROM_MATCH_PARAMS,
            {
                "modelName": model_name,
            },
        )

    def get_rom_list(self, model_name):
        return self._post(
            endpoints.GET_ROM_LIST,
            {
                "modelName": model_name,
            },
        )

    def get_rescue_recipe(self, model_name):
        return self._post(
            endpoints.RESCUE_GET_MODEL_RECIPE,
            {
                "modelName": model_name,
            },
        )

    def get_fastboot_support(self, model_name):
        return self._post(
            endpoints.GET_FASTBOOT_SUPPORT,
            {
                "modelName": model_name,
            },
        )

    def get_api_info(self):
        """Get the server's API info/dictionary — may reveal more endpoints."""
        return self._post(endpoints.GET_API_INFO)

    def get_software_fix_login_url(self):
        """Fetch the Lenovo ID authorize URL exactly as Software Fix does."""
        return self._post(endpoints.GET_API_INFO, {"key": "TIP_URL"})

    def bootstrap_guest_session(self, account_id=None, include_init_token=False):
        """Run the LRSA guest login sequence.

        Software Fix does not use /client/initToken.jhtml for guest login in
        the traced path. It initializes the RSA public key lazily, then posts
        to /user/guestLogin.jhtml with clientUUID authorization headers.
        """
        steps = [
            ("RSA Key", self.get_rsa_key),
        ]
        if include_init_token:
            steps.append(("Init Token", self.init_token))
        steps.append(("Guest Login", lambda: self.guest_login(account_id=account_id)))
        return [(name, fn()) for name, fn in steps]

    def probe_all(self, model="Lenovo TB390FU", sn="HNQ06MHH"):
        """Probe all known endpoints and report results."""
        print(f"Probing LRSA API for model={model}, sn={sn}")
        print(f"Base URL: {self.base_url}")
        print(f"Client UUID: {self.client_uuid}\n")

        tests = [
            ("RSA Key", self.get_rsa_key),
            ("Init Token", lambda: self.init_token()),
            ("Guest Login", self.guest_login),
            ("Guest Login (encrypted)", self.guest_login_encrypted),
            ("API Info", self.get_api_info),
            ("Device Info", lambda: self.get_device_info(sn)),
            ("ROM Match Params", lambda: self.get_rom_match_params(model)),
            ("Rescue ROM", lambda: self.get_rescue_rom(model, sn)),
            ("ROM List", lambda: self.get_rom_list(model)),
            ("Rescue Recipe", lambda: self.get_rescue_recipe(model)),
            ("Fastboot Support", lambda: self.get_fastboot_support(model)),
        ]

        for name, fn in tests:
            print(f"{'─' * 50}")
            print(f"Testing: {name}")
            try:
                result = fn()
                status = result["status"]
                indicator = "+" if status == 200 else ">" if status == 302 else "-"
                print(f"  {indicator} Status: {status}")
                if result.get("json"):
                    print(f"  JSON: {json.dumps(result['json'], indent=4)[:500]}")
                elif result.get("decrypted"):
                    print(f"  Decrypted: {result['decrypted'][:500]}")
                elif result.get("raw") and len(result["raw"]) < 200:
                    print(f"  Raw: {result['raw']}")
                elif status == 302:
                    print(f"  Redirect: {result['headers'].get('Location', 'unknown')}")
            except Exception as e:
                print(f"  Error: {e}")


def _print_result(result):
    print(f"Status: {result['status']}")
    if result.get("json") is not None:
        print(json.dumps(result["json"], indent=2))
    elif result.get("decrypted"):
        print(result["decrypted"])
    else:
        print(result["raw"][:2000])


def main():
    parser = argparse.ArgumentParser(
        description="Lenovo Software Fix / LRSA API client"
    )
    parser.add_argument("model", nargs="?", default="Lenovo TB390FU")
    parser.add_argument("sn", nargs="?", default="HNQ06MHH")
    parser.add_argument("--token")
    parser.add_argument("--client-uuid")
    parser.add_argument("--base-url", default=BASE_URL)
    parser.add_argument(
        "--action",
        choices=["probe", "bootstrap", "rescue-rom", "rom-match", "api-info"],
        default="probe",
    )
    args = parser.parse_args()

    client = LRSAClient(
        client_uuid=args.client_uuid,
        token=args.token,
        base_url=args.base_url,
    )

    if args.action == "bootstrap":
        for name, result in client.bootstrap_guest_session():
            print(f"\n{name}")
            _print_result(result)
        if client.token:
            print(f"\nToken: {client.token}")
    elif args.action == "rescue-rom":
        _print_result(client.get_rescue_rom(args.model, args.sn))
    elif args.action == "rom-match":
        _print_result(client.get_rom_match_params(args.model))
    elif args.action == "api-info":
        _print_result(client.get_api_info())
    else:
        client.probe_all(args.model, args.sn)


if __name__ == "__main__":
    main()
