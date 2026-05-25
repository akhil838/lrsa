#!/usr/bin/env python3
"""Lenovo Passport SSO probes for Software Fix login.

The browser login flow exposes Passport SSO cookies such as ``LPSWUST`` and
``LPSWUTGT``. Those are not the same as the OAuth access token returned by the
PKCE token endpoint. Software Fix also contains an older interserver callback
URL that consumes an ``lpsust`` value, so this module probes that path without
printing secret values.
"""

from lrsa.logging import get_logger

import argparse
from http.cookies import SimpleCookie
from pathlib import Path
import urllib.parse

import requests
import urllib3

from .constants import DEFAULT_REALMS, INTERSERVER_ACCOUNT_URL
from .session import save_json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def redact(value):
    if not value:
        return value
    value = str(value)
    if len(value) <= 18:
        return "<redacted>"
    return f"{value[:10]}...{value[-6:]}"


def parse_cookie_header(cookie_header):
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    return {key: morsel.value for key, morsel in cookie.items()}


def extract_passport_tokens(cookie_header):
    cookies = parse_cookie_header(cookie_header)
    return {
        key: cookies.get(key)
        for key in ("LPSWUST", "LPSWUTGT", "lenovoid.webLoginSignkey")
        if cookies.get(key)
    }


def parse_callback_url(url):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    return {
        "url": url,
        "host": parsed.netloc,
        "path": parsed.path,
        "query": {
            key: values[0] if len(values) == 1 else values
            for key, values in params.items()
        },
    }


def parse_softwarefix_callback(location):
    if not location:
        return {}
    parsed = urllib.parse.urlparse(location)
    params = urllib.parse.parse_qs(parsed.query)
    return {
        "scheme": parsed.scheme,
        "path": parsed.path,
        "authorization": params.get(
            "Authorization", params.get("authorization", [None])
        )[0],
        "full_name": params.get("fullName", params.get("FullName", [None]))[0],
        "raw_query": {
            key: values[0] if len(values) == 1 else values
            for key, values in params.items()
        },
    }


def probe_lpsust(lpsust, realm):
    response = requests.get(
        INTERSERVER_ACCOUNT_URL,
        params={"lpsust": lpsust, "realm": realm},
        allow_redirects=False,
        verify=False,
        timeout=30,
    )
    location = response.headers.get("Location")
    return {
        "realm": realm,
        "status": response.status_code,
        "headers": {
            key: redact(value)
            if key.lower() in {"set-cookie", "authorization"}
            else value
            for key, value in response.headers.items()
        },
        "location": location,
        "softwarefix_callback": parse_softwarefix_callback(location),
        "body_preview": response.text[:1000],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Probe Lenovo Passport SSO tokens for Software Fix login"
    )
    parser.add_argument(
        "--lpsust",
        help="Raw LPSWUST value. Prefer --cookie-file to keep tokens out of shell history.",
    )
    parser.add_argument(
        "--cookie-file",
        type=Path,
        help="File containing a Cookie header copied from DevTools/cURL.",
    )
    parser.add_argument(
        "--callback-url",
        help="Passport oauth2 callback URL, saved for reference in the output.",
    )
    parser.add_argument(
        "--realm",
        action="append",
        help="Realm to probe. Defaults to known Software Fix realms.",
    )
    parser.add_argument(
        "--out", type=Path, default=Path("lrsa_work/passport_probe.json")
    )
    args = parser.parse_args()

    cookie_tokens = {}
    if args.cookie_file:
        cookie_tokens = extract_passport_tokens(
            args.cookie_file.read_text(encoding="utf-8").strip()
        )

    lpsust = (
        args.lpsust or cookie_tokens.get("LPSWUST") or cookie_tokens.get("LPSWUTGT")
    )
    if not lpsust:
        raise RuntimeError(
            "No LPSWUST/LPSWUTGT token found. Provide --lpsust or --cookie-file."
        )

    realms = tuple(args.realm) if args.realm else DEFAULT_REALMS
    probes = [probe_lpsust(lpsust, realm) for realm in realms]

    output = {
        "callback": parse_callback_url(args.callback_url)
        if args.callback_url
        else None,
        "available_cookie_tokens": {
            key: redact(value) for key, value in cookie_tokens.items()
        },
        "used_lpsust": redact(lpsust),
        "probes": probes,
    }
    save_json(args.out, output)

    get_logger(__name__).info(f"Saved Passport probe: {args.out}")
    for probe in probes:
        callback = probe.get("softwarefix_callback") or {}
        get_logger(__name__).info(
            f"{probe['realm']}: HTTP {probe['status']} "
            f"location={redact(probe.get('location'))} "
            f"authorization={redact(callback.get('authorization'))} "
            f"fullName={callback.get('full_name')}"
        )


if __name__ == "__main__":
    main()
