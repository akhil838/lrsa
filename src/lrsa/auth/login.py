#!/usr/bin/env python3
"""Login entrypoint for LRSA."""

from __future__ import annotations

import argparse

from lrsa.logging import get_logger

from ..api.client import LRSAClient
from ..config import DEFAULT_WORK_DIR
from .session import complete_lenovo_id_login, save_json, begin_lenovo_id_login


def guest_login(client_uuid=None, account_id=None, include_init_token=False):
    client = LRSAClient(client_uuid=client_uuid)
    results = []
    for name, result in client.bootstrap_guest_session(
        account_id=account_id,
        include_init_token=include_init_token,
    ):
        results.append({"step": name, "status": result["status"], "response": result})
    return {
        "method": "guest",
        "client_uuid": client.client_uuid,
        "account_id": account_id or client.client_uuid,
        "token": client.token,
        "results": results,
        "auto_login": False,
    }


def lenovoid_login(open_browser=True, client_uuid=None, token=None):
    if token:
        client = LRSAClient(client_uuid=client_uuid, token=token)
        user_info = client.lenovo_id_user_info()
        return {
            "method": "lenovoid",
            "client_uuid": client.client_uuid,
            "token": token,
            "token_response": None,
            "user_info": user_info,
            "auto_login": True,
        }

    seed = begin_lenovo_id_login(client_uuid=client_uuid, open_browser=open_browser)
    get_logger(__name__).info("\nPaste the final callback URL from the browser.")
    callback_url = input("Callback URL: ").strip()
    session = complete_lenovo_id_login(callback_url, seed=seed)
    session.setdefault("auto_login", True)
    return session


def main():
    parser = argparse.ArgumentParser(
        description="Authenticate with Lenovo Software Fix / LRSA"
    )
    parser.add_argument("--method", choices=["guest", "lenovoid"], default="guest")
    parser.add_argument("--out", default=DEFAULT_WORK_DIR / "login_session.json")
    parser.add_argument("--client-uuid")
    parser.add_argument(
        "--token", help="Existing Lenovo ID access token for --method lenovoid."
    )
    parser.add_argument(
        "--account-id", help="Guest accountId. Defaults to client UUID."
    )
    parser.add_argument(
        "--include-init-token",
        action="store_true",
        help="Also probe /client/initToken.jhtml. Not required by the traced guest path.",
    )
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    if args.method == "guest":
        session = guest_login(
            client_uuid=args.client_uuid,
            account_id=args.account_id,
            include_init_token=args.include_init_token,
        )
    else:
        session = lenovoid_login(
            open_browser=not args.no_browser,
            client_uuid=args.client_uuid,
            token=args.token,
        )

    save_json(args.out, session)
    get_logger(__name__).info(f"Saved login session: {args.out}")
    if session.get("token"):
        get_logger(__name__).info("Token captured.")
    else:
        get_logger(__name__).info(
            "No token captured; inspect saved responses for server errors."
        )


if __name__ == "__main__":
    main()
