#!/usr/bin/env python3
"""Login entrypoint for LRSA.

Examples:
  python3 -m lrsa.login --method guest
  python3 -m lrsa.login --method lenovoid
  python3 -m lrsa.login --method lenovoid --no-browser
"""

import argparse

from .auth import lenovo_id_login, save_json
from .client import LRSAClient
from .config import DEFAULT_WORK_DIR


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
    }


def lenovoid_login(open_browser=True, client_uuid=None, token=None):
    token_data = None
    if not token:
        token, token_data = lenovo_id_login(open_browser=open_browser)
    client = LRSAClient(client_uuid=client_uuid, token=token)
    user_info = client.lenovo_id_user_info()
    return {
        "method": "lenovoid",
        "client_uuid": client.client_uuid,
        "token": token,
        "token_response": token_data,
        "user_info": user_info,
    }


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
    print(f"Saved login session: {args.out}")
    if session.get("token"):
        print("Token captured.")
    else:
        print("No token captured; inspect saved responses for server errors.")


if __name__ == "__main__":
    main()
