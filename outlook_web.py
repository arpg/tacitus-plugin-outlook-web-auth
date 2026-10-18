#!/usr/bin/env python3
"""outlook-web-auth: Graph tokens from Outlook on the web (README.md).

    outlook_web.py refresh [--force]   headless harvest, unless the token has
                                       more than 15 minutes left (owner cron
                                       job, every 30 minutes)
    outlook_web.py login               a visible browser for the SSO sign-in,
                                       then a harvest
    outlook_web.py check               the current token's status; exit 1
                                       when it is not valid
    outlook_web.py migrate-profile     move the browser profile from the auth
                                       directory to the owner-private one

The token itself reaches EA core through auth_sources.manual_token. The
core runs the cron job with EA_CORE_DIR set and its preprocessor
directory on PYTHONPATH. Run by hand, set EA_CORE_DIR to the ea-system
checkout.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


def _ensure_core() -> None:
    """Make EA core's modules (owner_trust, log_paths, chat_notify)
    importable, after the plugin's own directory."""
    try:
        import owner_trust  # noqa: F401
        return
    except ModuleNotFoundError:
        pass
    core = os.environ.get("EA_CORE_DIR", "").strip()
    if not core:
        print(json.dumps({"status": "error",
                          "message": "outlook-web-auth: EA core not found; set EA_CORE_DIR to "
                                     "the ea-system checkout"}), file=sys.stderr)
        sys.exit(2)
    for p in (Path(core), Path(core) / "preprocessor"):
        sys.path.insert(1, str(p))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="outlook_web.py",
                                 description="Graph tokens from Outlook on the web")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("refresh", help="headless harvest (the cron job)")
    p.add_argument("--force", action="store_true", help="harvest even if the token is valid")
    sub.add_parser("login", help="visible browser for the SSO sign-in")
    sub.add_parser("check", help="the current token's status")
    sub.add_parser("migrate-profile", help="move the browser profile to the owner-private dir")
    args = ap.parse_args(argv)
    _ensure_core()
    import outlook_harvest as h
    if args.cmd == "refresh":
        return 0 if h.refresh(force=args.force) else 1
    if args.cmd == "login":
        h._log("Starting login (visible browser)...")
        ok = h.harvest(visible=True)
        h._log("Login successful; token saved." if ok else "Login failed.")
        return 0 if ok else 1
    if args.cmd == "check":
        return 0 if h.check_token() else 1
    return 0 if h.migrate_profile() else 1


if __name__ == "__main__":
    sys.exit(main())
