"""Graph auth sources for EA core: a token from Outlook on the web.

graph_client.authenticate asks the auth sources of enabled owner plugins
for a token after the MSAL cache and before any interactive sign-in
(docs/plugins.md in ea-system). This plugin's source reads
auth/manual_token.txt in the EA tree: a token pasted from the browser's
developer tools, or the one the headless browser harvest
(outlook_harvest.py, `outlook_web.py refresh`) writes there. A token for
Microsoft Graph or for the Outlook REST API is accepted; graph_client
routes an Outlook-audience token to the REST API.

EA core loads this module into an owner process, from the owner-private
plugins directory, after the owner and integrity checks. Each source
takes no arguments and returns a token or None.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

TOKEN_NAME = "manual_token.txt"
PLACEHOLDER = "PASTE_TOKEN_HERE"
GRAPH_AUDIENCE = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph resource id
GRAPH_AUDIENCE_URL = "https://graph.microsoft.com"      # Microsoft Graph, URL form
OUTLOOK_AUDIENCE = "https://outlook.office.com"         # Outlook REST API
VALID_AUDIENCES = {GRAPH_AUDIENCE, GRAPH_AUDIENCE_URL, OUTLOOK_AUDIENCE}
RESIDENT_USER = "ea-bot"
PLUGIN_DIR = Path(__file__).resolve().parent

_ANNOUNCED: dict = {"done": False}


def _ot():
    """EA core's owner_trust: the copy the host process imported, else an
    import (the core puts its preprocessor directory on the path)."""
    mod = sys.modules.get("owner_trust") or sys.modules.get("preprocessor.owner_trust")
    if mod is None:
        import owner_trust as mod
    return mod


def token_file() -> Path:
    """auth/manual_token.txt in the EA tree this process uses (EA_DIR)."""
    return _ot().ea_dir() / "auth" / TOKEN_NAME


def checked_token_io() -> bool:
    """True when token files go through the owner checks: every process but
    the resident's own and one on a scratch EA tree (a test). An owner
    process on the install tree is checked whatever
    owner_trust.is_owner_process() says, so a missing private directory
    cannot switch the checks off. An unknown answer counts as checked."""
    ot = _ot()
    try:
        import pwd
        if os.geteuid() == pwd.getpwnam(RESIDENT_USER).pw_uid:
            return False
    except KeyError:
        pass
    except Exception:
        return True
    try:
        return os.path.realpath(ot.ea_dir()) == os.path.realpath(ot.install_ea_dir())
    except Exception:
        return True


def read_token_text(path) -> str:
    """The text of a token file: through owner_trust's checked descriptors
    (the auth directory sits under a directory the resident owns), or by
    path for the resident and a scratch tree."""
    if checked_token_io():
        return _ot().read_owner_file(path, allow_private_group=True).decode("utf-8")
    return Path(path).read_text()


def decode_jwt_payload(token: str) -> dict:
    """The JWT payload, not verified; {} when it cannot be read."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def manual_token() -> Optional[str]:
    """The token in auth/manual_token.txt, when it is for Microsoft Graph or
    the Outlook REST API and has more than a minute left; else None, with
    the reason on stderr. A token that cannot be decoded at all is used
    anyway, with a warning.

    Two ways to get one by hand (each lasts about an hour):
      Browser localStorage: outlook.office.com, DevTools > Application >
        Local Storage > outlook.office.com; an msal.* key whose "target"
        names https://graph.microsoft.com; copy its "secret".
      Network tab: DevTools > Network, filter graph.microsoft.com; copy the
        value after "Authorization: Bearer " from any request.
    The browser harvest writes the same file every 30 minutes."""
    path = token_file()
    try:
        token = read_token_text(path).strip()
    except FileNotFoundError:
        return None
    if not token or token == PLACEHOLDER:
        return None

    payload = decode_jwt_payload(token)
    if not payload:
        print("WARNING: could not decode the Outlook-web token; using it anyway.",
              file=sys.stderr)
        return token

    aud = payload.get("aud", "")
    if aud not in VALID_AUDIENCES:
        print(f"ERROR: the Outlook-web token has the wrong audience.\n"
              f"  Got:    {aud}\n"
              f"  Needed: {GRAPH_AUDIENCE} (Microsoft Graph)\n"
              f"       or {OUTLOOK_AUDIENCE} (Outlook REST API)\n"
              f"  See {PLUGIN_DIR / 'README.md'} for how to get the right token.",
              file=sys.stderr)
        return None

    exp = payload.get("exp", 0)
    remaining = exp - time.time()
    if remaining < 60:
        user = payload.get("preferred_username", "unknown")
        print(f"\nGRAPH API TOKEN EXPIRED\n"
              f"User: {user}\n"
              f"Expired: {datetime.fromtimestamp(exp).strftime('%Y-%m-%d %H:%M:%S')}\n"
              f"\nTo refresh: python3 {PLUGIN_DIR / 'outlook_web.py'} refresh --force\n"
              f"(or paste a new token from the browser into {path}).",
              file=sys.stderr)
        return None

    if not _ANNOUNCED["done"]:
        print(f"Using the Outlook-web Graph token for {payload.get('preferred_username', '?')} "
              f"({int(remaining / 60)} min remaining).", file=sys.stderr)
        _ANNOUNCED["done"] = True
    return token
