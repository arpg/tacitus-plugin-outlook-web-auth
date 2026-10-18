"""Harvest a Graph (or Outlook REST) token headless from Outlook on the web.

Opens outlook.office365.com in a persistent browser profile that keeps the
SSO cookies, waits for Outlook to load, then reads the MSAL access token
from localStorage: the token you would copy from the developer tools. It
writes it to auth/manual_token.txt, which auth_sources.manual_token hands
to EA core.

First run: a visible browser, for one SSO sign-in (`outlook_web.py login`).
After that: headless, on the SSO cookies (about 90 days), from the owner
cron job every 30 minutes (`outlook_web.py refresh`).

Runs as the owner. The browser profile lives in the owner-private
directory (a browser writes its profile by path for a whole session, and
no check made before launch holds while the resident can rename the
directory above it). Token files go through owner_trust, from EA core.
"""
from __future__ import annotations

import os
import stat
import sys
import time
from datetime import datetime
from pathlib import Path

import auth_sources as src

HERE = Path(__file__).resolve().parent
OUTLOOK_URL = "https://outlook.office365.com/mail/"
PROFILE_NAME = "playwright-outlook"
MIN_REMAINING_SECS = 300     # a harvested token must have more than this left
SSO_WARN_DAYS = 7            # warn when the SSO cookies expire within this many days
LOG_NAME = "outlook-web-auth.log"
CHROME_EPOCH_OFFSET = 11644473600   # seconds from 1601-01-01 to 1970-01-01


def _ot():
    import owner_trust
    return owner_trust


def _log(msg: str) -> None:
    """A line on stderr and in the owner-private log (a browser can swallow
    terminal output during a visible run)."""
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, file=sys.stderr, flush=True)
    try:
        from log_paths import owner_log
        with open(owner_log(LOG_NAME), "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _cmd(verb: str) -> str:
    return f"python3 {HERE / 'outlook_web.py'} {verb}"


def validate_token(token: str) -> tuple[bool, str]:
    """(valid, reason): a Graph or Outlook REST token with more than
    MIN_REMAINING_SECS left."""
    payload = src.decode_jwt_payload(token)
    if not payload:
        return False, "Could not decode JWT"
    aud = payload.get("aud", "")
    if aud not in src.VALID_AUDIENCES:
        return False, f"Wrong audience: {aud}"
    remaining = payload.get("exp", 0) - time.time()
    if remaining < MIN_REMAINING_SECS:
        return False, f"Expires in {int(remaining)}s (need >{MIN_REMAINING_SECS}s)"
    return True, (f"Valid, {int(remaining / 60)}m remaining, "
                  f"user={payload.get('preferred_username', '?')}")


def save_token(path: Path, token: str) -> None:
    """Write the token with owner_trust.token_file_mode(): 0600 under mail
    mediation, where the owner's mediator holds the tokens, 0640 group ea
    without it, where the resident reads them. An owner process writes
    through owner_trust (checked directory, atomic rename, mode set before
    any byte is written)."""
    ot = _ot()
    mode, gid = ot.token_file_mode()
    if src.checked_token_io():
        ot.write_owner_file(path, token + "\n", mode=mode, gid=gid, allow_private_group=True)
        return
    path.write_text(token + "\n")
    os.chmod(path, mode)
    if gid is not None:
        try:
            os.chown(path, -1, gid)
        except OSError:
            pass


def current_token() -> str:
    """The token in the file, or "" (missing, empty or the placeholder)."""
    try:
        token = src.read_token_text(src.token_file()).strip()
    except FileNotFoundError:
        return ""
    return "" if token == src.PLACEHOLDER else token


def check_token() -> bool:
    token = current_token()
    if not token:
        _log("No token in the token file")
        return False
    valid, reason = validate_token(token)
    _log(f"Token status: {reason}")
    return valid


# ── the browser profile ───────────────────────────────────────────────

def legacy_profile_parent() -> Path:
    """Where the profile was before it moved to the owner-private dir."""
    return _ot().ea_dir() / "auth"


def profile_dir() -> Path | None:
    """The browser profile to use, or None (reason logged).

    The owner-private one when it exists, or when there is none anywhere
    (it is created there, 0700). A profile still under the auth directory
    is used only while that directory and the profile pass the owner
    checks, with a warning to run `outlook_web.py migrate-profile`."""
    ot = _ot()
    priv = ot.private_dir()
    new = priv / PROFILE_NAME
    old = legacy_profile_parent() / PROFILE_NAME
    try:
        ot.check_owner_dir(priv)
        if os.path.lexists(new):
            ot.check_owner_dir(new, allow_private_group=True)
            return new
        if os.path.lexists(old):
            ot.check_owner_dir(old.parent, allow_private_group=True)
            ot.check_owner_dir(old, allow_private_group=True)
            _log(f"WARNING: browser profile still at {old}, under a directory the resident "
                 f"can rename. Move it: {_cmd('migrate-profile')}")
            return old
        os.mkdir(new, 0o700)
        ot.check_owner_dir(new)
        return new
    except (OSError, ot.OwnerTrustError) as e:
        _log(f"REFUSED: {e}")
        return None


def migrate_profile() -> bool:
    """Move the profile from the auth directory to the owner-private
    directory. Owner-run, once. The rename is made between the two checked
    directory descriptors, so a directory the resident renames or swaps
    meanwhile cannot be what moves. A profile already in the private
    directory is left as it is; the one at the old name then stays for the
    owner to remove. True when nothing was refused."""
    ot = _ot()
    priv = ot.private_dir()
    src_dir = legacy_profile_parent()
    try:
        ot.check_owner_dir(priv)
        with ot.open_owner_dir(src_dir, allow_private_group=True) as sfd, \
                ot.open_owner_dir(priv) as dfd:
            try:
                st = os.stat(PROFILE_NAME, dir_fd=sfd, follow_symlinks=False)
            except FileNotFoundError:
                _log(f"{PROFILE_NAME}: nothing at {src_dir}; skipped")
                return True
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
                raise ot.OwnerTrustError(f"{src_dir / PROFILE_NAME} is not a directory of the "
                                         f"owner's that no other user can write")
            try:
                os.stat(PROFILE_NAME, dir_fd=dfd, follow_symlinks=False)
                _log(f"{PROFILE_NAME}: already in {priv}; the copy at "
                     f"{src_dir / PROFILE_NAME} was left in place")
                return True
            except FileNotFoundError:
                pass
            os.rename(PROFILE_NAME, PROFILE_NAME, src_dir_fd=sfd, dst_dir_fd=dfd)
            _log(f"{PROFILE_NAME}: moved to {priv / PROFILE_NAME}")
            return True
    except (OSError, ot.OwnerTrustError) as e:
        _log(f"{PROFILE_NAME}: REFUSED: {e}")
        return False


# ── alerts ────────────────────────────────────────────────────────────

def load_slack_config() -> tuple[str, str]:
    """(bot token, channel id). The token comes by the owner_trust rule (the
    environment, the owner-private secrets.env, then the checked
    .env.secrets beside the EA tree's .env), never from .env, which the
    resident can write. The channel id is not a secret: the environment,
    else .env read as data."""
    ot = _ot()
    dotenv = ot.ea_dir() / ".env"
    token = ot.owner_secret("SLACK_BOT_TOKEN", legacy=dotenv.parent / ot.LEGACY_SECRETS_FILE)
    channel = os.environ.get("EA_SLACK_CHANNEL_ID", "") or ot.read_env_values(
        dotenv, ("EA_SLACK_CHANNEL_ID",)).get("EA_SLACK_CHANNEL_ID", "")
    return token, channel


def slack_alert(message: str) -> None:
    """Post an alert to the EA channel with the bot's credentials."""
    import chat_notify
    token, channel = load_slack_config()
    if chat_notify.frontend_name() == "slack" and (not token or not channel):
        _log("Cannot send the alert: missing SLACK_BOT_TOKEN or EA_SLACK_CHANNEL_ID")
        return
    try:
        sent = chat_notify.post_as_bot(channel, message, token=token,
                                       log=lambda detail: _log(f"Alert failed: {detail}"))
    except Exception as e:
        _log(f"Alert error: {e}")
        return
    if sent:
        _log("Alert sent.")


# ── the SSO cookie expiry ─────────────────────────────────────────────

def cookies_db() -> Path:
    """The profile's cookie store: in the owner-private profile, or in the
    legacy one while only that exists. This only chooses the name; the
    read checks what is there."""
    new = _ot().private_dir() / PROFILE_NAME
    old = legacy_profile_parent() / PROFILE_NAME
    base = old if (not os.path.lexists(new) and os.path.lexists(old)) else new
    return base / "Default" / "Cookies"


def read_cookie_store(cookies: Path) -> bytes | None:
    """The cookie store's bytes, or None when there is none or it is refused
    (reason logged). The read goes through owner_trust.read_owner_file: the
    profile's Default directory and the Cookies file are checked on their
    open descriptors (the owner's, not links, writable by no other user),
    so a store under the auth directory that the resident renamed, linked
    or replaced is never parsed."""
    ot = _ot()
    try:
        return ot.read_owner_file(cookies, allow_private_group=True)
    except FileNotFoundError:
        return None
    except (OSError, ot.OwnerTrustError) as e:
        hint = ""
        legacy = os.path.abspath(legacy_profile_parent()) + os.sep
        if os.path.abspath(cookies).startswith(legacy):
            hint = (f"; the profile is still under {legacy_profile_parent()}. Move it: "
                    f"{_cmd('migrate-profile')}")
        _log(f"SSO cookie check REFUSED: {e}{hint}")
        return None


def check_sso_cookie_expiry() -> int | None:
    """Days until the SSO cookies expire, from Chromium's cookie store, or
    None when that cannot be told. The store is parsed from a private copy
    (mkstemp, mode 0600, removed afterwards), so SQLite never opens or
    locks the browser's own file. Chromium keeps expiry as microseconds
    since 1601-01-01."""
    data = read_cookie_store(cookies_db())
    if data is None:
        return None
    import sqlite3
    import tempfile
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".db")
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
        conn = sqlite3.connect(tmp_path)
        try:
            rows = conn.execute(
                "SELECT name, expires_utc FROM cookies "
                "WHERE host_key LIKE '%login.microsoftonline.com%' "
                "AND expires_utc > 0 ORDER BY expires_utc DESC LIMIT 5").fetchall()
        finally:
            conn.close()
        if not rows:
            return None
        newest = max((exp / 1_000_000) - CHROME_EPOCH_OFFSET for _name, exp in rows)
        if newest <= 0:
            return None
        return int((newest - time.time()) / 86400)
    except Exception as e:
        _log(f"SSO cookie check failed: {e}")
        return None
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ── the harvest ───────────────────────────────────────────────────────

# MSAL.js keeps tokens in localStorage with credentialType=AccessToken.
# Scan every key, find access tokens with useful scopes, and return the
# best one (Graph audience before Outlook audience).
_EXTRACT_TOKEN_JS = r"""
() => {
    let best = null;
    let bestPriority = -1;
    let allAudiences = [];

    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (!key) continue;
        let val;
        try { val = JSON.parse(localStorage.getItem(key)); } catch(e) { continue; }
        if (!val || val.credentialType !== 'AccessToken' || !val.secret) continue;

        const target = (val.target || '').toLowerCase();
        allAudiences.push(target.substring(0, 80));

        // Tokens with Mail or Calendar scopes are the ones needed; a Graph
        // token without them is no use.
        const hasMailScopes = /mail\.(read|readwrite|send)/i.test(target);
        const hasCalScopes = /calendars\.(read|readwrite)/i.test(target);
        const hasUsefulScopes = hasMailScopes || hasCalScopes;

        let priority = 0;
        if (hasUsefulScopes && target.includes('graph.microsoft.com')) {
            priority = 4;  // Graph API with mail scopes
        } else if (hasUsefulScopes && target.includes('outlook.office.com')) {
            priority = 3;  // Outlook REST with mail scopes
        } else if (hasUsefulScopes) {
            priority = 2;  // mail scopes, another audience
        } else if (target.includes('graph.microsoft.com') || target.includes('outlook.office.com')) {
            priority = 1;  // the right service, no mail scopes
        }

        if (priority > bestPriority) {
            bestPriority = priority;
            best = {token: val.secret, target: target.substring(0, 120), priority: priority,
                    hasMailScopes: hasMailScopes, hasCalScopes: hasCalScopes};
        }
    }

    return {best: best, audiences: allAudiences, count: localStorage.length};
}
"""


def harvest(visible: bool = False) -> bool:
    """Open Outlook, read the token from localStorage, save it."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _log("ERROR: playwright not installed")
        return False

    profile = profile_dir()
    if profile is None:
        return False

    token_found = None
    with sync_playwright() as p:
        _log(f"Launching browser ({'visible' if visible else 'headless'})...")
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(profile),
            headless=not visible,
            args=["--disable-blink-features=AutomationControlled"],
            ignore_default_args=["--enable-automation"],
            locale="en-US",
            timezone_id="America/Denver",
        )
        page = context.pages[0] if context.pages else context.new_page()
        try:
            _log(f"Navigating to {OUTLOOK_URL}...")
            # 'commit' fires early and does not block on slow resources.
            page.goto(OUTLOOK_URL, wait_until="commit", timeout=60000)
            _log(f"Initial URL: {page.url[:80]}")

            timeout = 300000 if visible else 60000  # 5 min to sign in, 1 min headless
            _log(f"Waiting for page to finish loading (timeout={timeout // 1000}s)...")
            try:
                page.wait_for_load_state("networkidle", timeout=timeout)
            except Exception as e:
                _log(f"Page load wait ended: {e}")

            # A fresh profile reaches networkidle on the Outlook shell before
            # its script redirects to sign-in, so the URL would still read
            # /mail/ and the SSO wait would never start. A visible run gives
            # that redirect a moment to happen.
            if visible:
                try:
                    page.wait_for_url(
                        lambda u: "login.microsoftonline.com" in u or "login.live.com" in u,
                        timeout=10000)
                except Exception:
                    pass

            _log(f"Final URL: {page.url[:80]}")
            url = page.url.lower()
            if "login.microsoftonline.com" in url or "login.live.com" in url:
                if not visible:
                    _log("Redirected to login: the SSO cookies expired. Run login.")
                    slack_alert(":warning: *Graph API token refresh failed*: the SSO session "
                                "expired.\nAt the desktop, as the owner: "
                                f"`{_cmd('login')}`")
                    context.close()
                    return False
                _log("On the login page; waiting for you to complete SSO...")
                try:
                    page.wait_for_url("**/mail/**", timeout=300000)
                    page.wait_for_load_state("networkidle", timeout=30000)
                except Exception as e:
                    _log(f"SSO wait ended: {e}")

            _log("Extracting tokens from localStorage...")
            # Retries: the MSAL cache can lag the page.
            for attempt in range(4):
                _log(f"  Attempt {attempt + 1}/4...")
                try:
                    result = page.evaluate(_EXTRACT_TOKEN_JS)
                except Exception as e:
                    _log(f"  JS failed: {e}")
                    time.sleep(5)
                    continue
                _log(f"  localStorage: {result.get('count', 0)} keys, "
                     f"audiences: {result.get('audiences', [])}")
                best = result.get("best")
                if best and best.get("token"):
                    valid, reason = validate_token(best["token"])
                    if valid:
                        _log(f"  Valid token found! {reason}")
                        token_found = best["token"]
                        break
                    _log(f"  Token found but: {reason}")
                time.sleep(5)
        except Exception as e:
            _log(f"Error: {e}")
        finally:
            context.close()

    if not token_found:
        _log("No valid token found in browser storage.")
        if not visible:
            slack_alert(":warning: *Graph API token refresh failed*: no valid token in browser "
                        f"storage.\nAt the desktop, as the owner: `{_cmd('login')}`")
        return False

    _, reason = validate_token(token_found)
    path = src.token_file()
    try:
        save_token(path, token_found)
    except (OSError, _ot().OwnerTrustError) as e:
        _log(f"REFUSED to save the token: {e}")
        return False
    _log(f"Token saved to {path}: {reason}")

    sso_days = check_sso_cookie_expiry()
    if sso_days is not None:
        _log(f"SSO cookie expires in ~{sso_days} days.")
        if sso_days <= SSO_WARN_DAYS:
            slack_alert(f":alarm_clock: *SSO session expires in ~{sso_days} days.*\n"
                        f"At the desktop, as the owner: `{_cmd('login')}`, to refresh it "
                        f"before it expires.")
    return True


def refresh(force: bool = False) -> bool:
    """The cron pass: harvest headless, unless the current token still has
    more than 15 minutes left (or `force`)."""
    if not force:
        token = current_token()
        if token and validate_token(token)[0]:
            remaining = src.decode_jwt_payload(token).get("exp", 0) - time.time()
            if remaining > 900:
                _log(f"Token still valid ({int(remaining / 60)}m left), skipping.")
                return True
            _log(f"Token only {int(remaining / 60)}m left, refreshing...")
    ok = harvest(visible=False)
    if not ok:
        _log("Headless harvest failed. Run login to sign in again.")
    return ok
