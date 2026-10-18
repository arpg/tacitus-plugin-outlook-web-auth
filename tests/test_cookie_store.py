"""The SSO cookie-expiry probe reads the browser's cookie store only through
owner_trust's checked descriptors.

The harvest runs as the owner. Until `migrate-profile` has run, the
profile may sit under ~/.ea/auth, below directories the resident owns, so
the resident can put a link, a directory of its own or a writable file at
any name on the way to the store. These pin that:

  * a link at the store, a link at the profile's Default directory and a
    store another user can write are refused and never parsed, and the
    refusal names the migration;
  * a legacy store that passes the checks is still read, and the
    owner-private profile wins when both exist;
  * the private copy SQLite opens is removed, also when the parse fails.
"""
from __future__ import annotations

import sqlite3
import tempfile
import time
import types
from pathlib import Path

import pytest

import outlook_harvest as h

CHROME_EPOCH_OFFSET = 11644473600


def _store(path: Path, days: float) -> Path:
    """A Chromium-shaped cookie store with one SSO cookie `days` from now."""
    path.parent.mkdir(parents=True, exist_ok=True)
    expires = int((time.time() + days * 86400 + CHROME_EPOCH_OFFSET) * 1_000_000)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, expires_utc INTEGER)")
    conn.execute("INSERT INTO cookies VALUES ('.login.microsoftonline.com', 'ESTSAUTH', ?)",
                 (expires,))
    conn.commit()
    conn.close()
    path.chmod(0o600)
    return path


def _profile(root: Path) -> Path:
    """The profile's Default directory under `root`, mode 0700."""
    default = root / h.PROFILE_NAME / "Default"
    default.mkdir(parents=True)
    for d in (root / h.PROFILE_NAME, default):
        d.chmod(0o700)
    return default


@pytest.fixture
def env(owner, monkeypatch):
    """The owner layout, a scratch temp dir, and the module's log captured."""
    scratch = owner.tmp / "scratch"
    scratch.mkdir()
    logs: list = []
    monkeypatch.setattr(h, "_log", logs.append)
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    return types.SimpleNamespace(auth=owner.auth, priv=owner.priv, scratch=scratch, logs=logs,
                                 tmp=owner.tmp)


def _link_at_store(env):
    forged = _store(env.tmp / "resident" / "Cookies", days=2)
    (_profile(env.auth) / "Cookies").symlink_to(forged)


def _link_at_default(env):
    forged = _store(env.tmp / "resident" / "Default" / "Cookies", days=2)
    (env.tmp / "resident" / "Default").chmod(0o700)
    (env.auth / h.PROFILE_NAME).mkdir(mode=0o700)
    (env.auth / h.PROFILE_NAME / "Default").symlink_to(forged.parent)


def _writable_store(env):
    _store(_profile(env.auth) / "Cookies", days=2).chmod(0o606)


@pytest.mark.parametrize("plant", [_link_at_store, _link_at_default, _writable_store],
                         ids=["link-at-store", "link-at-default", "store-writable-by-others"])
def test_a_legacy_store_that_fails_the_owner_checks_is_not_parsed(env, plant):
    plant(env)
    assert h.check_sso_cookie_expiry() is None
    refused = [m for m in env.logs if "REFUSED" in m]
    assert refused, env.logs
    assert "migrate-profile" in refused[0]
    assert list(env.scratch.iterdir()) == []


def test_a_legacy_store_that_passes_the_checks_is_still_read(env):
    _store(_profile(env.auth) / "Cookies", days=30)
    assert h.check_sso_cookie_expiry() in (29, 30)
    assert not [m for m in env.logs if "REFUSED" in m or "failed" in m], env.logs
    assert list(env.scratch.iterdir()) == []


def test_the_private_profile_is_read_and_wins_over_the_legacy_one(env):
    _store(_profile(env.auth) / "Cookies", days=3)
    _store(_profile(env.priv) / "Cookies", days=60)
    assert h.check_sso_cookie_expiry() in (59, 60)
    assert env.logs == []


def test_no_store_is_no_answer_and_no_refusal(env):
    assert h.check_sso_cookie_expiry() is None
    (env.auth / h.PROFILE_NAME).mkdir(mode=0o700)
    assert h.check_sso_cookie_expiry() is None
    assert env.logs == []


def test_the_private_copy_is_removed_when_the_parse_fails(env):
    store = _profile(env.priv) / "Cookies"
    store.write_bytes(b"not a database" * 100)
    store.chmod(0o600)
    assert h.check_sso_cookie_expiry() is None
    assert any("SSO cookie check failed" in m for m in env.logs), env.logs
    assert list(env.scratch.iterdir()) == []
