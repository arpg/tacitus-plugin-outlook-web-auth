"""End to end through EA core: ea-plugin's install of this working tree into
a scratch owner-private directory, the auth source as the core loads it,
graph_client.authenticate taking its token after the MSAL cache (and
routing an Outlook-audience token to the REST API), and the cron line."""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from conftest import PLUGIN

import auth_sources as src
import plugin_install as I
import plugin_registry as R

SKIP = shutil.ignore_patterns(".git", "__pycache__", "state", ".pytest_cache", "*.pyc", "*.log")


def _jwt(claims: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJub25lIn0.{body}.sig"


def _git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}
    for k in [k for k in env if k.startswith("GIT_DIR") or k == "GIT_INDEX_FILE"]:
        env.pop(k)
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=env)


@pytest.fixture
def installed(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    shutil.copytree(PLUGIN, repo, ignore=SKIP)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "release")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    tree = tmp_path / "ea"
    (tree / "plugins").mkdir(parents=True)
    (tree / "auth").mkdir(mode=0o750)
    monkeypatch.setattr(R, "PLUGINS_DIR", tree / "plugins")
    monkeypatch.setattr(R, "_is_owner", lambda: True)
    monkeypatch.setattr(R._owner_trust, "private_dir", lambda: private)
    monkeypatch.setenv("EA_DIR", str(tree))
    monkeypatch.setattr(I._rio, "_owner_check", lambda: False)
    ctx = I.Context(private=private, agent_dir=tree / "plugins", ea_dir=tree,
                    local_copy=True, out=lambda line: None)
    R._LOCK_CACHE["key"] = None
    R._VERIFY_CACHE.clear()
    I.install(ctx, f"git:{repo}", accept=True, policy={"trusted_sources": [], "blocked_sources": []})
    return ctx


def _put_token(ctx, claims):
    tok = _jwt(claims)
    path = ctx.ea_dir / "auth" / src.TOKEN_NAME
    path.write_text(tok + "\n")
    path.chmod(0o600)
    return tok


def test_the_core_loads_the_auth_source_from_the_lock(installed):
    lock = installed.lock_path
    assert list(R.owner_auth_tokens("graph", lock=lock)) == []          # no token yet
    tok = _put_token(installed, {"aud": src.GRAPH_AUDIENCE_URL, "exp": int(time.time()) + 3600})
    assert list(R.owner_auth_tokens("graph", lock=lock)) == [tok]
    assert I.verify(installed)["outlook-web-auth"] == []


def test_authenticate_takes_the_token_after_msal_and_routes_its_audience(installed, monkeypatch):
    import graph_client as gc
    monkeypatch.setattr(gc._app, "get_accounts", lambda: [])
    monkeypatch.setattr(gc, "_SOURCE_TOKEN", {"token": None, "exp": 0.0})
    tok = _put_token(installed, {"aud": src.OUTLOOK_AUDIENCE, "exp": int(time.time()) + 3600})
    assert gc.authenticate() == tok
    assert gc._api_base() == gc.OUTLOOK_REST_URL


def test_the_harvest_is_an_owner_cron_job(installed):
    (line,) = I.cron_lines(installed, Path("/core/scripts/ea-plugin.py"), Path("/logs"))
    assert line.startswith("*/30 * * * *  ")
    assert "/core/scripts/ea-plugin.py run-owner outlook-web-auth harvest" in line
