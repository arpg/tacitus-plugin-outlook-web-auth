"""The harvest side: token validation, token file modes, the cron pass's
skip rule, the alerts' credentials and the browser profile's place."""
from __future__ import annotations

import base64
import json
import stat
import sys
import time
import types

import pytest

import auth_sources as src
import outlook_harvest as h
import outlook_web
import owner_trust as ot


def _jwt(claims: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJub25lIn0.{body}.sig"


@pytest.fixture
def logs(monkeypatch):
    seen: list = []
    monkeypatch.setattr(h, "_log", seen.append)
    return seen


def test_validate_token():
    soon = int(time.time()) + 3600
    assert h.validate_token(_jwt({"aud": src.GRAPH_AUDIENCE, "exp": soon}))[0]
    assert h.validate_token(_jwt({"aud": src.OUTLOOK_AUDIENCE, "exp": soon}))[0]
    assert not h.validate_token(_jwt({"aud": "https://other.example.org", "exp": soon}))[0]
    assert not h.validate_token(_jwt({"aud": src.GRAPH_AUDIENCE, "exp": int(time.time()) + 200}))[0]
    assert h.validate_token("x") == (False, "Could not decode JWT")


def test_token_modes_follow_mediation(owner, monkeypatch):
    tok = owner.auth / src.TOKEN_NAME
    monkeypatch.setattr(ot, "_resident_reads_tokens", lambda: False)      # mediated
    h.save_token(tok, "eyJ.a.b")
    assert stat.S_IMODE(tok.stat().st_mode) == 0o600 and tok.read_text() == "eyJ.a.b\n"
    monkeypatch.setattr(ot, "_resident_reads_tokens", lambda: True)       # no mediation
    monkeypatch.setattr(ot, "_ea_gid", lambda: None)
    h.save_token(tok, "eyJ.a.c")
    assert stat.S_IMODE(tok.stat().st_mode) == 0o640 and tok.read_text() == "eyJ.a.c\n"


def test_check_reports_the_current_token(owner, logs):
    assert outlook_web.main(["check"]) == 1
    (owner.auth / src.TOKEN_NAME).write_text(
        _jwt({"aud": src.GRAPH_AUDIENCE_URL, "exp": int(time.time()) + 3600}))
    (owner.auth / src.TOKEN_NAME).chmod(0o600)
    assert outlook_web.main(["check"]) == 0
    assert any(m.startswith("Token status: Valid") for m in logs)


def test_refresh_skips_a_token_with_time_left_and_harvests_otherwise(owner, logs, monkeypatch):
    runs = []
    monkeypatch.setattr(h, "harvest", lambda visible=False: runs.append(visible) or True)
    path = owner.auth / src.TOKEN_NAME
    path.write_text(_jwt({"aud": src.GRAPH_AUDIENCE_URL, "exp": int(time.time()) + 3600}))
    path.chmod(0o600)
    assert outlook_web.main(["refresh"]) == 0 and runs == []
    assert outlook_web.main(["refresh", "--force"]) == 0 and runs == [False]
    path.write_text(_jwt({"aud": src.GRAPH_AUDIENCE_URL, "exp": int(time.time()) + 600}))
    assert h.refresh() is True and runs == [False, False]          # under 15 minutes left
    monkeypatch.setattr(h, "harvest", lambda visible=False: False)
    assert outlook_web.main(["refresh", "--force"]) == 1


def test_harvest_without_playwright_fails_quietly(owner, logs, monkeypatch):
    monkeypatch.setitem(sys.modules, "playwright", None)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    assert h.harvest() is False
    assert any("playwright not installed" in m for m in logs)


# ── alerts ────────────────────────────────────────────────────────────

def _write(path, text, mode):
    path.write_text(text)
    path.chmod(mode)
    return path


def test_the_alert_token_never_comes_from_dotenv(owner, monkeypatch):
    _write(owner.tree / ".env", "EA_SLACK_CHANNEL_ID=C0EXAMPLE\nSLACK_BOT_TOKEN=xoxb-dotenv\n", 0o640)
    monkeypatch.delenv("EA_SLACK_CHANNEL_ID", raising=False)
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    assert h.load_slack_config() == ("", "C0EXAMPLE")
    _write(owner.tree / ".env.secrets", "SLACK_BOT_TOKEN=xoxb-legacy\n", 0o600)
    assert h.load_slack_config() == ("xoxb-legacy", "C0EXAMPLE")


def test_an_alert_posts_as_the_bot(owner, logs, monkeypatch):
    posts = []

    def post_as_bot(channel, text, token="", log=None):
        posts.append((channel, text, token))
        return True
    monkeypatch.setitem(sys.modules, "chat_notify", types.SimpleNamespace(
        frontend_name=lambda: "slack", post_as_bot=post_as_bot))
    monkeypatch.setattr(h, "load_slack_config", lambda: ("xoxb-example", "C0EXAMPLE"))
    h.slack_alert("token expiring")
    assert posts == [("C0EXAMPLE", "token expiring", "xoxb-example")]
    assert logs[-1] == "Alert sent."
    monkeypatch.setattr(h, "load_slack_config", lambda: ("", ""))
    h.slack_alert("again")
    assert len(posts) == 1 and "missing SLACK_BOT_TOKEN" in logs[-1]


# ── the browser profile ───────────────────────────────────────────────

def test_a_new_profile_is_made_in_the_private_dir(owner, logs):
    got = h.profile_dir()
    assert got == owner.priv / h.PROFILE_NAME
    assert stat.S_IMODE(got.stat().st_mode) == 0o700


def test_a_legacy_profile_is_used_only_while_it_passes_the_checks(owner, logs):
    old = owner.auth / h.PROFILE_NAME
    old.mkdir(mode=0o700)
    assert h.profile_dir() == old
    assert any("migrate-profile" in m for m in logs)
    old.chmod(0o707)
    assert h.profile_dir() is None
    assert not (owner.priv / h.PROFILE_NAME).exists()


def test_migrate_moves_the_profile_and_refuses_a_link(owner, logs, tmp_path):
    old = owner.auth / h.PROFILE_NAME
    old.mkdir(mode=0o700)
    (old / "Cookies").write_text("c")
    assert outlook_web.main(["migrate-profile"]) == 0
    assert (owner.priv / h.PROFILE_NAME / "Cookies").read_text() == "c"
    assert not old.exists()
    (owner.priv / h.PROFILE_NAME / "Cookies").unlink()
    (owner.priv / h.PROFILE_NAME).rmdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    old.symlink_to(elsewhere)
    assert h.migrate_profile() is False
    assert not (owner.priv / h.PROFILE_NAME).exists()
