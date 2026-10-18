"""auth_sources.manual_token: the token EA core's authenticate() gets from
this plugin. A Graph or Outlook REST token with time left is returned; a
wrong audience, a spent token, an empty file or the placeholder is not; a
token that cannot be decoded is used with a warning; a link at the file is
refused by the owner checks."""
from __future__ import annotations

import base64
import json
import time

import pytest

import auth_sources as src
import owner_trust as ot


def _jwt(claims: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJub25lIn0.{body}.sig"


def _put(owner, text, mode=0o600):
    path = owner.auth / src.TOKEN_NAME
    path.write_text(text)
    path.chmod(mode)
    return path


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    monkeypatch.setitem(src._ANNOUNCED, "done", False)


@pytest.mark.parametrize("aud", [src.GRAPH_AUDIENCE, src.GRAPH_AUDIENCE_URL, src.OUTLOOK_AUDIENCE])
def test_a_graph_or_outlook_token_with_time_left_is_returned(owner, aud, capsys):
    tok = _jwt({"aud": aud, "exp": int(time.time()) + 3600,
                "preferred_username": "someone@example.org"})
    _put(owner, tok + "\n")
    assert src.manual_token() == tok
    assert "someone@example.org" in capsys.readouterr().err
    assert src.manual_token() == tok
    assert capsys.readouterr().err == ""             # announced once


def test_a_wrong_audience_is_refused(owner, capsys):
    _put(owner, _jwt({"aud": "https://ic3.example.org", "exp": int(time.time()) + 3600}))
    assert src.manual_token() is None
    assert "wrong audience" in capsys.readouterr().err


def test_a_spent_token_is_refused_with_the_way_to_refresh(owner, capsys):
    _put(owner, _jwt({"aud": src.GRAPH_AUDIENCE_URL, "exp": int(time.time()) + 30}))
    assert src.manual_token() is None
    err = capsys.readouterr().err
    assert "EXPIRED" in err and "outlook_web.py refresh" in err


@pytest.mark.parametrize("text", ["", "\n", src.PLACEHOLDER])
def test_an_empty_file_or_the_placeholder_is_no_token(owner, text):
    _put(owner, text)
    assert src.manual_token() is None


def test_no_file_is_no_token(owner):
    assert src.manual_token() is None


def test_a_token_that_cannot_be_decoded_is_used_with_a_warning(owner, capsys):
    _put(owner, "opaque-token")
    assert src.manual_token() == "opaque-token"
    assert "could not decode" in capsys.readouterr().err


def test_a_link_at_the_token_file_is_refused(owner, tmp_path):
    planted = tmp_path / "planted"
    planted.write_text(_jwt({"aud": src.GRAPH_AUDIENCE_URL, "exp": int(time.time()) + 3600}))
    planted.chmod(0o600)
    (owner.auth / src.TOKEN_NAME).symlink_to(planted)
    with pytest.raises(ot.OwnerTrustError):
        src.manual_token()


def test_token_io_is_checked_on_the_install_tree_without_a_private_dir(monkeypatch, tmp_path):
    tree = tmp_path / "ea"
    tree.mkdir()
    monkeypatch.setenv("EA_DIR", str(tree))
    monkeypatch.setenv("EA_PRIVATE_DIR", str(tmp_path / "missing"))
    monkeypatch.setattr(ot, "install_ea_dir", lambda: tree)
    assert not ot.is_owner_process()
    assert src.checked_token_io()
    monkeypatch.setattr(ot, "install_ea_dir", lambda: tmp_path / "other-tree")
    assert not src.checked_token_io()
