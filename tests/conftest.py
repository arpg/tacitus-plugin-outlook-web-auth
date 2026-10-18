"""Test setup: the plugin and EA core on sys.path, a scratch EA tree.

The plugin builds on EA core's owner_trust. Point EA_CORE_DIR at an
ea-system checkout (default: ../../ea-system beside this repo's parent).
"""
from __future__ import annotations

import os
import sys
import tempfile
import types
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parent.parent
CORE = Path(os.environ.get("EA_CORE_DIR") or PLUGIN.parent.parent / "ea-system")
os.environ["EA_DIR"] = tempfile.mkdtemp(prefix="outlook-web-auth-test-")
os.environ["EA_CORE_DIR"] = str(CORE)
for p in (str(CORE), str(CORE / "preprocessor"), str(PLUGIN)):
    if p not in sys.path:
        sys.path.insert(0, p)

import owner_trust as ot  # noqa: E402

if not hasattr(ot, "token_file_mode"):
    raise RuntimeError(f"{CORE}: an EA core without owner_trust.token_file_mode; "
                       f"set EA_CORE_DIR to a current ea-system checkout")


@pytest.fixture
def owner(tmp_path, monkeypatch):
    """An owner process: this euid owns the private dir, and the EA tree in
    use is the one the owner's ~/.ea names."""
    tree = tmp_path / "ea"
    for sub in ("state", "logs", "config"):
        (tree / sub).mkdir(parents=True)
    (tree / "auth").mkdir(mode=0o750)
    (tree / "auth").chmod(0o750)
    priv = tmp_path / "private"
    priv.mkdir(mode=0o700)
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir(mode=0o700)
    monkeypatch.setenv("EA_DIR", str(tree))
    monkeypatch.setenv("EA_PRIVATE_DIR", str(priv))
    monkeypatch.setenv("EA_PLUGIN_DIR", str(plugin_dir))
    monkeypatch.setattr(ot, "install_ea_dir", lambda: tree)
    assert ot.is_owner_process()
    return types.SimpleNamespace(tree=tree, priv=priv, auth=tree / "auth", tmp=tmp_path,
                                 plugin_dir=plugin_dir)
