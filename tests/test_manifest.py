"""The manifest passes EA core's checks and declares what the core expects:
one graph auth source, auth_sources.manual_token, and the browser harvest
as an owner cron job every 30 minutes."""
from __future__ import annotations

from conftest import PLUGIN

import plugin_manifest as PM


def test_the_manifest_passes_the_core_checks():
    norm, errors = PM.load(PLUGIN)
    assert errors == []
    assert norm["manifest_version"] == 2 and norm["name"] == "outlook-web-auth"
    assert norm["zone"] == "owner"
    assert PM.needs_explicit_consent(PM.capability_summary(norm))


def test_the_auth_source_and_the_cron_job():
    norm, _ = PM.load(PLUGIN)
    hooks = norm["capabilities"]["owner_hooks"]
    assert hooks["auth_sources"] == [{"name": "manual-token", "kind": "graph",
                                      "module": "auth_sources.py", "function": "manual_token"}]
    (job,) = hooks["cron"]
    assert job["label"] == "harvest" and job["cron"] == "*/30 * * * *"
    assert job["command"] == ["python3", "{plugin_dir}/outlook_web.py", "refresh"]
    assert hooks["verbs"] == []
