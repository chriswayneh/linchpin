"""Regression tests for QE round 2 on PR #1 (written before the fixes)."""

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from linchpin import cli
from linchpin.loader import LoadError, load_dir
from linchpin.models import Finding
from linchpin.output import _safe_cell, to_csv
from linchpin.rules import identity_findings

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]
OLD = "2026-01-01T00:00:00Z"


def empty():
    return {"entra": [], "okta": [], "crowd": [], "bitbucket": {"users": [], "events": []}}


# A) no-email accounts get a fallback identifier, never a blank user
def test_id003_id004_fallback_identifiers():
    d = empty()
    d["entra"] = [
        {
            "userPrincipalName": "",
            "accountEnabled": True,
            "lastSignInDateTime": OLD,
            "isPrivileged": True,
            "mfaRegistered": False,
        }
    ]
    d["okta"] = [
        {
            "login": "okta-login-1",
            "status": "ACTIVE",
            "lastLogin": OLD,
            "isAdmin": True,
            "mfaEnrolled": False,
        }
    ]
    d["crowd"] = [{"name": "crowd-name", "active": True, "lastAuthenticated": OLD}]
    fs = [f for f in identity_findings(d, NOW) if f.rule_id in ("ID003", "ID004")]
    users = {(f.rule_id, f.source): f.user for f in fs}
    assert all(f.user for f in fs)
    assert users[("ID003", "okta")] == "okta-login-1"
    assert users[("ID004", "okta")] == "okta-login-1"
    assert users[("ID003", "crowd")] == "crowd-name"
    assert users[("ID003", "entra")] == "(no email)"
    assert users[("ID004", "entra")] == "(no email)"


def test_changelog_mentions_fallback_identifier():
    text = (ROOT / "CHANGELOG.md").read_text()
    assert "(no email)" in text


# B) non-string emails -> LoadError naming file/entry/field; CLI exits 2
@pytest.mark.parametrize(
    ("name", "payload", "field"),
    [
        ("crowd", [{"email": 5}], "email"),
        ("entra", [{"mail": ["a"]}], "mail"),
        ("entra", [{"userPrincipalName": 1.5}], "userPrincipalName"),
        ("okta", [{"login": {"x": 1}}], "login"),
        ("bitbucket", {"users": [{"email": True}], "events": []}, "email"),
        ("bitbucket", {"users": [], "events": [{"email": 7}]}, "email"),
    ],
)
def test_non_string_email_raises(tmp_path, name, payload, field):
    (tmp_path / f"{name}.json").write_text(json.dumps(payload))
    with pytest.raises(LoadError) as exc:
        load_dir(tmp_path)
    msg = str(exc.value)
    assert f"{name}.json" in msg and "[0]" in msg and f"'{field}'" in msg


def test_non_string_email_cli_exit_2(tmp_path, capsys):
    (tmp_path / "crowd.json").write_text(json.dumps([{"email": 5}]))
    assert cli.main(["identity", "--data", str(tmp_path)]) == 2
    assert "crowd.json" in capsys.readouterr().err


# C) control characters never reach the CSV writer
def test_safe_cell_strips_nul_and_controls():
    assert _safe_cell("a\x00b\x07c") == "abc"
    assert _safe_cell("=1+1") == "'=1+1"
    assert _safe_cell("\x00=cmd") == "'=cmd"


@given(st.text())
def test_csv_roundtrip_property(value):
    f = Finding("ID001", "high", value, "crowd", value, {"k": value})
    rows = list(csv.reader(io.StringIO(to_csv([f]))))
    assert len(rows) == 2
    cell = rows[1][2]
    assert not any(ord(c) < 32 or ord(c) == 127 for c in cell if c not in "\t\n\r")
    assert "\x00" not in to_csv([f])
    assert cell[:1] not in ("=", "+", "-", "@")


# D) README lines <= 100 chars
def test_readme_line_length():
    long = [
        i
        for i, line in enumerate((ROOT / "README.md").read_text().splitlines(), 1)
        if len(line) > 100
    ]
    assert long == []
