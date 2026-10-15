"""Regression tests for QE round 3 on PR #1 (written before the fixes)."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from linchpin import cli
from linchpin.loader import LoadError, load_dir
from linchpin.models import Finding
from linchpin.output import to_table
from linchpin.rules import display_id, signal_findings

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]
BLANKS = [None, "", "   ", "\t"]


def empty():
    return {"entra": [], "okta": [], "crowd": [], "bitbucket": {"users": [], "events": []}}


def offhours_events(email, n=12):
    return [
        {"email": email, "timestamp": f"2026-09-27T02:{i:02d}:00Z", "repo": f"r{i}"}
        for i in range(n)
    ]


# Blocker) anonymous events are never merged into SIG001 or matched to a leaver
@pytest.mark.parametrize("blank", BLANKS)
def test_sig001_ignores_anonymous_events(blank):
    d = empty()
    d["bitbucket"]["events"] = offhours_events(blank)
    assert signal_findings(d, NOW) == []


@pytest.mark.parametrize("blank", BLANKS)
def test_sig002_anonymous_leaver_never_matches_anonymous_events(blank):
    d = empty()
    d["entra"] = [
        {"mail": blank, "userPrincipalName": blank, "employeeLeaveDateTime": "2026-09-25T00:00:00Z"}
    ]
    d["bitbucket"]["events"] = offhours_events(blank, 2) + [
        {"timestamp": "2026-09-28T10:00:00Z", "repo": "x"}
    ]
    assert signal_findings(d, NOW, mass_threshold=1) == []


blank_email = st.sampled_from(BLANKS + ["a@x.com", "B@X.com"])


@given(
    emails=st.lists(blank_email, min_size=1, max_size=20),
    leavers=st.lists(blank_email, max_size=3),
    hours=st.lists(st.integers(0, 23), min_size=1, max_size=20),
)
def test_no_sig_row_has_empty_user(emails, leavers, hours):
    d = empty()
    d["entra"] = [{"mail": m, "employeeLeaveDateTime": "2026-09-20T00:00:00Z"} for m in leavers]
    d["bitbucket"]["events"] = [
        {"email": e, "timestamp": f"2026-09-26T{h:02d}:00:00Z", "repo": f"r{i}"}
        for i, (e, h) in enumerate(zip(emails, hours, strict=False))
    ]
    for f in signal_findings(d, NOW, mass_threshold=1, leaver_window_days=30):
        assert f.user.strip()


def test_changelog_mentions_signals_anonymous():
    text = (ROOT / "CHANGELOG.md").read_text()
    assert "SIG001" in text.split("### Fixed", 1)[1]


# 1) display_id lowercases logins
def test_display_id_lowercases_login():
    assert display_id({"login": "  Okta.User@X.COM "}) == "okta.user@x.com"
    assert display_id({"name": "Crowd.Name"}) == "crowd.name"


# 2) control characters in identity fields are rejected
@pytest.mark.parametrize(
    ("name", "payload", "field"),
    [
        ("okta", [{"login": "evil\x1b[31m"}], "login"),
        ("entra", [{"mail": "a\x00@x.com"}], "mail"),
        ("crowd", [{"email": "a@x.com", "name": "n\nm"}], "name"),
        ("bitbucket", {"users": [{"username": "u\x07"}], "events": []}, "username"),
        ("bitbucket", {"users": [], "events": [{"email": "e\x7f@x.com"}]}, "email"),
    ],
)
def test_control_chars_in_identity_fields_rejected(tmp_path, name, payload, field):
    (tmp_path / f"{name}.json").write_text(json.dumps(payload))
    with pytest.raises(LoadError) as exc:
        load_dir(tmp_path)
    msg = str(exc.value)
    assert f"{name}.json" in msg and "[0]" in msg and f"'{field}'" in msg
    assert "control" in msg


def test_control_chars_cli_exit_2(tmp_path, capsys):
    (tmp_path / "okta.json").write_text(json.dumps([{"login": "x\x1b]0;pwn\x07"}]))
    assert cli.main(["identity", "--data", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "okta.json" in err and "\x1b" not in err


# 3) to_table never emits raw control chars (terminal escape injection)
def test_table_strips_terminal_escapes():
    f = Finding("ID001", "high", "evil\x1b[2J\x1b]0;pwn\x07", "crowd\r", "r\x00", {"k": "\x1b"})
    out = to_table([f])
    assert not any(ord(c) < 32 and c != "\n" or ord(c) == 127 for c in out)
    assert "evil[2J]0;pwn" in out


@given(st.text())
def test_table_property_no_control_chars(value):
    out = to_table([Finding("ID001", "high", value, value, value, {"v": value})])
    assert not any(ord(c) < 32 and c != "\n" or ord(c) == 127 for c in out)
