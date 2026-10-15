"""Regression tests for QE findings on PR #1 (written before the fixes)."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from linchpin import cli
from linchpin.loader import LoadError, load_dir
from linchpin.rules import identity_findings, signal_findings

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def empty():
    return {"entra": [], "okta": [], "crowd": [], "bitbucket": {"users": [], "events": []}}


def write(tmp_path, **files):
    for name, value in files.items():
        (tmp_path / f"{name}.json").write_text(json.dumps(value))


# 1) bad timestamps in --data -> LoadError naming file and field; CLI exit 2
@pytest.mark.parametrize(
    ("name", "payload", "field"),
    [
        ("okta", [{"email": "a@x.com", "lastLogin": "not-a-date"}], "lastLogin"),
        (
            "entra",
            [{"mail": "a@x.com", "employeeLeaveDateTime": "31/12/2026"}],
            "employeeLeaveDateTime",
        ),
        ("crowd", [{"email": "a@x.com", "lastAuthenticated": 12345}], "lastAuthenticated"),
        (
            "bitbucket",
            {"users": [], "events": [{"email": "a@x.com", "timestamp": "bad"}]},
            "timestamp",
        ),
    ],
)
def test_bad_timestamp_raises_loaderror(tmp_path, name, payload, field):
    write(tmp_path, **{name: payload})
    with pytest.raises(LoadError) as exc:
        load_dir(tmp_path)
    assert f"{name}.json" in str(exc.value)
    assert field in str(exc.value)


def test_bad_timestamp_cli_exit_2(tmp_path, capsys):
    write(tmp_path, okta=[{"email": "a@x.com", "lastLogin": "garbage"}])
    assert cli.main(["identity", "--data", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "okta.json" in err and "lastLogin" in err


# 2) entries must be objects; bitbucket users/events must be lists
@pytest.mark.parametrize(
    ("name", "payload", "match"),
    [
        ("entra", ["not-an-object"], "entra.json"),
        ("okta", [1], "okta.json"),
        ("crowd", [None], "crowd.json"),
        ("bitbucket", {"users": "x", "events": []}, "users"),
        ("bitbucket", {"users": [], "events": {}}, "events"),
        ("bitbucket", {"users": ["x"], "events": []}, "users"),
        ("bitbucket", {"users": [], "events": [3]}, "events"),
    ],
)
def test_entries_must_be_objects(tmp_path, name, payload, match):
    write(tmp_path, **{name: payload})
    with pytest.raises(LoadError, match=match):
        load_dir(tmp_path)


# 3) SIG002 must ignore None/missing repos
def test_sig002_repos_skip_none():
    d = empty()
    d["entra"] = [{"mail": "l@x.com", "employeeLeaveDateTime": "2026-09-25T00:00:00Z"}]
    d["bitbucket"]["events"] = [
        {"email": "l@x.com", "timestamp": "2026-09-26T10:00:00Z", "repo": None},
        {"email": "l@x.com", "timestamp": "2026-09-27T10:00:00Z"},
        {"email": "l@x.com", "timestamp": "2026-09-28T10:00:00Z", "repo": "proj/a"},
    ]
    [f] = signal_findings(d, NOW)
    assert f.evidence["repos"] == ["proj/a"]
    assert f.evidence["events_after_leave"] == 3


# 5) CLI threshold bounds
@pytest.mark.parametrize(
    "argv",
    [
        ["identity", "--demo", "--stale-days", "0"],
        ["identity", "--demo", "--stale-days", "-5"],
        ["signals", "--demo", "--mass-threshold", "0"],
        ["signals", "--demo", "--leaver-window-days", "-1"],
        ["signals", "--demo", "--mass-threshold", "abc"],
    ],
)
def test_cli_rejects_bad_thresholds(argv):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2


def test_cli_accepts_boundary_thresholds(capsys):
    assert cli.main(["identity", "--demo", "--stale-days", "1"]) == 0
    assert (
        cli.main(["signals", "--demo", "--mass-threshold", "1", "--leaver-window-days", "0"]) == 0
    )


# 6) SIG002 branch coverage: event before leave date, and old leaver
def test_sig002_event_before_leave_not_flagged():
    d = empty()
    d["entra"] = [{"mail": "l@x.com", "employeeLeaveDateTime": "2026-09-25T00:00:00Z"}]
    d["bitbucket"]["events"] = [
        {"email": "l@x.com", "timestamp": "2026-09-20T10:00:00Z", "repo": "proj/a"}
    ]
    assert signal_findings(d, NOW) == []


def test_sig002_old_leaver_with_activity_not_flagged():
    d = empty()
    d["entra"] = [{"mail": "old@x.com", "employeeLeaveDateTime": "2026-01-01T00:00:00Z"}]
    d["bitbucket"]["events"] = [
        {"email": "old@x.com", "timestamp": "2026-09-28T10:00:00Z", "repo": "proj/a"}
    ]
    assert signal_findings(d, NOW) == []


# 7) dev extras include security/type tooling
def test_dev_extras_include_tooling():
    # text check (tomllib is 3.11+, CI also runs 3.10)
    text = (ROOT / "pyproject.toml").read_text()
    dev = text.split("dev = [", 1)[1].split("]", 1)[0]
    for tool in ("mypy", "bandit", "pip-audit"):
        assert f'"{tool}' in dev
    assert "--cov-branch" in text


# 8) changelog
def test_changelog_has_010():
    text = (ROOT / "CHANGELOG.md").read_text()
    assert "0.1.0" in text


# 9) empty emails never correlate
def test_empty_emails_are_not_matched():
    d = empty()
    d["entra"] = [
        {"mail": "", "accountEnabled": False, "lastSignInDateTime": "2026-09-30T00:00:00Z"}
    ]
    d["okta"] = [{"email": None, "status": "DEPROVISIONED"}]
    d["crowd"] = [{"email": "", "active": True, "lastAuthenticated": "2026-09-30T00:00:00Z"}]
    d["bitbucket"]["users"] = [{"email": "  ", "active": True}]
    fs = identity_findings(d, NOW)
    assert not [f for f in fs if f.rule_id in ("ID001", "ID002")]
