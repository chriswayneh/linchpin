"""v0.2.1 tests for the 2026-10-15 review findings (written before the fixes)."""

import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from linchpin import loader, output, rules
from linchpin.models import Finding
from linchpin.output import to_table
from linchpin.rules import identity_findings, signal_findings

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
RECENT = "2026-09-30T00:00:00Z"


def empty():
    return {"entra": [], "okta": [], "crowd": [], "bitbucket": {"users": [], "events": []}}


# 1) a duplicate IdP record must never hide a disabled account, whatever the file order
@pytest.mark.parametrize("order", [0, 1])
def test_duplicate_never_hides_disabled_okta(order):
    a = {"email": "a@x.com", "status": "ACTIVE", "lastLogin": RECENT}
    b = {"email": "A@x.com", "status": "SUSPENDED", "lastLogin": RECENT}
    d = empty()
    d["okta"] = [a, b] if order == 0 else [b, a]
    d["crowd"] = [{"email": "a@x.com", "active": True, "lastAuthenticated": RECENT}]
    [f] = [x for x in identity_findings(d, NOW) if x.rule_id == "ID002"]
    assert f.evidence["okta.status"] == "SUSPENDED"


@pytest.mark.parametrize("order", [0, 1])
def test_duplicate_never_hides_disabled_entra(order):
    a = {"mail": "u@x.com", "accountEnabled": True, "lastSignInDateTime": RECENT}
    b = {"mail": "", "userPrincipalName": "U@x.com", "accountEnabled": False}
    d = empty()
    d["entra"] = [a, b] if order == 0 else [b, a]
    d["bitbucket"]["users"] = [{"email": "u@x.com", "active": True}]
    [f] = [x for x in identity_findings(d, NOW) if x.rule_id == "ID002"]
    assert f.evidence["entra.accountEnabled"] is False


# 2) SIG001 must ignore events after --now, like SIG002
def test_sig001_ignores_events_after_now():
    d = empty()
    d["bitbucket"]["events"] = [
        {"email": "f@x.com", "repo": f"r{i}", "timestamp": "2026-10-03T02:00:00Z"}
        for i in range(12)
    ]
    assert signal_findings(d, NOW) == []
    assert len(signal_findings(d, datetime(2026, 10, 4, tzinfo=timezone.utc))) == 1


# 3) a finding is labeled with the identifier its source correlates on
def test_display_id_matches_correlation_key():
    d = empty()
    d["entra"] = [
        {
            "email": "alias@x.com",
            "mail": "Real@x.com",
            "isPrivileged": True,
            "mfaRegistered": False,
            "accountEnabled": True,
            "lastSignInDateTime": RECENT,
        }
    ]
    d["okta"] = [
        {
            "email": "o@x.com",
            "login": "other@x.com",
            "isAdmin": True,
            "mfaEnrolled": False,
            "status": "ACTIVE",
            "lastLogin": "2020-01-01T00:00:00Z",
        }
    ]
    users = {(f.rule_id, f.source): f.user for f in identity_findings(d, NOW)}
    assert users[("ID004", "entra")] == "real@x.com"
    assert users[("ID004", "okta")] == "o@x.com"
    assert users[("ID003", "okta")] == "o@x.com"
    assert rules.display_id({"login": "L@x.com"}, "okta") == "l@x.com"
    assert rules.display_id({"name": "Crowd.N"}, "crowd") == "crowd.n"


# 4) one long value must not pad every table row
def test_table_width_is_capped():
    long_user = "u" * 5000 + "@x.com"
    fs = [
        Finding("ID001", "high", long_user, "crowd", "r", {}),
        Finding("ID001", "high", "s@x.com", "crowd", "r", {}),
    ]
    out = to_table(fs)
    short = [ln for ln in out.splitlines() if "s@x.com" in ln and "evidence" not in ln][0]
    assert len(short) < 200
    assert long_user in out  # never truncated, only not used for padding
    assert 20 <= output.TABLE_MAX_WIDTH <= 80


# 5) SIG002 scans events once, not once per leaver
def test_sig002_scans_events_once(monkeypatch):
    calls = {"n": 0}
    real = rules.norm_email

    def counting(value):
        calls["n"] += 1
        return real(value)

    monkeypatch.setattr(rules, "norm_email", counting)
    d = empty()
    d["entra"] = [
        {"mail": f"l{i}@x.com", "employeeLeaveDateTime": "2026-09-20T00:00:00Z"} for i in range(50)
    ]
    d["bitbucket"]["events"] = [
        {"email": f"l{i % 50}@x.com", "repo": "r", "timestamp": "2026-09-25T10:00:00Z"}
        for i in range(200)
    ]
    fs = signal_findings(d, NOW)
    assert len([f for f in fs if f.rule_id == "SIG002"]) == 50
    assert calls["n"] <= 2 * 200 + 2 * 50  # linear, not 50 x 200


# 6) a path that passes is_file() but is swapped to a FIFO must be refused, never block
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_fifo_swap_is_refused_without_blocking(tmp_path, monkeypatch):
    fifo = tmp_path / "okta.json"
    os.mkfifo(fifo)
    monkeypatch.setattr(Path, "is_file", lambda self: True)  # the race: checked as a file

    # Unblocks a blocking open so a regression fails instead of hanging; with the fix the
    # timer is cancelled before it fires, hence no coverage.
    def late_writer():  # pragma: no cover
        try:
            fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            return
        os.write(fd, b"[]")
        os.close(fd)

    t = threading.Timer(2.0, late_writer)
    t.start()
    try:
        with pytest.raises(loader.LoadError, match="not a regular file"):
            loader._read_capped(fifo)
    finally:
        t.cancel()
        t.join()


def test_version_021_docs():
    from linchpin import __version__

    root = Path(__file__).resolve().parents[1]
    assert __version__ == "0.2.1"
    assert 'version = "0.2.1"' in (root / "pyproject.toml").read_text()
    assert "## [0.2.1] - Unreleased" in (root / "CHANGELOG.md").read_text()
    readme = (root / "README.md").read_text()
    assert "fires if any of them is" in readme and "incomplete" in readme
