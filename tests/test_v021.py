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
    assert f.evidence["okta.status"] == ["SUSPENDED"]


@pytest.mark.parametrize("order", [0, 1])
def test_duplicate_never_hides_disabled_entra(order):
    a = {"mail": "u@x.com", "accountEnabled": True, "lastSignInDateTime": RECENT}
    b = {"mail": "", "userPrincipalName": "U@x.com", "accountEnabled": False}
    d = empty()
    d["entra"] = [a, b] if order == 0 else [b, a]
    d["bitbucket"]["users"] = [{"email": "u@x.com", "active": True}]
    [f] = [x for x in identity_findings(d, NOW) if x.rule_id == "ID002"]
    assert f.evidence["entra.accountEnabled"] == [False]


# 1b) ID002 evidence is identical under every file order: all disabled values, deduped, sorted
def test_id002_evidence_is_order_independent():
    import itertools

    okta = [
        {"email": "a@x.com", "status": "ACTIVE"},
        {"email": "A@x.com", "status": "SUSPENDED"},
        {"email": " a@x.com", "status": "DEPROVISIONED"},
        {"email": "a@X.com", "status": "SUSPENDED"},
        {"email": "a@x.com", "status": None},
    ]
    entra = [
        {"mail": "a@x.com", "accountEnabled": True},
        {"mail": "A@x.com", "accountEnabled": False},
        {"userPrincipalName": "a@x.com", "accountEnabled": None},
    ]
    seen = set()
    for po in itertools.permutations(okta):
        for pe in itertools.permutations(entra):
            d = empty()
            d["okta"], d["entra"] = list(po), list(pe)
            d["crowd"] = [{"email": "a@x.com", "active": True}]
            [f] = [x for x in identity_findings(d, NOW) if x.rule_id == "ID002"]
            seen.add(repr(sorted(f.evidence.items())))
            assert f.evidence["okta.status"] == ["DEPROVISIONED", "SUSPENDED"]
            assert f.evidence["entra.accountEnabled"] == [False]
    assert len(seen) == 1


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


# 5b) SIG002 index keys are normalized emails (mixed case / padded event emails still match)
def test_sig002_matches_unnormalized_event_emails():
    d = empty()
    d["entra"] = [{"mail": "Leaver@X.com", "employeeLeaveDateTime": "2026-09-20T00:00:00Z"}]
    d["bitbucket"]["events"] = [
        {"email": "  LEAVER@x.COM ", "repo": "r1", "timestamp": "2026-09-25T10:00:00Z"},
        {"email": "leaver@x.com\t", "repo": "r2", "timestamp": "2026-09-26T10:00:00Z"},
    ]
    [f] = [x for x in signal_findings(d, NOW) if x.rule_id == "SIG002"]
    assert f.user == "leaver@x.com" and f.evidence["events_after_leave"] == 2
    assert f.evidence["repos"] == ["r1", "r2"]


# 6) a path that passes is_file() but is swapped to a FIFO must be refused, never block.
# No writer ever opens the FIFO: a blocking open would hang, so the load runs in a daemon thread
# and must finish within 1 s.
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_fifo_swap_is_refused_without_blocking(tmp_path, monkeypatch):
    fifo = tmp_path / "okta.json"
    os.mkfifo(fifo)
    monkeypatch.setattr(Path, "is_file", lambda self: True)  # the race: checked as a file
    result: dict[str, BaseException] = {}

    def load():
        try:
            loader._read_capped(fifo)
        except BaseException as exc:  # noqa: BLE001 - recorded and asserted below
            result["exc"] = exc

    t = threading.Thread(target=load, daemon=True)
    t.start()
    t.join(timeout=1.0)
    blocked = t.is_alive()
    if blocked:  # pragma: no cover - only on regression: unblock the hung open, then fail
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
        t.join(timeout=5)
    assert not blocked, "loading a FIFO blocked (open without O_NONBLOCK?)"
    assert isinstance(result.get("exc"), loader.LoadError)
    assert "not a regular file" in str(result["exc"])


def test_version_021_docs():
    from linchpin import __version__

    root = Path(__file__).resolve().parents[1]
    assert __version__ == "0.2.1"
    assert 'version = "0.2.1"' in (root / "pyproject.toml").read_text()
    assert "## [0.2.1] - 2026-10-15" in (root / "CHANGELOG.md").read_text()
    assert "Unreleased" not in (root / "CHANGELOG.md").read_text()
    readme = (root / "README.md").read_text()
    assert "fires if any of them is" in readme and "incomplete" in readme
    assert "release-v0.2.1-blue" in readme and "releases/tag/v0.2.1" in readme
    assert "release-v0.2.0" not in readme and "releases/tag/v0.2.0" not in readme
    assert "Real output from v0.2.1." in readme and "Real output from v0.2.0" not in readme
    assert "linchpin.git@v0.2.1" in readme and "linchpin.git@v0.2.0" not in readme
    assert "linchpin.git@main" not in readme
    assert "used_for_matching" not in readme and "`first_index`" in readme
    assert "informational" in readme
    roadmap = (root / "ROADMAP.md").read_text()
    assert "v0.2.1 checks every duplicate" in roadmap
    changelog = (root / "CHANGELOG.md").read_text().split("## [0.2.0]")[0]
    assert "### Changed" in changelog and "`used_for_matching`" in changelog
    assert "`first_index`" in changelog
    demo_src = (root / "src" / "linchpin" / "demo.py").read_text()
    assert "used for matching" not in demo_src


# 1c) the sort is real: with many distinct statuses a set's iteration order differs from sorted
def test_id002_okta_status_list_is_sorted_full_set():
    statuses = ["SUSPENDED", "DEPROVISIONED", "STAGED", "LOCKED_OUT", "PROVISIONED", "RECOVERY"]
    d = empty()
    d["okta"] = [{"email": "a@x.com", "status": st} for st in statuses]
    d["crowd"] = [{"email": "a@x.com", "active": True}]
    [f] = [x for x in identity_findings(d, NOW) if x.rule_id == "ID002"]
    got = f.evidence["okta.status"]
    assert got == sorted(got)
    assert got == sorted(statuses)
