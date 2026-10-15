import csv
import io
import json
import runpy
from datetime import datetime, timezone

import pytest

from linchpin import cli
from linchpin.demo import DEMO_NOW, generate
from linchpin.loader import LoadError, load_dir
from linchpin.models import Finding, parse_ts
from linchpin.output import to_csv, to_json, to_table
from linchpin.rules import identity_findings, is_off_hours, signal_findings

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


def empty():
    return {"entra": [], "okta": [], "crowd": [], "bitbucket": {"users": [], "events": []}}


def rule_ids(findings):
    return {f.rule_id for f in findings}


def test_demo_is_deterministic_and_seed_sensitive():
    assert generate(seed=1) == generate(seed=1)
    assert generate(seed=1) != generate(seed=2)


def test_demo_has_all_sources_and_no_real_domains():
    d = generate()
    assert d["entra"] and d["okta"] and d["crowd"] and d["bitbucket"]["users"]
    blob = json.dumps(d)
    assert "@example.com" in blob
    assert "password" not in blob.lower()


def test_demo_triggers_every_rule():
    d = generate()
    assert rule_ids(identity_findings(d, DEMO_NOW)) == {"ID001", "ID002", "ID003", "ID004", "ID005"}
    assert rule_ids(signal_findings(d, DEMO_NOW)) == {"SIG001", "SIG002"}


@pytest.mark.parametrize("seed", [1, 7, 99])
def test_demo_rules_fire_across_seeds(seed):
    d = generate(seed=seed)
    assert rule_ids(signal_findings(d, DEMO_NOW)) == {"SIG001", "SIG002"}
    assert {"ID001", "ID002", "ID004"} <= rule_ids(identity_findings(d, DEMO_NOW))


def test_every_finding_is_explainable():
    d = generate()
    for f in identity_findings(d, DEMO_NOW) + signal_findings(d, DEMO_NOW):
        assert f.rule_id and f.reason and f.evidence and f.severity and f.user


def test_orphan_and_disabled():
    d = empty()
    d["crowd"] = [
        {"email": "Ghost@X.com", "active": True, "lastAuthenticated": "2026-09-30T00:00:00Z"},
        {"email": "inactive@x.com", "active": False},
    ]
    d["entra"] = [{"mail": "dis@x.com", "accountEnabled": False}]
    d["okta"] = [{"email": "sus@x.com", "status": "SUSPENDED", "lastLogin": "2026-09-30T00:00:00Z"}]
    d["bitbucket"]["users"] = [
        {"email": "dis@x.com", "active": True},
        {"email": "sus@x.com", "active": True},
    ]
    fs = identity_findings(d, NOW)
    orphan = [f for f in fs if f.rule_id == "ID001"]
    assert [f.user for f in orphan] == ["ghost@x.com"]
    dis = {f.user: f.evidence for f in fs if f.rule_id == "ID002"}
    assert dis["dis@x.com"]["entra.accountEnabled"] is False
    assert dis["sus@x.com"]["okta.status"] == "SUSPENDED"


def test_stale_and_missing_login():
    d = empty()
    d["entra"] = [
        {
            "mail": "a@x.com",
            "accountEnabled": True,
            "lastSignInDateTime": "2026-01-01T00:00:00Z",
            "mfaRegistered": True,
        },
        {"mail": "b@x.com", "accountEnabled": True, "lastSignInDateTime": None},
        {"mail": "c@x.com", "accountEnabled": False, "lastSignInDateTime": "2020-01-01T00:00:00Z"},
    ]
    stale = {f.user: f for f in identity_findings(d, NOW) if f.rule_id == "ID003"}
    assert set(stale) == {"a@x.com", "b@x.com"}
    assert stale["b@x.com"].evidence["days_since"] is None
    assert not [
        f
        for f in identity_findings(d, NOW, stale_days=10000)
        if f.rule_id == "ID003" and f.user == "a@x.com"
    ]


def test_privileged_without_mfa_negative():
    d = empty()
    d["entra"] = [
        {
            "mail": "p@x.com",
            "isPrivileged": True,
            "mfaRegistered": True,
            "accountEnabled": True,
            "lastSignInDateTime": "2026-09-30T00:00:00Z",
        }
    ]
    assert "ID004" not in rule_ids(identity_findings(d, NOW))


def test_off_hours():
    assert is_off_hours(datetime(2026, 10, 3, 12, tzinfo=timezone.utc))  # Saturday
    assert is_off_hours(datetime(2026, 10, 1, 3, tzinfo=timezone.utc))
    assert is_off_hours(datetime(2026, 10, 1, 20, tzinfo=timezone.utc))
    assert not is_off_hours(datetime(2026, 10, 1, 9, tzinfo=timezone.utc))


def test_signals_thresholds_and_old_leaver():
    d = empty()
    d["bitbucket"]["events"] = [
        {"email": "n@x.com", "timestamp": f"2026-09-30T02:0{i}:00Z", "repo": f"r{i}"}
        for i in range(5)
    ] + [{"email": "n@x.com", "timestamp": "bad-but-empty"[:0]}]
    assert not signal_findings(d, NOW)
    assert rule_ids(signal_findings(d, NOW, mass_threshold=5)) == {"SIG001"}
    d["entra"] = [
        {"mail": "old@x.com", "employeeLeaveDateTime": "2025-01-01T00:00:00Z"},
        {"mail": "n@x.com", "employeeLeaveDateTime": "2026-09-29T00:00:00Z"},
    ]
    fs = signal_findings(d, NOW, mass_threshold=50)
    assert [(f.rule_id, f.user) for f in fs] == [("SIG002", "n@x.com")]
    assert fs[0].evidence["events_after_leave"] == 5


def test_parse_ts_naive_and_empty():
    assert parse_ts(None) is None
    assert parse_ts("2026-01-01T00:00:00").tzinfo is not None


def test_outputs():
    f = Finding("ID001", "high", "=cmd@x.com", "crowd", "r, with comma", {"k": 1})
    data = json.loads(to_json([f]))
    assert data[0]["evidence"] == {"k": 1}
    rows = list(csv.reader(io.StringIO(to_csv([f]))))
    assert rows[0][0] == "rule_id"
    assert rows[1][2] == "'=cmd@x.com"
    assert rows[1][4] == "r, with comma"
    assert "evidence:" in to_table([f])
    assert to_table([]) == "No findings."


def test_loader(tmp_path):
    d = generate()
    for k in ("entra", "okta", "crowd", "bitbucket"):
        (tmp_path / f"{k}.json").write_text(json.dumps(d[k]))
    assert load_dir(tmp_path) == d


def test_loader_missing_files_and_errors(tmp_path):
    assert load_dir(tmp_path)["bitbucket"] == {"users": [], "events": []}
    with pytest.raises(LoadError, match="not found"):
        load_dir(tmp_path / "nope")
    (tmp_path / "okta.json").write_text("{bad")
    with pytest.raises(LoadError, match="invalid JSON"):
        load_dir(tmp_path)
    (tmp_path / "okta.json").write_text("{}")
    with pytest.raises(LoadError, match="array"):
        load_dir(tmp_path)
    (tmp_path / "okta.json").write_text("[]")
    (tmp_path / "bitbucket.json").write_text("[]")
    with pytest.raises(LoadError, match="object"):
        load_dir(tmp_path)


@pytest.mark.parametrize("cmd", ["identity", "signals"])
@pytest.mark.parametrize("fmt", ["table", "json", "csv"])
def test_cli_demo(capsys, cmd, fmt):
    assert cli.main([cmd, "--demo", "--format", fmt]) == 0
    out = capsys.readouterr().out
    assert ("ID00" if cmd == "identity" else "SIG00") in out


def test_cli_data_dir(tmp_path, capsys):
    d = generate()
    for k in ("entra", "okta", "crowd", "bitbucket"):
        (tmp_path / f"{k}.json").write_text(json.dumps(d[k]))
    assert (
        cli.main(
            [
                "signals",
                "--data",
                str(tmp_path),
                "--now",
                "2026-10-01T15:00:00Z",
                "--format",
                "json",
            ]
        )
        == 0
    )
    assert {f["rule_id"] for f in json.loads(capsys.readouterr().out)} == {"SIG001", "SIG002"}
    assert cli.main(["identity", "--data", str(tmp_path)]) == 0


def test_cli_errors(tmp_path, capsys):
    assert cli.main(["identity", "--data", str(tmp_path / "missing")]) == 2
    assert "not found" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["identity", "--demo", "--now", "garbage"])
    with pytest.raises(SystemExit):
        cli.main(["identity", "--demo", "--users", "3"])
    with pytest.raises(SystemExit):
        cli.main(["identity"])


def test_module_entrypoint(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["linchpin", "identity", "--demo", "--format", "json"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("linchpin", run_name="__main__")
    assert exc.value.code == 0
