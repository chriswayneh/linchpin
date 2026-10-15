"""v0.2.0 tests: ID005 duplicate-identity policy and markdown output (written first)."""

from datetime import datetime, timezone
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from linchpin import __version__, cli
from linchpin.demo import DEMO_NOW, generate
from linchpin.models import Finding
from linchpin.output import RENDERERS, to_markdown
from linchpin.rules import RULES, identity_findings

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]
RECENT = "2026-09-30T00:00:00Z"


def empty():
    return {"entra": [], "okta": [], "crowd": [], "bitbucket": {"users": [], "events": []}}


# ---- ID005 duplicate identities ------------------------------------------------------


def test_id005_registered():
    assert "ID005" in RULES


def test_id005_okta_duplicates_first_record_wins():
    d = empty()
    d["okta"] = [
        {"email": "A@x.com", "login": "a1", "status": "ACTIVE", "lastLogin": RECENT},
        {"email": "b@x.com", "status": "ACTIVE", "lastLogin": RECENT},
        {"email": " a@X.com ", "login": "a2", "status": "SUSPENDED", "lastLogin": RECENT},
    ]
    d["crowd"] = [{"email": "a@x.com", "active": True, "lastAuthenticated": RECENT}]
    fs = identity_findings(d, NOW)
    dup = [f for f in fs if f.rule_id == "ID005"]
    assert len(dup) == 1
    f = dup[0]
    assert (f.user, f.source, f.severity) == ("a@x.com", "okta", "medium")
    assert f.evidence["count"] == 2
    assert f.evidence["used_for_matching"] == 0
    assert [r["index"] for r in f.evidence["records"]] == [0, 2]
    assert f.evidence["records"][1]["login"] == "a2"
    # first record (ACTIVE) is used for matching: no false ID002 from the later SUSPENDED copy
    assert "ID002" not in {x.rule_id for x in fs}


def test_id005_entra_mail_vs_upn_duplicate():
    d = empty()
    d["entra"] = [
        {"mail": "", "userPrincipalName": "u@x.com", "accountEnabled": False},
        {"mail": "U@x.com", "accountEnabled": True, "lastSignInDateTime": RECENT},
    ]
    d["bitbucket"]["users"] = [{"email": "u@x.com", "active": True}]
    fs = identity_findings(d, NOW)
    [f] = [x for x in fs if x.rule_id == "ID005"]
    assert f.source == "entra" and f.evidence["used_for_matching"] == 0
    # first (disabled) record is used -> ID002 fires deterministically
    assert "ID002" in {x.rule_id for x in fs}


@pytest.mark.parametrize("source", ["crowd", "bitbucket"])
def test_id005_app_exports(source):
    d = empty()
    rows = [
        {"email": "c@x.com", "active": True, "lastAuthenticated": RECENT, "name": "c1"},
        {"email": "C@x.com", "active": False, "name": "c2"},
    ]
    if source == "bitbucket":
        d["bitbucket"]["users"] = rows
    else:
        d["crowd"] = rows
    [f] = [x for x in identity_findings(d, NOW) if x.rule_id == "ID005"]
    assert f.source == source and f.evidence["count"] == 2


def test_id005_ignores_blank_and_unique_emails():
    d = empty()
    d["okta"] = [{"email": "", "login": ""}, {"email": None}, {"email": "x@x.com"}]
    assert "ID005" not in {f.rule_id for f in identity_findings(d, NOW)}


def test_order_independent_of_input_shuffle_for_matching():
    a = {"email": "a@x.com", "status": "ACTIVE", "lastLogin": RECENT}
    b = {"email": "a@x.com", "status": "SUSPENDED", "lastLogin": RECENT}
    app = [{"email": "a@x.com", "active": True, "lastAuthenticated": RECENT}]
    d1 = {**empty(), "okta": [a, b], "crowd": app}
    d2 = {**empty(), "okta": [b, a], "crowd": app}
    # documented policy: first record in file order is used
    assert "ID002" not in {f.rule_id for f in identity_findings(d1, NOW)}
    assert "ID002" in {f.rule_id for f in identity_findings(d2, NOW)}


def test_demo_has_duplicate():
    fs = identity_findings(generate(), DEMO_NOW)
    assert "ID005" in {f.rule_id for f in fs}


# ---- markdown output -----------------------------------------------------------------


def test_markdown_registered_and_cli(capsys):
    assert RENDERERS["markdown"] is to_markdown
    assert cli.main(["identity", "--demo", "--format", "markdown"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# linchpin report")
    assert "| Severity | Count |" in out and "| Rule | Count |" in out
    assert "| ID004 |" in out


def test_markdown_summary_counts():
    fs = [
        Finding("ID001", "high", "a@x.com", "crowd", "r", {}),
        Finding("ID001", "high", "b@x.com", "crowd", "r", {}),
        Finding("ID004", "critical", "c@x.com", "okta", "r", {}),
    ]
    md = to_markdown(fs)
    assert "| critical | 1 |" in md and "| high | 2 |" in md
    assert "| ID001 | 2 |" in md and "| ID004 | 1 |" in md
    assert "3 finding(s)" in md


def test_markdown_empty():
    md = to_markdown([])
    assert "No findings." in md and "| Rule |" not in md


def test_markdown_escaping():
    evil = "a|b<script>alert(1)</script>`x`*y*_z_[l](javascript:x)\x1b[2J\u202e\r\nnext"
    md = to_markdown([Finding("ID001", "high", evil, "crowd", evil, {"k": evil})])
    rows = [line for line in md.splitlines() if line.startswith("| ID001 | high |")]
    assert len(rows) == 1
    row = rows[0]
    assert "<script>" not in md and "&lt;script&gt;" in row
    assert "a\\|b" in row
    assert row.count(" | ") == 5  # 6 cells, no injected separators
    assert "\x1b" not in md and "\u202e" not in md and "\r" not in md
    assert "](" not in row.replace("\\](", "")


@given(st.text())
def test_markdown_property_one_row_per_finding(value):
    md = to_markdown([Finding("ID001", "high", value, value, value, {"v": value})])
    rows = [line for line in md.splitlines() if line.startswith("| ID001 | high |")]
    assert len(rows) == 1
    assert "<" not in rows[0] and ">" not in rows[0]
    unescaped_pipes = rows[0].replace("\\|", "").count("|")
    assert unescaped_pipes == 7


# ---- docs / version ------------------------------------------------------------------


def test_version_020_docs():
    assert __version__ == "0.2.0"
    assert 'version = "0.2.0"' in (ROOT / "pyproject.toml").read_text()
    assert "## [0.2.0] - 2026-10-15" in (ROOT / "CHANGELOG.md").read_text()
    readme = (ROOT / "README.md").read_text()
    assert "release-v0.2.0-blue" in readme and "releases/tag/v0.2.0" in readme
    assert "linchpin.git@v0.2.0" in readme and "linchpin.git@main" not in readme
    assert "ID005" in readme and "markdown" in readme
    roadmap = (ROOT / "ROADMAP.md").read_text()
    assert "last record wins silently" not in roadmap
