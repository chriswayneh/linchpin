"""v0.1.2 regression tests for Codex findings (written before the fixes)."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from linchpin import __version__, cli, loader
from linchpin.loader import LoadError, load_dir
from linchpin.rules import display_id, identity_findings

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]
RECENT = "2026-09-30T00:00:00Z"


def write(tmp_path, name, payload):
    (tmp_path / f"{name}.json").write_text(json.dumps(payload))


# 1) MFA / privilege / enabled flags must be JSON booleans
@pytest.mark.parametrize(
    ("name", "entry", "field"),
    [
        ("entra", {"mail": "a@x.com", "mfaRegistered": "false"}, "mfaRegistered"),
        ("entra", {"mail": "a@x.com", "isPrivileged": "true"}, "isPrivileged"),
        ("entra", {"mail": "a@x.com", "accountEnabled": 0}, "accountEnabled"),
        ("okta", {"email": "a@x.com", "mfaEnrolled": "false"}, "mfaEnrolled"),
        ("okta", {"email": "a@x.com", "isAdmin": 1}, "isAdmin"),
        ("crowd", {"email": "a@x.com", "active": "yes"}, "active"),
        ("bitbucket", {"users": [{"email": "a@x.com", "active": "true"}], "events": []}, "active"),
    ],
)
def test_flags_must_be_booleans(tmp_path, name, entry, field):
    write(tmp_path, name, entry if name == "bitbucket" else [entry])
    with pytest.raises(LoadError) as exc:
        load_dir(tmp_path)
    msg = str(exc.value)
    assert f"{name}.json" in msg and "[0]" in msg and f"'{field}'" in msg and "boolean" in msg


def test_flags_bool_or_null_accepted(tmp_path):
    write(
        tmp_path,
        "entra",
        [{"mail": "a@x.com", "mfaRegistered": None, "isPrivileged": False, "accountEnabled": True}],
    )
    assert load_dir(tmp_path)["entra"][0]["isPrivileged"] is False


def test_string_false_mfa_cli_exit_2(tmp_path, capsys):
    write(tmp_path, "okta", [{"email": "a@x.com", "isAdmin": True, "mfaEnrolled": "false"}])
    assert cli.main(["identity", "--data", str(tmp_path)]) == 2
    assert "mfaEnrolled" in capsys.readouterr().err


# 2) every identifier display_id may read is validated, and display_id never crashes
@pytest.mark.parametrize(
    ("name", "entry", "field"),
    [
        ("entra", {"mail": "a@x.com", "email": 42}, "email"),
        ("entra", {"mail": "a@x.com", "login": ["x"]}, "login"),
        ("okta", {"email": "a@x.com", "name": 1}, "name"),
        ("crowd", {"email": "a@x.com", "username": {}}, "username"),
        ("okta", {"email": "a@x.com", "mail": "b\u202e@x.com"}, "mail"),
    ],
)
def test_all_identifier_fields_validated(tmp_path, name, entry, field):
    write(tmp_path, name, [entry])
    with pytest.raises(LoadError, match=f"{name}.json.*'{field}'"):
        load_dir(tmp_path)


def test_display_id_ignores_non_strings():
    assert display_id({"email": 42, "mail": "A@X.com"}) == "a@x.com"
    assert display_id({"email": 42, "login": None, "name": 7}) == "(no email)"


def test_entra_email_42_no_crash_in_rules():
    d = {
        "entra": [
            {
                "mail": "a@x.com",
                "email": 42,
                "accountEnabled": True,
                "lastSignInDateTime": "2020-01-01T00:00:00Z",
            }
        ],
        "okta": [],
        "crowd": [],
        "bitbucket": {"users": [], "events": []},
    }
    [f] = identity_findings(d, NOW)
    assert f.user == "a@x.com"


# 3) any UnicodeError (not only UnicodeDecodeError) -> LoadError
def test_generic_unicode_error_is_loaderror(tmp_path, monkeypatch):
    write(tmp_path, "okta", [])

    class Raw(bytes):
        def decode(self, *a, **kw):
            raise UnicodeError("bad codec state")

    monkeypatch.setattr(loader, "_read_capped", lambda path: Raw(b"[]"))
    with pytest.raises(LoadError, match="okta.json.*UTF-8"):
        load_dir(tmp_path)


# version / changelog
def test_version_012():
    assert __version__ == "0.1.2"
    assert 'version = "0.1.2"' in (ROOT / "pyproject.toml").read_text()
    assert "## [0.1.2] - Unreleased" in (ROOT / "CHANGELOG.md").read_text()
