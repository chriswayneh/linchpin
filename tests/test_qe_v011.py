"""QE regression tests for PR #2 (v0.1.1), written before the fixes."""

import json
import os
from pathlib import Path

import pytest

from linchpin import cli, loader
from linchpin import loader as loader_mod
from linchpin.loader import LoadError, load_dir
from linchpin.models import Finding, has_control_chars, strip_control
from linchpin.output import to_csv, to_table

ROOT = Path(__file__).resolve().parents[1]


# 1) int digit limit (ValueError) -> LoadError, exit 2
def test_huge_int_literal_is_loaderror(tmp_path, capsys):
    (tmp_path / "okta.json").write_text('[{"email": "a@x.com", "n": ' + "9" * 5000 + "}]")
    with pytest.raises(LoadError, match="okta.json"):
        load_dir(tmp_path)
    assert cli.main(["identity", "--data", str(tmp_path)]) == 2
    assert "okta.json" in capsys.readouterr().err


def test_changelog_mentions_digit_limit():
    entry = (ROOT / "CHANGELOG.md").read_text().split("## [0.1.0]")[0]
    assert "digit" in entry


# 2) --now overflow / too early for the windows -> parser.error (exit 2)
@pytest.mark.parametrize(
    "argv",
    [
        ["identity", "--demo", "--now", "0001-01-01T00:00:00+23:59"],
        ["identity", "--demo", "--now", "0001-01-02T00:00:00Z"],
        ["signals", "--demo", "--now", "0001-01-02T00:00:00Z"],
        ["identity", "--demo", "--stale-days", "999999999999"],
        ["signals", "--demo", "--leaver-window-days", "999999999999"],
        ["identity", "--demo", "--now", "0001-06-01T00:00:00Z"],
        ["identity", "--demo", "--now", "0001-01-02T00:00:00Z", "--stale-days", "1"],
        ["signals", "--demo", "--now", "0001-01-02T00:00:00Z", "--leaver-window-days", "0"],
    ],
)
def test_cli_now_overflow_exit_2(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2
    assert "--now" in capsys.readouterr().err


@pytest.mark.parametrize("cmd", ["identity", "signals"])
def test_cli_demo_latest_now_ok(cmd):
    assert cli.main([cmd, "--demo", "--now", "9999-12-31T23:59:59Z"]) == 0


def test_cli_early_but_valid_now_ok():
    assert cli.main(["identity", "--demo", "--now", "0002-01-01T00:00:00Z"]) == 0


# 3) size cap boundaries, non-regular files, OSError
def test_size_cap_exact_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "MAX_FILE_BYTES", 10)
    (tmp_path / "okta.json").write_text("[]" + " " * 8)  # exactly 10 bytes
    assert load_dir(tmp_path)["okta"] == []
    (tmp_path / "okta.json").write_text("[]" + " " * 9)  # 11 bytes
    with pytest.raises(LoadError, match="okta.json.*limit"):
        load_dir(tmp_path)


def test_size_cap_does_not_trust_st_size(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "MAX_FILE_BYTES", 10)
    (tmp_path / "okta.json").write_text("[" + " " * 50 + "]")
    real_stat = Path.stat

    def tiny_stat(self, *a, **kw):
        st = real_stat(self, *a, **kw)
        return os.stat_result((st.st_mode, *st[1:6], 1, *st[7:10]))

    monkeypatch.setattr(Path, "stat", tiny_stat)
    with pytest.raises(LoadError, match="limit"):
        load_dir(tmp_path)


def test_symlink_to_dev_zero_refused(tmp_path):
    os.symlink("/dev/zero", tmp_path / "okta.json")
    with pytest.raises(LoadError, match="okta.json.*regular file"):
        load_dir(tmp_path)


def test_directory_named_like_export_refused(tmp_path):
    (tmp_path / "crowd.json").mkdir()
    with pytest.raises(LoadError, match="crowd.json.*regular file"):
        load_dir(tmp_path)


def test_oserror_is_loaderror(tmp_path, monkeypatch, capsys):
    (tmp_path / "entra.json").write_text("[]")

    def boom(*a, **kw):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(loader_mod.os, "open", boom)  # loader opens via os.open (v0.2.1)
    with pytest.raises(LoadError, match="entra.json.*Permission denied"):
        load_dir(tmp_path)
    assert cli.main(["identity", "--data", str(tmp_path)]) == 2


# 4) unpaired surrogates (Cs)
def test_surrogate_is_control():
    assert has_control_chars("a\ud800b")
    assert strip_control("a\ud800b") == "ab"


def test_surrogate_output_encodes():
    f = Finding("ID001", "high", "x\udfffy", "crowd", "r\ud800", {"k": "\ud800"})
    to_table([f]).encode("utf-8")
    to_csv([f]).encode("utf-8")


def test_loader_rejects_surrogate(tmp_path):
    (tmp_path / "okta.json").write_text('[{"login": "a\\ud800@x.com"}]')
    with pytest.raises(LoadError, match="'login'.*U\\+D800"):
        load_dir(tmp_path)


# optional) error names the code point, never the raw char
def test_control_error_names_code_point(tmp_path):
    (tmp_path / "okta.json").write_text(json.dumps([{"login": "a\u200db"}]))
    with pytest.raises(LoadError) as exc:
        load_dir(tmp_path)
    assert "contains U+200D" in str(exc.value)
    assert "\u200d" not in str(exc.value)


# 5) SECURITY.md wording
def test_security_md_wording():
    text = (ROOT / "SECURITY.md").read_text()
    assert "@chriswayneh" in text
    assert "public issue" in text.lower() or "do not open an issue" in text.lower()
    assert "once the repository is public" not in text
    assert "private vulnerability reporting is turned on" in text
    assert "best effort" in text
    assert "5 business days" not in text
