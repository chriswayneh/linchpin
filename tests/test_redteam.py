"""Red Team regression tests for v0.1.1 (written before the fixes)."""

import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from linchpin import __version__, cli, loader
from linchpin.loader import LoadError, load_dir
from linchpin.models import has_control_chars, strip_control
from linchpin.output import _safe_cell

ROOT = Path(__file__).resolve().parents[1]
UNICODE_CONTROLS = ["\x80", "\x9b", "\x9f", "\u202a", "\u202e", "\u2066", "\u2069", "\u200b"]


# 1) Unicode Cc and Cf (C1 controls, bidi overrides/isolates, zero-width)
@pytest.mark.parametrize("ch", UNICODE_CONTROLS)
def test_has_control_chars_unicode(ch):
    assert has_control_chars(f"a{ch}b")
    assert strip_control(f"a{ch}b") == "ab"


@pytest.mark.parametrize("ch", ["\x9b", "\u202e", "\u2066"])
def test_loader_rejects_unicode_controls(tmp_path, ch):
    (tmp_path / "okta.json").write_text(json.dumps([{"login": f"adm{ch}in@x.com"}]))
    with pytest.raises(LoadError, match="okta.json.*'login'.*control"):
        load_dir(tmp_path)


def test_normal_unicode_is_kept():
    assert not has_control_chars("josé.müller@例え.jp")
    assert strip_control("josé") == "josé"


@given(st.text())
def test_strip_control_property(value):
    import unicodedata

    out = strip_control(value)
    assert not has_control_chars(out)
    assert all(unicodedata.category(c) not in ("Cc", "Cf") for c in out)


# 2) decode / recursion / overflow errors become LoadError (exit 2)
def test_invalid_utf8_is_loaderror(tmp_path):
    (tmp_path / "entra.json").write_bytes(b'[{"mail": "\xff\xfe"}]')
    with pytest.raises(LoadError, match="entra.json.*UTF-8"):
        load_dir(tmp_path)


def test_deeply_nested_json_is_loaderror(tmp_path):
    (tmp_path / "crowd.json").write_text("[" * 200_000 + "]" * 200_000)
    with pytest.raises(LoadError, match="crowd.json.*nest"):
        load_dir(tmp_path)


def test_extreme_tz_offset_is_loaderror(tmp_path):
    (tmp_path / "okta.json").write_text(
        json.dumps([{"email": "a@x.com", "lastLogin": "0001-01-01T00:00:00+23:59"}])
    )
    with pytest.raises(LoadError, match="okta.json.*'lastLogin'"):
        load_dir(tmp_path)


def test_bad_inputs_exit_2(tmp_path, capsys):
    (tmp_path / "entra.json").write_bytes(b"\xff")
    assert cli.main(["identity", "--data", str(tmp_path)]) == 2
    assert "entra.json" in capsys.readouterr().err


# 3) refuse oversized files, reading at most MAX + 1 bytes
# (replaces the v0.1.1 st_size-based test: QE asked not to trust st_size)
def test_oversized_file_reads_at_most_cap_plus_one(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "MAX_FILE_BYTES", 16)
    (tmp_path / "okta.json").write_text("[" + " " * 1000 + "]")
    sizes = []
    real_fdopen = loader.os.fdopen

    def spy_open(fd, *a, **kw):  # loader opens via os.open + os.fdopen (v0.2.1)
        fh = real_fdopen(fd, *a, **kw)
        real_read = fh.read

        def read(n=-1):
            sizes.append(n)
            return real_read(n)

        fh.read = read
        return fh

    monkeypatch.setattr(loader.os, "fdopen", spy_open)
    with pytest.raises(LoadError, match="okta.json.*limit"):
        load_dir(tmp_path)
    assert sizes == [17]


def test_max_size_constant():
    assert loader.MAX_FILE_BYTES == 200 * 1024 * 1024


# 4) formula guard ignores leading whitespace
@pytest.mark.parametrize("value", [" =cmd", "  +1", "\u3000@x", " -2"])
def test_csv_guard_leading_whitespace(value):
    assert _safe_cell(value).startswith("'")


# 5) SECURITY.md and version
def test_security_md():
    text = (ROOT / "SECURITY.md").read_text()
    assert "Security" in text and "private vulnerability reporting" in text.lower()


def test_version_011():
    # Pinned version moved to the current release test; keep the 0.1.1 entry check and
    # require pyproject and __version__ to agree.
    assert f'version = "{__version__}"' in (ROOT / "pyproject.toml").read_text()
    assert "## [0.1.1]" in (ROOT / "CHANGELOG.md").read_text()
