"""QE hardening for Markdown output (written before the fixes)."""

from pathlib import Path

import cmarkgfm
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from markdown_it import MarkdownIt

from linchpin.models import Finding, has_control_chars, strip_control
from linchpin.output import to_csv, to_markdown, to_table

ROOT = Path(__file__).resolve().parents[1]
MDIT = MarkdownIt("gfm-like", {"linkify": True})


def renders(md: str) -> list[str]:
    return [cmarkgfm.github_flavored_markdown_to_html(md), MDIT.render(md)]


def finding(value: str) -> Finding:
    return Finding("ID001", "high", value, value, value, {"v": value})


def data_rows(md: str) -> list[str]:
    return [line for line in md.splitlines() if line.startswith("| ID001 | high |")]


# 1) line separators: every row is exactly one line for str.splitlines
@pytest.mark.parametrize("sep", ["\u2028", "\u2029", "\x1c", "\x1d", "\x1e", "\x85", "\v", "\f"])
def test_line_separators_stripped(sep):
    assert has_control_chars(f"a{sep}b")
    assert strip_control(f"a{sep}b") == "ab"
    md = to_markdown([finding(f"x{sep}y")])
    rows = data_rows(md)
    assert len(rows) == 1
    assert len(rows[0].splitlines()) == 1
    for out in (to_table([finding(f"x{sep}y")]), to_csv([finding(f"x{sep}y")])):
        assert sep not in out


@settings(deadline=None)
@given(st.text())
def test_every_markdown_row_is_one_line(value):
    md = to_markdown([finding(value)])
    assert len(data_rows(md)) == 1
    for line in md.split("\n"):
        assert len(line.splitlines()) <= 1


# 2) no autolinks, links, images or raw HTML in rendered output
PAYLOADS = [
    "https://evil.example/p",
    "www.evil.example",
    "<https://evil.example>",
    "[x]: http://e",
    "![i](http://e/x.png)",
    "evil@attacker.example",
    "mailto:evil@attacker.example",
    "ftp://evil.example/x",
    "[t](https://evil.example)",
    "<img src=x onerror=alert(1)>",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_no_links_or_images_rendered(payload):
    md = to_markdown([finding(payload)])
    for html in renders(md):
        assert "<a" not in html and "<img" not in html and "<script" not in html


@settings(deadline=None)
@given(
    st.lists(
        st.sampled_from(
            [
                "http",
                "https",
                "www",
                ".",
                ":",
                "/",
                "//",
                "@",
                "evil",
                "example",
                "com",
                "[",
                "]",
                "(",
                ")",
                "<",
                ">",
                "!",
                "x",
                " ",
                "mailto",
            ]
        ),
        max_size=12,
    ).map("".join)
)
def test_no_links_property(value):
    for html in renders(to_markdown([finding(value)])):
        assert "<a" not in html and "<img" not in html


def test_markdown_dev_extras_and_docs():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert '"cmarkgfm' in pyproject and "markdown-it-py[linkify]" in pyproject
    assert "markdown" in (ROOT / "SPEC.md").read_text().split("## Outputs")[1].split("##")[0]
    roadmap = (ROOT / "ROADMAP.md").read_text()
    assert "(in progress, 0.2.0)" in roadmap
    assert "autolink" in (ROOT / "README.md").read_text()


# Mutation guard: '!', '(' and ')' must stay in the backslash-escape set.
@pytest.mark.parametrize("value", ["![i](x)", "(a)!", "![i](http://e/x.png)"])
def test_bang_and_parens_are_escaped(value):
    md = to_markdown([finding(value)])
    row = data_rows(md)[0]
    assert "\\!" in row and "\\(" in row and "\\)" in row
    assert "![" not in row.replace("\\![", "") and "](" not in row.replace("\\](", "")
    for html in renders(md):
        assert "<a" not in html and "<img" not in html
