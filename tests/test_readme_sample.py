"""The README 'Try it' sample must match real demo output (no drift, no invented rows)."""

import re
from pathlib import Path

import pytest

from linchpin import cli

ROOT = Path(__file__).resolve().parents[1]


def trimmed(output: str) -> list[str]:
    """Real table output without evidence lines, cut before the REASON column."""
    lines = output.splitlines()
    cut = lines[0].index("REASON")
    keep = [
        line[:cut].rstrip()
        for line in lines
        if line.strip() and not line.startswith("    evidence:")
    ]
    return keep[:-1] + [lines[-1]]  # total line is short; keep it whole


def readme_block(command: str) -> list[str]:
    text = (ROOT / "README.md").read_text()
    m = re.search(rf"^\$ {re.escape(command)}\n(.*?)(?:\n\n|\n```)", text, re.M | re.S)
    assert m, f"README has no sample for {command!r}"
    return m.group(1).splitlines()


@pytest.mark.parametrize("command", ["linchpin identity --demo", "linchpin signals --demo"])
def test_readme_sample_matches_real_output(command, capsys):
    argv = command.split()[1:]
    assert cli.main(argv) == 0
    assert readme_block(command) == trimmed(capsys.readouterr().out)
