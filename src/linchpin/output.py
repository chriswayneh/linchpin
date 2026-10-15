"""Render findings as table, JSON, or CSV."""

from __future__ import annotations

import csv
import io
import json

from .models import Finding, strip_control

COLUMNS = ["rule_id", "severity", "user", "source", "reason", "evidence"]


def _evidence_str(f: Finding) -> str:
    return json.dumps(f.evidence, sort_keys=True, separators=(",", ":"))


def to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2, sort_keys=True)


def _safe_cell(value: str) -> str:
    """Strip control characters (incl. NUL, which crashes csv on 3.10) and neutralise
    spreadsheet formula injection in CSV cells."""
    value = strip_control(value)
    # Spreadsheets ignore leading whitespace, so check the first non-space character.
    return "'" + value if value.lstrip()[:1] in ("=", "+", "-", "@") else value


def to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(COLUMNS)
    for f in findings:
        w.writerow(
            [
                _safe_cell(str(x))
                for x in (f.rule_id, f.severity, f.user, f.source, f.reason, _evidence_str(f))
            ]
        )
    return buf.getvalue()


def to_table(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    # Defense in depth: never write raw control chars (terminal escape injection).
    rows = [
        [strip_control(str(c)) for c in (f.rule_id, f.severity, f.user, f.source, f.reason)]
        for f in findings
    ]
    head = COLUMNS[:5]
    widths = [max(len(head[i]), *(len(r[i]) for r in rows)) for i in range(5)]
    line = "  ".join(h.upper().ljust(w) for h, w in zip(head, widths, strict=True))
    out = [line, "  ".join("-" * w for w in widths)]
    for f, r in zip(findings, rows, strict=True):
        out.append("  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip())
        out.append(f"    evidence: {strip_control(_evidence_str(f))}")
    out.append(f"\n{len(findings)} finding(s).")
    return "\n".join(out)


_SEVERITIES = ("critical", "high", "medium", "low")
_MD_ESCAPE = {c: "\\" + c for c in "\\`*_[]|~!()"}
# Defeat GFM / linkify autolinks (URLs, www., emails): ':', '.', '/' and '@' become numeric
# character references, and a WORD JOINER reference follows ':', '.' and '@' so renderers that
# decode references before autolinking still see a broken scheme, domain or address.
_WJ = "&#8288;"
_MD_ENTITIES = {":": "&#58;" + _WJ, ".": "&#46;" + _WJ, "/": "&#47;", "@": "&#64;" + _WJ}


def _md_cell(value: object) -> str:
    """Make text safe inside a Markdown table cell.

    Control characters and line separators are stripped, HTML is entity-escaped (no raw tags),
    Markdown syntax characters (including the ``|`` cell separator) are backslash-escaped, and
    URL/email characters are written as references so nothing is autolinked.
    """
    text = strip_control(str(value))
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return "".join(_MD_ENTITIES.get(c) or _MD_ESCAPE.get(c, c) for c in text)


def to_markdown(findings: list[Finding]) -> str:
    out = ["# linchpin report", "", "## Summary", ""]
    if not findings:
        out.append("No findings.")
        return "\n".join(out) + "\n"
    out.append(f"{len(findings)} finding(s).")
    out += ["", "| Severity | Count |", "|---|---|"]
    for sev in _SEVERITIES:
        if n := sum(1 for f in findings if f.severity == sev):
            out.append(f"| {sev} | {n} |")
    out += ["", "| Rule | Count |", "|---|---|"]
    for rule in sorted({f.rule_id for f in findings}):
        out.append(f"| {_md_cell(rule)} | {sum(1 for f in findings if f.rule_id == rule)} |")
    out += [
        "",
        "## Findings",
        "",
        "| Rule | Severity | User | Source | Reason | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        cells = (f.rule_id, f.severity, f.user, f.source, f.reason, _evidence_str(f))
        out.append("| " + " | ".join(_md_cell(c) for c in cells) + " |")
    return "\n".join(out) + "\n"


RENDERERS = {"table": to_table, "json": to_json, "csv": to_csv, "markdown": to_markdown}
