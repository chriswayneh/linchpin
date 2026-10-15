"""Render findings as table, JSON, or CSV."""

from __future__ import annotations

import csv
import io
import json

from .models import Finding

COLUMNS = ["rule_id", "severity", "user", "source", "reason", "evidence"]


def _evidence_str(f: Finding) -> str:
    return json.dumps(f.evidence, sort_keys=True, separators=(",", ":"))


def to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2, sort_keys=True)


def _safe_cell(value: str) -> str:
    """Neutralise spreadsheet formula injection in CSV cells."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


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
    rows = [[f.rule_id, f.severity, f.user, f.source, f.reason] for f in findings]
    head = COLUMNS[:5]
    widths = [max(len(head[i]), *(len(r[i]) for r in rows)) for i in range(5)]
    line = "  ".join(h.upper().ljust(w) for h, w in zip(head, widths, strict=True))
    out = [line, "  ".join("-" * w for w in widths)]
    for f, r in zip(findings, rows, strict=True):
        out.append("  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip())
        out.append(f"    evidence: {_evidence_str(f)}")
    out.append(f"\n{len(findings)} finding(s).")
    return "\n".join(out)


RENDERERS = {"table": to_table, "json": to_json, "csv": to_csv}
