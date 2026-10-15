"""Core data types."""

from __future__ import annotations

import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class Finding:
    """An explainable flag: which rule fired, why, and on what evidence."""

    rule_id: str
    severity: str
    user: str
    source: str
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_ts(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp (``Z`` allowed) into an aware UTC datetime."""
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def norm_email(value: str | None) -> str:
    return (value or "").strip().lower()


_CONTROL_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})


def _is_control(ch: str) -> bool:
    """C0/C1 controls and DEL (Cc) plus format chars such as bidi overrides,
    isolates and zero-width characters (Cf), and unpaired surrogates (Cs)."""
    return unicodedata.category(ch) in _CONTROL_CATEGORIES


def first_control_char(value: str) -> str | None:
    return next((c for c in value if _is_control(c)), None)


def has_control_chars(value: str) -> bool:
    return first_control_char(value) is not None


def strip_control(value: str) -> str:
    """Remove Unicode Cc, Cf and Cs characters (NUL, ESC, C1 incl. CSI, bidi overrides, ...)."""
    return "".join(c for c in value if not _is_control(c))
