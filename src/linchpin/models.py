"""Core data types."""

from __future__ import annotations

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


CONTROL_CHARS = {c: None for c in range(32)} | {127: None}


def has_control_chars(value: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in value)


def strip_control(value: str) -> str:
    """Remove C0 control characters and DEL (NUL, ESC, CR, LF, ...)."""
    return value.translate(CONTROL_CHARS)
