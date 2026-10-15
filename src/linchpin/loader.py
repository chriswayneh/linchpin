"""Load export files from a directory (read-only)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import parse_ts

FILES = {
    "entra": "entra.json",
    "okta": "okta.json",
    "crowd": "crowd.json",
    "bitbucket": "bitbucket.json",
}


TIMESTAMP_FIELDS: dict[str, tuple[str, ...]] = {
    "entra": ("lastSignInDateTime", "employeeLeaveDateTime"),
    "okta": ("lastLogin",),
    "crowd": ("lastAuthenticated",),
    "bitbucket.users": ("lastActivity",),
    "bitbucket.events": ("timestamp",),
}


class LoadError(Exception):
    """Raised when an export is missing or malformed."""


def load_dir(directory: str | Path) -> dict[str, Any]:
    base = Path(directory)
    if not base.is_dir():
        raise LoadError(f"data directory not found: {base}")
    data: dict[str, Any] = {}
    for key, fname in FILES.items():
        path = base / fname
        if not path.exists():
            data[key] = {"users": [], "events": []} if key == "bitbucket" else []
            continue
        try:
            data[key] = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise LoadError(f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc
    bb = data["bitbucket"]
    if not isinstance(bb, dict):
        raise LoadError("bitbucket.json must be an object with 'users' and 'events'")
    bb.setdefault("users", [])
    bb.setdefault("events", [])
    for key in ("users", "events"):
        if not isinstance(bb[key], list):
            raise LoadError(f"bitbucket.json: '{key}' must be a JSON array")
    for key in ("entra", "okta", "crowd"):
        if not isinstance(data[key], list):
            raise LoadError(f"{FILES[key]} must be a JSON array")
    sections = [
        ("entra.json", "entra", data["entra"]),
        ("okta.json", "okta", data["okta"]),
        ("crowd.json", "crowd", data["crowd"]),
        ("bitbucket.json", "bitbucket.users", bb["users"]),
        ("bitbucket.json", "bitbucket.events", bb["events"]),
    ]
    for fname, section, entries in sections:
        _validate_entries(fname, section, entries)
    return data


def _validate_entries(fname: str, section: str, entries: list[Any]) -> None:
    """Every entry must be an object and every known timestamp field must parse."""
    label = section.split(".", 1)[1] if "." in section else "entry"
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise LoadError(f"{fname}: {label} [{i}] must be a JSON object")
        for field in TIMESTAMP_FIELDS[section]:
            value = entry.get(field)
            if value is None or value == "":
                continue
            try:
                if not isinstance(value, str):
                    raise ValueError("not a string")
                parse_ts(value)
            except ValueError as exc:
                raise LoadError(
                    f"{fname}: {label} [{i}] field '{field}': invalid ISO-8601 timestamp {value!r}"
                ) from exc
