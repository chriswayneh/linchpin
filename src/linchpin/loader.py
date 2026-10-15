"""Load export files from a directory (read-only)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FILES = {
    "entra": "entra.json",
    "okta": "okta.json",
    "crowd": "crowd.json",
    "bitbucket": "bitbucket.json",
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
    for key in ("entra", "okta", "crowd"):
        if not isinstance(data[key], list):
            raise LoadError(f"{FILES[key]} must be a JSON array")
    return data
