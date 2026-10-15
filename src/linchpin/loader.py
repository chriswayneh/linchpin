"""Load export files from a directory (read-only)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import first_control_char, parse_ts

FILES = {
    "entra": "entra.json",
    "okta": "okta.json",
    "crowd": "crowd.json",
    "bitbucket": "bitbucket.json",
}


# Every identifier the rules may read (matching and display_id), in every section, must be a
# string without control characters, so rules never see a non-string identifier.
_ALL_IDS = ("email", "mail", "userPrincipalName", "login", "name", "username")
IDENTITY_FIELDS: dict[str, tuple[str, ...]] = {
    "entra": _ALL_IDS,
    "okta": _ALL_IDS,
    "crowd": _ALL_IDS,
    "bitbucket.users": _ALL_IDS,
    "bitbucket.events": _ALL_IDS,
}

# Flags the rules test for truthiness must be real JSON booleans ("false" is truthy).
BOOL_FIELDS: dict[str, tuple[str, ...]] = {
    "entra": ("accountEnabled", "isPrivileged", "mfaRegistered"),
    "okta": ("isAdmin", "mfaEnrolled"),
    "crowd": ("active",),
    "bitbucket.users": ("active",),
    "bitbucket.events": (),
}

TIMESTAMP_FIELDS: dict[str, tuple[str, ...]] = {
    "entra": ("lastSignInDateTime", "employeeLeaveDateTime"),
    "okta": ("lastLogin",),
    "crowd": ("lastAuthenticated",),
    "bitbucket.users": ("lastActivity",),
    "bitbucket.events": ("timestamp",),
}


MAX_FILE_BYTES = 200 * 1024 * 1024  # refuse exports over 200 MB before reading them


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
            data[key] = json.loads(_read_capped(path).decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise LoadError(f"{path}: not valid UTF-8 (byte offset {exc.start})") from exc
        except UnicodeError as exc:
            raise LoadError(f"{path}: not valid UTF-8 ({exc})") from exc
        except RecursionError as exc:
            raise LoadError(f"{path}: JSON is nested too deeply") from exc
        except json.JSONDecodeError as exc:
            raise LoadError(f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})") from exc
        except ValueError as exc:  # e.g. integer literal over the int max-str-digits limit
            raise LoadError(f"{path}: invalid JSON value ({exc})") from exc
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


def _read_capped(path: Path) -> bytes:
    """Read a regular file, refusing anything over MAX_FILE_BYTES.

    st_size is not trusted: at most MAX_FILE_BYTES + 1 bytes are read and the length checked.
    Non-regular files (directories, devices such as /dev/zero via symlink) are refused.
    """
    if not path.is_file():
        raise LoadError(f"{path}: not a regular file")
    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise LoadError(f"{path}: cannot read ({exc.strerror or exc})") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise LoadError(f"{path}: file is over the {MAX_FILE_BYTES} byte limit")
    return raw


def _validate_entries(fname: str, section: str, entries: list[Any]) -> None:
    """Every entry must be an object and every known timestamp field must parse."""
    label = section.split(".", 1)[1] if "." in section else "entry"
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise LoadError(f"{fname}: {label} [{i}] must be a JSON object")
        for field in IDENTITY_FIELDS[section]:
            if entry.get(field) is not None and not isinstance(entry[field], str):
                raise LoadError(
                    f"{fname}: {label} [{i}] field '{field}': expected a string, "
                    f"got {type(entry[field]).__name__}"
                )
            if isinstance(entry.get(field), str) and (bad := first_control_char(entry[field])):
                raise LoadError(
                    f"{fname}: {label} [{i}] field '{field}': contains U+{ord(bad):04X} "
                    "(control character)"
                )
        for field in BOOL_FIELDS[section]:
            if entry.get(field) is not None and not isinstance(entry[field], bool):
                raise LoadError(
                    f"{fname}: {label} [{i}] field '{field}': expected a JSON boolean, "
                    f"got {type(entry[field]).__name__}"
                )
        for field in TIMESTAMP_FIELDS[section]:
            value = entry.get(field)
            if value is None or value == "":
                continue
            try:
                if not isinstance(value, str):
                    raise ValueError("not a string")
                parse_ts(value)
            except (ValueError, OverflowError) as exc:
                raise LoadError(
                    f"{fname}: {label} [{i}] field '{field}': invalid ISO-8601 timestamp {value!r}"
                ) from exc
