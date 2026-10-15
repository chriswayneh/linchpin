"""Explainable detection rules.

Identity hygiene:
  ID001 orphaned app account (no Entra/Okta identity)
  ID002 disabled in IdP but active in an app
  ID003 stale login (> stale_days)
  ID004 privileged without MFA
Insider signals:
  SIG001 off-hours mass repo access
  SIG002 recent leaver activity
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from .models import Finding, norm_email, parse_ts

RULES = {
    "ID001": "Orphaned app account: active in an app with no Entra or Okta identity",
    "ID002": "Disabled in IdP but still active in an app",
    "ID003": "Stale login: no authentication within the stale window",
    "ID004": "Privileged account without MFA",
    "SIG001": "Off-hours mass repository access",
    "SIG002": "Activity by a recent leaver after their leave date",
}


NO_EMAIL = "(no email)"


def display_id(u: dict[str, Any]) -> str:
    """Best identifier for a finding: email, else login/name/username, else ``(no email)``."""
    for key in ("email", "mail", "userPrincipalName"):
        if email := norm_email(u.get(key)):
            return email
    for key in ("login", "name", "username"):
        value = u.get(key)
        if ident := norm_email(value if isinstance(value, str) else None):
            return ident  # lowercased, matching how identities are compared
    return NO_EMAIL


def _idp_index(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    idx: dict[str, dict[str, Any]] = defaultdict(dict)
    for u in data["entra"]:
        if email := norm_email(u.get("mail")) or norm_email(u.get("userPrincipalName")):
            idx[email]["entra"] = u
    for u in data["okta"]:
        if email := norm_email(u.get("email")) or norm_email(u.get("login")):
            idx[email]["okta"] = u
    return idx


def _apps(data: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    out = [("crowd", norm_email(u.get("email")), u) for u in data["crowd"]]
    out += [("bitbucket", norm_email(u.get("email")), u) for u in data["bitbucket"]["users"]]
    # Accounts with no email cannot be correlated; skip rather than match on "".
    return [row for row in out if row[1]]


def identity_findings(data: dict[str, Any], now: datetime, stale_days: int = 90) -> list[Finding]:
    findings: list[Finding] = []
    idp = _idp_index(data)

    for source, email, u in _apps(data):
        if not u.get("active"):
            continue
        rec = idp.get(email)
        if not rec:
            findings.append(
                Finding(
                    "ID001",
                    "high",
                    email,
                    source,
                    RULES["ID001"],
                    {"email": email, "active": True, "idp_sources_checked": ["entra", "okta"]},
                )
            )
            continue
        disabled: dict[str, Any] = {}
        if "entra" in rec and rec["entra"].get("accountEnabled") is False:
            disabled["entra.accountEnabled"] = False
        if "okta" in rec and rec["okta"].get("status", "ACTIVE") != "ACTIVE":
            disabled["okta.status"] = rec["okta"]["status"]
        if disabled:
            findings.append(
                Finding(
                    "ID002",
                    "high",
                    email,
                    source,
                    RULES["ID002"],
                    {**disabled, f"{source}.active": True},
                )
            )

    cutoff = now - timedelta(days=stale_days)
    stale_fields = [
        ("entra", "lastSignInDateTime", "accountEnabled", True),
        ("okta", "lastLogin", "status", "ACTIVE"),
        ("crowd", "lastAuthenticated", "active", True),
    ]
    for source, ts_field, active_field, active_val in stale_fields:
        for u in data[source]:
            if u.get(active_field, active_val) != active_val:
                continue
            last = parse_ts(u.get(ts_field))
            if last is None or last < cutoff:
                email = display_id(u)
                days = None if last is None else (now - last).days
                findings.append(
                    Finding(
                        "ID003",
                        "medium",
                        email,
                        source,
                        RULES["ID003"],
                        {
                            f"{source}.{ts_field}": u.get(ts_field),
                            "days_since": days,
                            "stale_days": stale_days,
                        },
                    )
                )

    for u in data["entra"]:
        if u.get("isPrivileged") and not u.get("mfaRegistered"):
            email = display_id(u)
            findings.append(
                Finding(
                    "ID004",
                    "critical",
                    email,
                    "entra",
                    RULES["ID004"],
                    {"entra.isPrivileged": True, "entra.mfaRegistered": u.get("mfaRegistered")},
                )
            )
    for u in data["okta"]:
        if u.get("isAdmin") and not u.get("mfaEnrolled"):
            email = display_id(u)
            findings.append(
                Finding(
                    "ID004",
                    "critical",
                    email,
                    "okta",
                    RULES["ID004"],
                    {"okta.isAdmin": True, "okta.mfaEnrolled": u.get("mfaEnrolled")},
                )
            )
    return _sorted(findings)


def is_off_hours(ts: datetime, start: int = 7, end: int = 20) -> bool:
    """Weekend, or outside [start, end) hours UTC."""
    return ts.weekday() >= 5 or not (start <= ts.hour < end)


def signal_findings(
    data: dict[str, Any], now: datetime, mass_threshold: int = 10, leaver_window_days: int = 30
) -> list[Finding]:
    findings: list[Finding] = []
    events = data["bitbucket"]["events"]

    buckets: dict[tuple[str, str], list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)
    for e in events:
        ts = parse_ts(e.get("timestamp"))
        email = norm_email(e.get("email"))
        if email and ts and is_off_hours(ts):  # anonymous events are never merged
            buckets[(email, ts.date().isoformat())].append((ts, e))
    for (email, day), timed in sorted(buckets.items()):
        timed.sort(key=lambda pair: pair[0])  # by parsed UTC time, not string order
        evs = [e for _, e in timed]
        repos = _repos(evs)
        if len(repos) >= mass_threshold:
            findings.append(
                Finding(
                    "SIG001",
                    "high",
                    email,
                    "bitbucket",
                    RULES["SIG001"],
                    {
                        "date": day,
                        "distinct_repos": len(repos),
                        "threshold": mass_threshold,
                        "repos": repos,
                        "first": evs[0]["timestamp"],
                        "last": evs[-1]["timestamp"],
                    },
                )
            )

    window = now - timedelta(days=leaver_window_days)
    for u in data["entra"]:
        leave = parse_ts(u.get("employeeLeaveDateTime"))
        if not leave or not window <= leave <= now:  # future leave dates never fire
            continue
        email = norm_email(u.get("mail")) or norm_email(u.get("userPrincipalName"))
        if not email:  # an anonymous leaver must never match anonymous events
            continue
        after = sorted(
            (
                (ts, e)
                for e in events
                if norm_email(e.get("email")) == email
                and (ts := parse_ts(e.get("timestamp")))
                and leave < ts <= now
            ),
            key=lambda pair: pair[0],
        )
        if after:
            findings.append(
                Finding(
                    "SIG002",
                    "critical",
                    email,
                    "bitbucket",
                    RULES["SIG002"],
                    {
                        "entra.employeeLeaveDateTime": u["employeeLeaveDateTime"],
                        "events_after_leave": len(after),
                        "repos": _repos([e for _, e in after]),
                        "last_event": after[-1][1]["timestamp"],
                    },
                )
            )
    return _sorted(findings)


def _repos(events: list[dict[str, Any]]) -> list[str]:
    """Distinct, sorted repo names; events with a missing/None/non-string repo are skipped."""
    return sorted({r for e in events if isinstance(r := e.get("repo"), str) and r})


def _sorted(findings: list[Finding]) -> list[Finding]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda f: (order.get(f.severity, 9), f.rule_id, f.user, f.source))
