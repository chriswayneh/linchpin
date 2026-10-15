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
    "ID005": "Duplicate identity: several records in one export share a normalized email",
    "SIG001": "Off-hours mass repository access",
    "SIG002": "Activity by a recent leaver after their leave date",
}


NO_EMAIL = "(no email)"


def display_id(u: dict[str, Any], source: str | None = None) -> str:
    """Best identifier for a finding, else ``(no email)``.

    With ``source``, the record's correlation key (see ``_match_key``) comes first, so a finding
    is labeled with the same identity it is matched on. Then email/mail/UPN, then
    login/name/username.
    """
    if source is not None and (key := _match_key(source, u)):
        return key
    for key in ("email", "mail", "userPrincipalName"):
        value = u.get(key)
        if isinstance(value, str) and (email := norm_email(value)):
            return email
    for key in ("login", "name", "username"):
        value = u.get(key)
        if ident := norm_email(value if isinstance(value, str) else None):
            return ident  # lowercased, matching how identities are compared
    return NO_EMAIL


def _match_key(source: str, u: dict[str, Any]) -> str:
    """Normalized email used to correlate a record ("" when it has none)."""
    if source == "entra":
        return norm_email(u.get("mail")) or norm_email(u.get("userPrincipalName"))
    if source == "okta":
        return norm_email(u.get("email")) or norm_email(u.get("login"))
    return norm_email(u.get("email"))


def _records(data: dict[str, Any], source: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = (
        data["bitbucket"]["users"] if source == "bitbucket" else data[source]
    )
    return records


def _idp_index(data: dict[str, Any]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Index every Entra and Okta record by normalized email, in file order.

    Duplicate policy: all duplicate records are kept, so ID002 fires when ANY of them is
    disabled (order-independent; a duplicate can never hide a disabled account). ID005 reports
    the duplicates.
    """
    idx: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for source in ("entra", "okta"):
        for u in data[source]:
            if email := _match_key(source, u):
                idx[email][source].append(u)
    return idx


_DUP_EVIDENCE_FIELDS = (
    "email",
    "mail",
    "userPrincipalName",
    "login",
    "name",
    "username",
    "status",
    "accountEnabled",
    "active",
)


def _duplicate_findings(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for source in ("entra", "okta", "crowd", "bitbucket"):
        groups: dict[str, list[int]] = defaultdict(list)
        for i, u in enumerate(_records(data, source)):
            if key := _match_key(source, u):
                groups[key].append(i)
        for email, indexes in groups.items():
            if len(indexes) < 2:
                continue
            records = [
                {
                    "index": i,
                    **{
                        k: _records(data, source)[i][k]
                        for k in _DUP_EVIDENCE_FIELDS
                        if k in _records(data, source)[i]
                    },
                }
                for i in indexes
            ]
            findings.append(
                Finding(
                    "ID005",
                    "medium",
                    email,
                    source,
                    RULES["ID005"],
                    {"count": len(indexes), "first_index": indexes[0], "records": records},
                )
            )
    return findings


def _apps(data: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    out = [("crowd", norm_email(u.get("email")), u) for u in data["crowd"]]
    out += [("bitbucket", norm_email(u.get("email")), u) for u in data["bitbucket"]["users"]]
    # Accounts with no email cannot be correlated; skip rather than match on "".
    return [row for row in out if row[1]]


def identity_findings(data: dict[str, Any], now: datetime, stale_days: int = 90) -> list[Finding]:
    findings: list[Finding] = _duplicate_findings(data)
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
        # Every duplicate record is checked; evidence lists each disabled value once, sorted, so
        # it is identical whatever the file order. A null or missing value is unknown, not
        # disabled.
        disabled: dict[str, Any] = {}
        if any(r.get("accountEnabled") is False for r in rec.get("entra", [])):
            disabled["entra.accountEnabled"] = [False]
        okta_bad = sorted(
            {
                st
                for r in rec.get("okta", [])
                if (st := r.get("status")) is not None and st != "ACTIVE"
            }
        )
        if okta_bad:
            disabled["okta.status"] = okta_bad
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
            state = u.get(active_field)
            if state is not None and state != active_val:  # null/missing = unknown, still checked
                continue
            last = parse_ts(u.get(ts_field))
            if last is None or last < cutoff:
                email = display_id(u, source)
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
            email = display_id(u, "entra")
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
            email = display_id(u, "okta")
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
        # anonymous events are never merged; events after --now never count
        if email and ts and ts <= now and is_off_hours(ts):
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

    # Index timed events by normalized email once: O(events + leavers), not O(events x leavers).
    by_email: dict[str, list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)
    for e in events:
        if (key := norm_email(e.get("email"))) and (ts := parse_ts(e.get("timestamp"))):
            by_email[key].append((ts, e))

    window = now - timedelta(days=leaver_window_days)
    for u in data["entra"]:
        leave = parse_ts(u.get("employeeLeaveDateTime"))
        if not leave or not window <= leave <= now:  # future leave dates never fire
            continue
        email = norm_email(u.get("mail")) or norm_email(u.get("userPrincipalName"))
        if not email:  # an anonymous leaver must never match anonymous events
            continue
        after = sorted(
            ((ts, e) for ts, e in by_email.get(email, []) if leave < ts <= now),
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
