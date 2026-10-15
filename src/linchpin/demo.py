"""Seeded, deterministic fake identity exports (no real people or credentials).

The generator builds a population of mostly-healthy users and then plants a known set
of risky scenarios so every rule has something realistic to find.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

DEMO_NOW = datetime(2026, 10, 1, 15, 0, tzinfo=timezone.utc)
DOMAIN = "example.com"

FIRST = [
    "ava",
    "ben",
    "chloe",
    "dev",
    "emma",
    "felix",
    "grace",
    "hugo",
    "isla",
    "jack",
    "kira",
    "liam",
    "maya",
    "noah",
    "olive",
    "priya",
    "quinn",
    "rosa",
    "sam",
    "theo",
]
LAST = [
    "adams",
    "brooks",
    "chen",
    "diaz",
    "evans",
    "fischer",
    "garcia",
    "hughes",
    "ito",
    "jones",
    "khan",
    "lopez",
    "moore",
    "nguyen",
    "ortiz",
    "patel",
]
REPOS = [
    f"proj/{name}"
    for name in (
        "api",
        "web",
        "infra",
        "billing",
        "auth",
        "mobile",
        "data",
        "ml",
        "docs",
        "ops",
        "search",
        "payments",
        "ledger",
        "gateway",
        "notify",
        "reports",
    )
]


def _iso(dt: datetime) -> str:
    # isoformat zero-pads the year (strftime %Y does not on Linux for years < 1000).
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def generate(seed: int = 42, users: int = 30, now: datetime = DEMO_NOW) -> dict[str, Any]:
    """Return ``{"entra": [...], "okta": [...], "crowd": [...], "bitbucket": {...}}``."""
    # Reason for nosec: seeded PRNG generates reproducible fake demo data only;
    # it is never used for secrets, tokens, or any security decision.
    rng = random.Random(seed)  # nosec B311
    names: list[str] = []
    while len(names) < users:
        n = f"{rng.choice(FIRST)}.{rng.choice(LAST)}"
        if n not in names:
            names.append(n)

    entra: list[dict[str, Any]] = []
    okta: list[dict[str, Any]] = []
    crowd: list[dict[str, Any]] = []
    bb_users: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []

    def recent() -> str:
        return _iso(now - timedelta(days=rng.randint(0, 20), hours=rng.randint(0, 23)))

    for name in names:
        email = f"{name}@{DOMAIN}"
        entra.append(
            {
                "userPrincipalName": email,
                "mail": email,
                "accountEnabled": True,
                "lastSignInDateTime": recent(),
                "isPrivileged": False,
                "mfaRegistered": True,
                "employeeLeaveDateTime": None,
            }
        )
        okta.append(
            {
                "login": email,
                "email": email,
                "status": "ACTIVE",
                "lastLogin": recent(),
                "mfaEnrolled": True,
                "isAdmin": False,
            }
        )
        crowd.append(
            {
                "name": name,
                "email": email,
                "active": True,
                "lastAuthenticated": recent(),
                "groups": ["jira-users"],
            }
        )
        bb_users.append(
            {
                "username": name.replace(".", "_"),
                "email": email,
                "active": True,
                "lastActivity": recent(),
            }
        )
        for _ in range(rng.randint(1, 4)):
            day = now - timedelta(days=rng.randint(1, 14))
            ts = day.replace(hour=rng.randint(9, 17), minute=rng.randint(0, 59))
            if ts.weekday() >= 5:
                ts -= timedelta(days=2)
            events.append(
                {
                    "email": email,
                    "timestamp": _iso(ts),
                    "action": "repo.clone",
                    "repo": rng.choice(REPOS),
                }
            )

    # --- planted scenarios (indexes are stable for a given seed) ---
    p = names
    # 1. disabled in Entra, still active in Bitbucket and Crowd
    entra[0]["accountEnabled"] = False
    okta[0]["status"] = "DEPROVISIONED"
    # 2. privileged without MFA (Entra) and Okta admin without MFA
    entra[1].update(isPrivileged=True, mfaRegistered=False)
    okta[2].update(isAdmin=True, mfaEnrolled=False)
    # 3. stale logins
    crowd[3]["lastAuthenticated"] = _iso(now - timedelta(days=200))
    okta[4]["lastLogin"] = _iso(now - timedelta(days=120))
    # 3b. duplicate identity: a second, STAGED Okta record for the same person. ID005 reports
    #     the duplicates, and ID002 fires because one of the records is not ACTIVE.
    okta.append({**okta[7], "login": okta[7]["login"].upper(), "status": "STAGED"})
    # 4. recent leaver who is still active after leave date
    leave = now - timedelta(days=10)
    entra[5].update(employeeLeaveDateTime=_iso(leave), accountEnabled=False)
    events.append(
        {
            "email": f"{p[5]}@{DOMAIN}",
            "timestamp": _iso(leave + timedelta(days=3)),
            "action": "repo.clone",
            "repo": "proj/payments",
        }
    )
    # 5. off-hours mass repo access (Saturday 02:xx UTC, many distinct repos)
    sat = now - timedelta(days=(now.weekday() - 5) % 7 or 7)
    for i, repo in enumerate(REPOS[:12]):
        events.append(
            {
                "email": f"{p[6]}@{DOMAIN}",
                "timestamp": _iso(sat.replace(hour=2, minute=i * 4, second=0)),
                "action": "repo.clone",
                "repo": repo,
            }
        )
    # 6. orphaned app accounts with no IdP identity
    crowd.append(
        {
            "name": "svc.legacy-build",
            "email": f"svc.legacy-build@{DOMAIN}",
            "active": True,
            "lastAuthenticated": recent(),
            "groups": ["admins"],
        }
    )
    bb_users.append(
        {
            "username": "contractor_old",
            "email": f"contractor.old@{DOMAIN}",
            "active": True,
            "lastActivity": recent(),
        }
    )

    events.sort(key=lambda e: (e["timestamp"], e["email"], e["repo"]))
    return {
        "entra": entra,
        "okta": okta,
        "crowd": crowd,
        "bitbucket": {"users": bb_users, "events": events},
    }
