"""Regression tests for second review of PR #1 (written before the fixes)."""

from datetime import datetime, timezone

import pytest

from linchpin.rules import identity_findings, signal_findings

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
RECENT = "2026-09-30T00:00:00Z"


def empty():
    return {"entra": [], "okta": [], "crowd": [], "bitbucket": {"users": [], "events": []}}


# 1) normalize before choosing between mail/UPN and email/login
@pytest.mark.parametrize(
    ("source", "user"),
    [
        ("entra", {"mail": "   ", "userPrincipalName": "Dis@X.com", "accountEnabled": False}),
        ("okta", {"email": " \t", "login": "Dis@X.com", "status": "SUSPENDED"}),
    ],
)
def test_whitespace_primary_falls_back_to_secondary(source, user):
    d = empty()
    d[source] = [{**user, "lastSignInDateTime": RECENT, "lastLogin": RECENT}]
    d["crowd"] = [{"email": "dis@x.com", "active": True, "lastAuthenticated": RECENT}]
    ids = {f.rule_id for f in identity_findings(d, NOW) if f.user == "dis@x.com"}
    assert "ID002" in ids
    assert "ID001" not in ids


# 2) SIG002 bounds: window_start <= leave <= now and leave < ts <= now
def sig002(leave, *event_ts):
    d = empty()
    d["entra"] = [{"mail": "l@x.com", "employeeLeaveDateTime": leave}]
    d["bitbucket"]["events"] = [
        {"email": "l@x.com", "timestamp": ts, "repo": "r"} for ts in event_ts
    ]
    return [f for f in signal_findings(d, NOW) if f.rule_id == "SIG002"]


def test_sig002_future_leave_date_does_not_fire():
    assert sig002("2026-10-20T00:00:00Z", "2026-10-25T00:00:00Z") == []


def test_sig002_future_events_do_not_count():
    assert sig002("2026-09-25T00:00:00Z", "2026-10-05T00:00:00Z") == []
    [f] = sig002("2026-09-25T00:00:00Z", "2026-09-26T00:00:00Z", "2026-10-05T00:00:00Z")
    assert f.evidence["events_after_leave"] == 1
    assert f.evidence["last_event"] == "2026-09-26T00:00:00Z"


def test_sig002_boundaries_inclusive():
    # leave exactly at window start, event exactly at now
    [f] = sig002("2026-09-01T12:00:00Z", "2026-10-01T12:00:00Z")
    assert f.evidence["events_after_leave"] == 1
    # leave exactly now: no event can be strictly after and <= now
    assert sig002("2026-10-01T12:00:00Z", "2026-10-01T12:00:00Z") == []


# 3) first/last/last_event chosen by parsed UTC time, not string compare
def test_sig001_first_last_by_parsed_time_mixed_offsets():
    d = empty()
    # 2026-09-27 is Sunday. String order differs from real UTC order.
    d["bitbucket"]["events"] = [
        {"email": "a@x.com", "timestamp": "2026-09-27T09:00:00+08:00", "repo": "r1"},  # 01:00Z
        {"email": "a@x.com", "timestamp": "2026-09-27T02:00:00Z", "repo": "r2"},  # 02:00Z
        {"email": "a@x.com", "timestamp": "2026-09-26T23:30:00-05:00", "repo": "r3"},  # 04:30Z
    ]
    [f] = signal_findings(d, NOW, mass_threshold=3)
    assert f.evidence["first"] == "2026-09-27T09:00:00+08:00"
    assert f.evidence["last"] == "2026-09-26T23:30:00-05:00"


def test_sig002_last_event_by_parsed_time_mixed_offsets():
    [f] = sig002(
        "2026-09-25T00:00:00Z",
        "2026-09-28T23:00:00-05:00",  # 2026-09-29T04:00Z (latest)
        "2026-09-29T03:00:00Z",
    )
    assert f.evidence["last_event"] == "2026-09-28T23:00:00-05:00"
