# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [0.1.1] - Unreleased

### Security (Red Team review)
- Control-character checks now cover Unicode categories Cc and Cf: C1 controls
  (U+0080–U+009F, including CSI U+009B), bidi overrides/isolates (U+202A–U+202E,
  U+2066–U+2069) and zero-width characters. Identity fields containing them are rejected
  (exit 2); table and CSV output strip them.
- Invalid UTF-8, deeply nested JSON (RecursionError) and timestamps with extreme UTC
  offsets (OverflowError) now raise a clear `LoadError` (exit 2) instead of a traceback.
- Export files over 200 MB are refused before being read (exit 2).
- CSV formula-injection guard ignores leading whitespace (e.g. `" =cmd"`).

### Added
- `SECURITY.md` describing private vulnerability reporting.

## [0.1.0] - 2026-10-15

### Added
- `linchpin identity` command: ID001 orphaned app account, ID002 disabled in IdP but active
  in app, ID003 stale login, ID004 privileged without MFA.
- `linchpin signals` command: SIG001 off-hours mass repo access, SIG002 recent-leaver activity.
- `--demo` seeded, deterministic fake exports across Entra ID, Okta, Atlassian Crowd, Bitbucket.
- `--data DIR` loader for `entra.json`, `okta.json`, `crowd.json`, `bitbucket.json`.
- Explainable findings (`rule_id`, `severity`, `user`, `source`, `reason`, `evidence`).
- Output formats: table, JSON, CSV (CSV cells guarded against formula injection).
- Tooling: pytest with branch coverage and hypothesis (fail-under 85), ruff, mypy (strict),
  bandit, pip-audit.

### Fixed (QE review of PR #1)
- Invalid timestamps in `--data` exports raise a clear error naming file and field (exit 2).
- Export entries must be JSON objects; Bitbucket `users`/`events` must be arrays.
- SIG002 evidence ignores missing/`None` repo values (previously crashed sorting).
- mypy error in repo collection fixed via `isinstance` narrowing.
- `--stale-days` and `--mass-threshold` must be >= 1; `--leaver-window-days` >= 0.
- Accounts with empty emails are no longer correlated with each other; their ID003/ID004
  findings show the lowercased login, name, or username instead, else `(no email)`.
  Signals skip anonymous data: SIG001 never merges events without an email, and SIG002
  never matches a leaver without an email, so no SIG finding has an empty user.
- Non-string email/identity fields in exports raise a clear error (exit 2).
- CSV output strips control characters (NUL crashed the csv writer on Python 3.10).
- IdP correlation normalizes before choosing: a blank/whitespace `mail` (Entra) or `email`
  (Okta) falls back to `userPrincipalName` / `login` instead of dropping the account.
- SIG002 fires only for leave dates within `[now - window, now]` and events strictly after
  the leave date and not after `now`; future leave dates or events never fire.
- SIG001 `first`/`last` and SIG002 `last_event` are chosen by parsed UTC time, not string
  order, so mixed UTC offsets are reported correctly.
- Control characters in identity fields are rejected on load (exit 2); table output also
  strips them as defense against terminal escape injection.
