# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [0.1.0] - Unreleased

### Added
- `linchpin identity` command: ID001 orphaned app account, ID002 disabled in IdP but active
  in app, ID003 stale login, ID004 privileged without MFA.
- `linchpin signals` command: SIG001 off-hours mass repo access, SIG002 recent-leaver activity.
- `--demo` seeded, deterministic fake exports across Entra ID, Okta, Atlassian Crowd, Bitbucket.
- `--data DIR` loader for `entra.json`, `okta.json`, `crowd.json`, `bitbucket.json`.
- Explainable findings (`rule_id`, `severity`, `user`, `source`, `reason`, `evidence`).
- Output formats: table, JSON, CSV (CSV cells guarded against formula injection).
- Tooling: pytest with branch coverage (fail-under 85), ruff, mypy (strict), bandit, pip-audit.

### Fixed (QE review of PR #1)
- Invalid timestamps in `--data` exports raise a clear error naming file and field (exit 2).
- Export entries must be JSON objects; Bitbucket `users`/`events` must be arrays.
- SIG002 evidence ignores missing/`None` repo values (previously crashed sorting).
- mypy error in repo collection fixed via `isinstance` narrowing.
- `--stale-days` and `--mass-threshold` must be >= 1; `--leaver-window-days` >= 0.
- Accounts with empty emails are no longer correlated with each other.
