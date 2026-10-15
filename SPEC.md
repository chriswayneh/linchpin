# linchpin — Spec

## Purpose
Correlate user identity exports across **Entra ID, Okta, Atlassian Crowd, and Bitbucket**
and flag identity-hygiene and insider-risk signals for IAM / security teams.

## Principles
- **CLI only.** No GUI, no server, no daemon.
- **Read-only.** Consumes exported files (or built-in `--demo` data). Never writes to,
  or calls, any identity provider or application.
- **Explainable.** Every finding carries `rule_id`, `severity`, `reason`, and `evidence`
  (the exact source fields and values that triggered it).
- **Deterministic.** Same input (or same `--seed`) → same output.
- **No secrets.** Exports should contain identity metadata only; no credentials are read or stored.

## Commands
- `linchpin identity` — identity hygiene: orphaned accounts, disabled-in-IdP-but-active-in-app,
  stale logins, privileged without MFA.
- `linchpin signals` — insider-risk signals: off-hours mass repo access, recent-leaver activity.

## Inputs
`--demo` (seeded fake data) or `--data DIR` containing `entra.json`, `okta.json`,
`crowd.json`, `bitbucket.json`. Users are correlated by normalized email.

## Outputs
`--format table` (default), `json`, `csv`. Exit code 0 always in v0.1 (gating comes later).
