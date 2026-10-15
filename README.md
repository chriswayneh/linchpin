# linchpin

CLI-only, read-only Python tool that correlates identity exports from Microsoft Entra ID,
Okta, Atlassian Crowd, and Bitbucket to flag identity-hygiene and insider-risk signals.
Every flag is explainable: rule id, reason, and the evidence fields behind it.

See [SPEC.md](SPEC.md) and [ROADMAP.md](ROADMAP.md). Status: pre-release.

## Quick start (v0.1)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'

linchpin identity --demo                 # identity hygiene, table output
linchpin signals  --demo --format json   # insider-risk signals as JSON
linchpin identity --data ./exports --format csv
```

`--data DIR` reads `entra.json`, `okta.json`, `crowd.json`, `bitbucket.json` (missing files
are treated as empty; malformed entries, emails, or timestamps exit with code 2). Users are
correlated by normalized email. `--demo` data is seeded (`--seed`, `--users 7..300`) and uses
`example.com` addresses only. Times are evaluated in UTC.

| Rule | Severity | Meaning |
|---|---|---|
| ID001 | high | Active Crowd/Bitbucket account with no Entra or Okta identity (orphan) |
| ID002 | high | Disabled in Entra / non-ACTIVE in Okta but active in Crowd/Bitbucket |
| ID003 | medium | Active Entra/Okta/Crowd account with no login in `--stale-days` (90) |
| ID004 | critical | Entra privileged or Okta admin without MFA |
| SIG001 | high | ≥ `--mass-threshold` (10) distinct repos off-hours in one UTC day |
| SIG002 | critical | Bitbucket activity after a leave date within `--leaver-window-days` (30) |

Off-hours means a weekend, or outside 07:00–20:00 UTC.
Findings for accounts without an email use login, name, or username, else `(no email)`.

Every finding has `rule_id`, `severity`, `user`, `source`, `reason`, and `evidence`.

## Development

```bash
ruff check . && ruff format --check .
pytest            # branch coverage, enforces --cov-fail-under=85
mypy && bandit -r src && pip-audit --skip-editable
```
