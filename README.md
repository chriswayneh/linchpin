# linchpin

[![CI][ci-badge]][ci] [![License: MIT][lic-badge]](LICENSE) [![Python][py-badge]](pyproject.toml)
[![Release][rel-badge]][rel]

[ci-badge]: https://github.com/chriswayneh/linchpin/actions/workflows/ci.yml/badge.svg?branch=main
[ci]: https://github.com/chriswayneh/linchpin/actions/workflows/ci.yml
[lic-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[py-badge]: https://img.shields.io/badge/python-3.10%2B-blue.svg
[rel-badge]: https://img.shields.io/badge/release-v0.2.1-blue.svg
[rel]: https://github.com/chriswayneh/linchpin/releases/tag/v0.2.1

**A read-only CLI that finds identity drift across Entra ID, Okta, Atlassian Crowd and
Bitbucket, and explains every finding.**

## Quick start

### Try it
```bash
pip install git+https://github.com/chriswayneh/linchpin.git@v0.2.1
linchpin identity --demo
linchpin signals --demo
```

Real output from v0.2.1.
Every row is shown; the REASON column and the per-finding evidence lines are omitted to fit
the page (use `--format json` to see the evidence):

```text
$ linchpin identity --demo
RULE_ID  SEVERITY  USER                          SOURCE
-------  --------  ----------------------------  ---------
ID004    critical  hugo.evans@example.com        okta
ID004    critical  isla.hughes@example.com       entra
ID001    high      contractor.old@example.com    bitbucket
ID001    high      svc.legacy-build@example.com  crowd
ID002    high      ben.adams@example.com         bitbucket
ID002    high      ben.adams@example.com         crowd
ID002    high      dev.adams@example.com         bitbucket
ID002    high      dev.adams@example.com         crowd
ID002    high      hugo.adams@example.com        bitbucket
ID002    high      hugo.adams@example.com        crowd
ID003    medium    dev.chen@example.com          crowd
ID003    medium    sam.nguyen@example.com        okta
ID005    medium    hugo.adams@example.com        okta
13 finding(s).

$ linchpin signals --demo
RULE_ID  SEVERITY  USER                      SOURCE
-------  --------  ------------------------  ---------
SIG002   critical  ben.adams@example.com     bitbucket
SIG001   high      chloe.garcia@example.com  bitbucket
2 finding(s).
```

`--demo` uses seeded fake users on `example.com` across all four sources, so no tenant or
export is needed. The same seed always gives the same output.

### Install
```bash
git clone https://github.com/chriswayneh/linchpin.git
cd linchpin
pip install .            # or: pip install -e '.[dev]' for development
linchpin --version
```

Requires Python 3.10 or newer.

```bash
linchpin identity --demo                 # identity hygiene, table output
linchpin signals --demo --format json    # insider-risk signals as JSON
linchpin identity --data ./exports --format csv > identity.csv
```

### Development
```bash
pip install -e '.[dev]'
ruff check . && ruff format --check .
pytest            # branch coverage, enforces --cov-fail-under=85
mypy && bandit -r src && pip-audit --skip-editable
```

## Features

### The problem
Each system has its own copy of your users, and they drift apart:

- **Leavers still active in apps:** disabled in Entra or Okta, still enabled in Crowd or
  Bitbucket, sometimes still cloning repos after their leave date.
- **Privileged users without MFA:** Entra privileged roles or Okta admins with no MFA enrolled.
- **Stale and orphaned accounts:** no login in months, or app accounts with no identity
  provider record at all.

linchpin correlates the four exports by email and flags these cases. Each finding has a rule
id, a severity, a reason and the exact evidence fields behind it.

**Who it's for:** IAM and security engineers, auditors who need explainable evidence, and
platform teams who own Atlassian and Bitbucket access.

linchpin never calls an identity provider or application. It reads exported JSON files (or
built-in `--demo` data) and prints findings. It has no runtime dependencies.

## Usage

### Commands
| Command | What it does |
|---|---|
| `identity` | Identity hygiene: rules ID001 to ID005 |
| `signals` | Insider-risk signals: rules SIG001 and SIG002 |

#### Flags for both commands

| Flag | Default | Meaning |
|---|---|---|
| `--demo` | | Use seeded fake demo data (one of `--demo` or `--data` is required) |
| `--data DIR` | | Directory with `entra.json`, `okta.json`, `crowd.json`, `bitbucket.json` |
| `--seed N` | `42` | Demo RNG seed; same seed gives the same data |
| `--users N` | `30` | Demo user count, 7 to 300 |
| `--now TS` | demo epoch or current UTC | Reference time (ISO-8601) for all windows |
| `--format` | `table` | `table`, `json`, `csv` or `markdown` |

The demo epoch is `2026-10-01T15:00:00Z`. With `--data`, `--now` defaults to the current UTC
time.

#### Command-specific flags

| Command | Flag | Default | Meaning |
|---|---|---|---|
| `identity` | `--stale-days N` | `90` | ID003 stale window, at least 1 |
| `signals` | `--mass-threshold N` | `10` | SIG001 distinct repos per off-hours day, at least 1 |
| `signals` | `--leaver-window-days N` | `30` | SIG002 look-back for leave dates, at least 0 |

#### Input files

With `--data DIR`, missing files are treated as empty, so results for that source are
incomplete: check that all four exports are present. Users are correlated by normalized
(trimmed, lowercased) email: Entra `mail`, else `userPrincipalName`; Okta `email`, else `login`.
Times are evaluated in UTC.

**Duplicate identities:** if several records in one export normalize to the same email, ID005
lists every duplicate record (its index and identifier fields) and `first_index`, the index of
the first one in file order (informational only; it does not select a record for matching).
ID002 checks every duplicate Entra/Okta record, so it fires if any of them is disabled,
whatever the file order; its evidence lists every disabled value, deduplicated and sorted (for
example `"okta.status": ["DEPROVISIONED", "SUSPENDED"]`). Findings are labeled with the
identifier the source correlates on (Entra `mail`/`userPrincipalName`, Okta `email`/`login`).

#### Output formats

`table` (default), `json`, `csv`, and `markdown`: a report with summary counts by severity and
by rule, then a findings table. In Markdown output, control characters and Unicode line
separators are removed, `&`, `<` and `>` become HTML entities, Markdown syntax characters
(including `|`) are backslash-escaped, and `:`, `.`, `/` and `@` are written as character
references (with an invisible word joiner) so GitHub and linkify renderers create no autolinks,
links or images.

### Rules
| Rule | Severity | Meaning |
|---|---|---|
| ID001 | high | Active Crowd/Bitbucket account with no Entra or Okta identity (orphan) |
| ID002 | high | Disabled in Entra / non-ACTIVE in Okta but active in Crowd/Bitbucket |
| ID003 | medium | Active Entra/Okta/Crowd account with no login in `--stale-days` |
| ID004 | critical | Entra privileged or Okta admin without MFA |
| ID005 | medium | Several records in one export share a normalized email (duplicate identity) |
| SIG001 | high | At least `--mass-threshold` distinct repos off-hours in one UTC day |
| SIG002 | critical | Bitbucket activity after a recent leave date, up to `--now` |

A null or missing Okta `status` or Entra `accountEnabled` is treated as unknown: it never fires
ID002 as disabled, and the account is still checked by ID003. A null or missing Crowd `active`
also keeps the account in ID003 (ID003 covers Entra, Okta and Crowd only).

Off-hours means a weekend, or outside 07:00-20:00 UTC. SIG002 fires only when the leave date is
within `[now - window, now]` and the activity is after the leave date and not after `now`.

Every finding has `rule_id`, `severity`, `user`, `source`, `reason` and `evidence`.
Identity findings for accounts without an email use the lowercased login, name or username,
else `(no email)`. Signals skip events and leavers with no email, so no SIG row has an empty
user.

### Exit codes
| Code | Meaning |
|---|---|
| 0 | Success, with or without findings |
| 1 | Not used on purpose: only an unexpected internal error (uncaught exception) |
| 2 | Usage error (bad arguments, out-of-range flags, bad or too early `--now`), or a load error |

Load errors include a missing data directory, a non-regular file, a file over 200 MB, unreadable
files, invalid UTF-8 or JSON, nesting too deep, malformed entries, non-string or control-character
identity fields, an Okta `status` that is not a string, non-boolean MFA/privilege/active flags,
and invalid timestamps. Email syntax is not validated.
Errors are one line on stderr, without a traceback.

### More
- [ROADMAP.md](ROADMAP.md): phases v0.1 to v1.0
- [SECURITY.md](SECURITY.md): how to report a vulnerability
- [CHANGELOG.md](CHANGELOG.md): release notes
- [SPEC.md](SPEC.md): scope and principles

## Architecture

```mermaid
flowchart LR
    entry["linchpin console script<br/>or python -m linchpin"] --> cli
    cli["cli.py<br/>argparse, --now and window checks,<br/>exit codes"]
    files[("Export files<br/>entra, okta, crowd,<br/>bitbucket .json")] --> loader
    cli -->|"--data DIR"| loader
    cli -->|"--demo"| demo
    loader["loader.py<br/>regular file, 200 MB cap, UTF-8 JSON,<br/>type + control-char checks"]
    demo["demo.py<br/>seeded fake exports"]
    loader --> data(("exports dict"))
    demo --> data
    data --> rules["rules.py<br/>identity_findings / signal_findings"]
    rules --> findings(("sorted Findings"))
    findings --> output["output.py<br/>table / json / csv / markdown"]
    output --> stdout(["stdout"])
    models["models.py<br/>Finding, parse_ts, norm_email,<br/>control-char helpers"]
    models -.-> cli
    models -.-> loader
    models -.-> rules
    models -.-> output
```

| Module | Role | Imports (linchpin modules) |
|---|---|---|
| `cli.py` | Arguments, `--now` checks, runs commands, exit codes | the other five |
| `loader.py` | Reads and validates `--data` exports | `models` |
| `demo.py` | Generates deterministic fake exports | (none) |
| `models.py` | `Finding`, timestamp and email normalization, control-character helpers | (none) |
| `rules.py` | The seven detection rules | `models` |
| `output.py` | Renders findings as table, JSON, CSV or Markdown | `models` |

## Built with

**Languages** (GitHub language stats, checked 2026-10-21): Python 100%

**AI tools:**

- Grok Bot (confirmed by Chris, 2026-10-21)
- Cursor cloud agents (confirmed by Chris, 2026-10-21)

Commits made with AI help carry a `Co-authored-by` trailer from now on. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned phases and [CHANGELOG.md](CHANGELOG.md) for released
versions.

## Security

See [SECURITY.md](SECURITY.md) for supported versions and how to report a vulnerability privately.

### Hardening
- **Control characters:** identity fields containing Unicode Cc, Cf, Cs, Zl or Zp characters
  (C0/C1 controls including CSI, bidi overrides and isolates, zero-width characters, unpaired
  surrogates, U+2028/U+2029 line separators) are rejected on load, and the error names the code
  point (e.g. `U+200D`), never the raw character. Table, CSV and Markdown output strip the same
  categories.
- **Bounded reads:** each export must be a regular file (`is_file()`), so directories and
  devices such as a symlink to `/dev/zero` are refused. At most 200 MB + 1 byte is read, so
  the cap does not trust `st_size`.
- **CSV formula guard:** cells whose first non-whitespace character is `=`, `+`, `-` or `@` are
  prefixed with `'`.
- **Read-only:** no network calls and no writes; output goes to stdout only.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), including how to credit AI tools in commits.

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

README layout adapted from
[Best-README-Template](https://github.com/othneildrew/Best-README-Template) by Othneil Drew.
