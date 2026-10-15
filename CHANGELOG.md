# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [0.2.0] - 2026-10-15

### Added
- ID005 (medium): duplicate identity. When several records in one export (Entra, Okta, Crowd
  or Bitbucket users) normalize to the same email, one finding lists every duplicate record
  (index and identifier/status fields) and `used_for_matching`.
- `--format markdown`: a report with summary counts by severity and by rule, then a findings
  table. Cells strip control characters and line separators, entity-escape `&`, `<`, `>`,
  backslash-escape Markdown syntax including `|`, and write `:`, `.`, `/`, `@` as character
  references so GFM and linkify renderers produce no autolinks, links or images.
- Demo data includes a duplicate Okta record so ID005 appears in `identity --demo`.

### Changed
- U+2028/U+2029 (Unicode line/paragraph separators, Zl/Zp) are treated as control characters:
  rejected in identity fields and stripped from all output formats.
- Duplicate policy: the first record in file order is used for Entra/Okta matching (was a
  silent last-record-wins). This can change ID002 results for exports with duplicates.
- ROADMAP: v0.2 is the duplicate-identity and Markdown work; later phases renumbered (real
  exports v0.3, correlation v0.4, rules config v0.5, CI gating v0.6, reporting v0.7).

## [0.1.2] - 2026-10-15

### Fixed
- MFA, privilege, enabled and active flags (`mfaRegistered`, `isPrivileged`, `accountEnabled`,
  `mfaEnrolled`, `isAdmin`, `active`) must be JSON booleans or null; a string such as
  `"false"` was treated as true. Other types now raise a clear error (exit 2).
- Every identifier field the rules read (`email`, `mail`, `userPrincipalName`, `login`,
  `name`, `username`) is type- and control-character-checked in every export, so a record such
  as `{"mail": "a@x.com", "email": 42}` exits 2 instead of crashing. Display names skip
  non-string values.
- Okta `status` must be a string or null (with the control-character check); other types exit 2.
  A null or missing Okta `status` or Entra `accountEnabled` is treated as unknown: it no longer
  fires a false ID002 or drops the account from ID003. A null Crowd `active` also stays in
  ID003 (ID003 covers Entra, Okta and Crowd only).
- Any `UnicodeError` while decoding an export (not only `UnicodeDecodeError`) exits 2.

## [0.1.1] - 2026-10-15

### Security (Red Team review)
- Control-character checks now cover Unicode categories Cc, Cf and Cs: C1 controls
  (U+0080–U+009F, including CSI U+009B), bidi overrides/isolates (U+202A–U+202E,
  U+2066–U+2069), zero-width characters and unpaired surrogates. Identity fields containing
  them are rejected (exit 2) with the code point named, e.g. `contains U+200D`; table and CSV
  output strip them.
- Invalid UTF-8, deeply nested JSON (RecursionError), integer literals over Python's
  int digit limit (ValueError) and timestamps with extreme UTC offsets (OverflowError) now
  raise a clear `LoadError` (exit 2) instead of a traceback.
- Exports must be regular files (directories and devices such as a symlink to `/dev/zero`
  are refused). At most 200 MB + 1 byte is read, so oversized files are refused without
  trusting `st_size`; read errors (OSError) exit 2.
- `--now` values that overflow, are too early for the stale/leaver window, or are too early
  to generate `--demo` data (which is dated up to ~200 days before `--now`), are rejected
  with exit 2.
- Demo timestamps zero-pad years below 1000 so they round-trip through the parser.
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
