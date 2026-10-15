# Roadmap

Each phase lists its theme and scope.

## v0.1: Foundations (done, 0.1.0 to 0.1.2)
`identity` + `signals` commands, `--demo` seeded data across Entra/Okta/Crowd/Bitbucket,
explainable flags, table/JSON/CSV output, pytest ≥85% coverage, ruff.

## v0.2: Duplicate identities and Markdown reports (in progress, 0.2.0)
ID005 duplicate-identity policy: several records with the same normalized email in one
provider export are reported with evidence, and the first record in file order is used for
matching. `--format markdown` reports: summary counts by severity and rule plus a safely
escaped findings table. Pulled forward from the correlation and reporting phases because they
fix a silent correctness gap and give auditors a shareable report without new inputs.

## v0.3: Real exports
Parsers for native export formats (Entra Graph JSON, Okta CSV/API JSON, Crowd XML/CSV,
Bitbucket audit log), schema validation, clear parse errors.

## v0.4: Correlation
Alias/UPN matching beyond email, manual mapping file, confidence scores on joins.

## v0.5: Rules config
YAML rule config (thresholds, business hours, timezones), enable/disable rules,
severity overrides.

## v0.6: CI gating
`--fail-on severity`, baseline/suppression file with expiry and justification.

## v0.7: Reporting
SARIF output, diff between two runs.

## v0.8: More signals
Privilege creep, group-membership drift, dormant service accounts,
shared-account heuristics.

## v0.9: Scale and hardening
Streaming parsing for large exports, performance benchmarks, fuzzing of parsers, docs site,
packaging, signed releases.

## v1.0: Stable
Stable rule ids and output schema, semantic versioning guarantees, PyPI release.

## Known limitations
- Only linchpin's own JSON input layout is accepted; native provider export formats arrive in
  v0.3.
- Users are correlated by email only (Entra `mail`/UPN, Okta `email`/`login`).
