# Roadmap

Each phase lists its theme and scope.

## v0.1: Foundations
`identity` + `signals` commands, `--demo` seeded data across Entra/Okta/Crowd/Bitbucket,
explainable flags, table/JSON/CSV output, pytest ≥85% coverage, ruff.

## v0.2: Real exports
Parsers for native export formats (Entra Graph JSON, Okta CSV/API JSON, Crowd XML/CSV,
Bitbucket audit log), schema validation, clear parse errors.

## v0.3: Correlation
Alias/UPN matching beyond email, manual mapping file, confidence scores on joins.

## v0.4: Rules config
YAML rule config (thresholds, business hours, timezones), enable/disable rules,
severity overrides.

## v0.5: CI gating
`--fail-on severity`, baseline/suppression file with expiry and justification.

## v0.6: Reporting
Markdown/HTML-free text reports, SARIF output, diff between two runs.

## v0.7: More signals
Privilege creep, group-membership drift, dormant service accounts,
shared-account heuristics.

## v0.8: Scale
Streaming parsing for large exports, performance benchmarks.

## v0.9: Hardening
Fuzzing of parsers, docs site, packaging, signed releases.

## v1.0: Stable
Stable rule ids and output schema, semantic versioning guarantees, PyPI release.
