# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| 0.1.x | No |

Fixes are released on the latest 0.2.x version only.

## Reporting a vulnerability

Report vulnerabilities privately to the owner, @chriswayneh on GitHub. Never report a
suspected vulnerability in a public issue, pull request or discussion.

GitHub private vulnerability reporting is turned on for this repository and is the
preferred channel: use the **Report a vulnerability** form on the **Security** tab, or go
directly to https://github.com/chriswayneh/linchpin/security/advisories/new.

Include what you can of:
- the affected version (`linchpin --version`) and command,
- steps to reproduce, using `--demo` data or redacted exports,
- the impact you expect.

Never include real identity exports, secrets or tokens in a report.

## What to expect

linchpin is maintained by one person, so responses are best effort. The aim is to
acknowledge a report within a week, then keep you updated on the assessment and any fix.
Credit in the CHANGELOG is offered once a fix is released, if you want it.

## Scope

linchpin is a read-only CLI that parses identity exports. Relevant issues include crashes or
hangs on crafted input, output injection (terminal escapes, CSV formulas), and any path where
the tool could write, send, or leak data.
