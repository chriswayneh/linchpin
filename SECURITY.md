# Security Policy

## Reporting a vulnerability

Please do not open public issues for security problems.

Report vulnerabilities privately through GitHub: open the repository's **Security** tab and
choose **Report a vulnerability** (GitHub private vulnerability reporting). Include steps to
reproduce, affected version, and impact.

You can expect an acknowledgement within 5 business days. Fixes are released as patch
versions and noted in the CHANGELOG.

## Supported versions

Only the latest release receives security fixes.

## Scope

linchpin is a read-only CLI that parses identity exports. Relevant issues include crashes or
hangs on crafted input, output injection (terminal escapes, CSV formulas), and any path where
the tool could write, send, or leak data.
