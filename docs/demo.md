# Terminal demo

The README GIF replays actual output captured from the published
`linchpin` **v0.2.1** package on 2026-11-05 (America/Chicago), using only the
built-in `--demo` seeded fixtures. Timing is adjusted for README readability.
It is a recorded replay, not a live Entra, Okta, Crowd, or Bitbucket session.

## What it shows

1. Confirm the installed version (`0.2.1`).
2. `linchpin signals --demo` — insider-risk signals from the seeded fixtures
   (leaver activity after leave date; off-hours mass repository access).
3. `linchpin identity --demo` — identity hygiene findings (privileged without
   MFA, orphaned app accounts, disabled-in-IdP-but-active, stale logins,
   duplicate identities), each with rule id, severity, reason, and evidence.

## Run it yourself

Use Python 3.10 or newer in an isolated environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install "git+https://github.com/chriswayneh/linchpin.git@v0.2.1"

.venv/bin/linchpin --version
.venv/bin/linchpin signals --demo
.venv/bin/linchpin identity --demo
```

`--demo` uses seeded fake data only. linchpin never calls an identity provider
or application API. Do not pass real export directories or credentials for this
walkthrough.

## Re-record the GIF

Requires [vhs](https://github.com/charmbracelet/vhs) (and `ttyd`) plus a
monospace font such as JetBrains Mono:

```bash
./scripts/record-demo.sh
```

That script stages a throwaway directory with `mktemp -d`, installs v0.2.1 into
a temporary venv, records `docs/assets/demo.gif` from `scripts/demo.tape`, and
starts no Docker containers. It never passes credentials on the command line.

## Text alternative

The [Try it](../README.md#try-it) section shows the same `--demo` commands in
text.
