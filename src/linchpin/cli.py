"""Command-line interface: ``linchpin identity`` and ``linchpin signals``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from . import __version__
from .demo import DEMO_NOW, generate
from .loader import LoadError, load_dir
from .models import parse_ts
from .output import RENDERERS
from .rules import identity_findings, signal_findings


def _int_min(minimum: int) -> Callable[[str], int]:
    """argparse type: integer >= minimum (argparse equivalent of click.IntRange)."""

    def parse(value: str) -> int:
        try:
            n = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from None
        if n < minimum:
            raise argparse.ArgumentTypeError(f"must be >= {minimum}, got {n}")
        return n

    return parse


def _common(p: argparse.ArgumentParser) -> None:
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--demo", action="store_true", help="use seeded fake demo data")
    src.add_argument("--data", metavar="DIR", help="directory of JSON exports")
    p.add_argument("--seed", type=int, default=42, help="demo RNG seed (default 42)")
    p.add_argument("--users", type=int, default=30, help="demo user count (default 30)")
    p.add_argument("--now", help="reference time ISO-8601 (default: demo epoch or current UTC)")
    p.add_argument("--format", choices=sorted(RENDERERS), default="table")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="linchpin", description=__doc__)
    parser.add_argument("--version", action="version", version=f"linchpin {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    ident = sub.add_parser("identity", help="identity hygiene flags")
    _common(ident)
    ident.add_argument("--stale-days", type=_int_min(1), default=90)
    sig = sub.add_parser("signals", help="insider-risk signals")
    _common(sig)
    sig.add_argument("--mass-threshold", type=_int_min(1), default=10)
    sig.add_argument("--leaver-window-days", type=_int_min(0), default=30)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.demo and not 7 <= args.users <= 300:
        parser.error("--users must be between 7 and 300 (demo scenarios need >= 7)")
    try:
        now = parse_ts(args.now) if args.now else None
    except ValueError:
        parser.error(f"invalid --now timestamp: {args.now!r}")
    try:
        if args.demo:
            now = now or DEMO_NOW
            data = generate(seed=args.seed, users=args.users, now=now)
        else:
            now = now or datetime.now(timezone.utc)
            data = load_dir(args.data)
    except LoadError as exc:
        print(f"linchpin: error: {exc}", file=sys.stderr)
        return 2

    if args.command == "identity":
        findings = identity_findings(data, now, stale_days=args.stale_days)
    else:
        findings = signal_findings(
            data,
            now,
            mass_threshold=args.mass_threshold,
            leaver_window_days=args.leaver_window_days,
        )
    print(RENDERERS[args.format](findings))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
