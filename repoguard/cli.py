"""CLI: python -m repoguard scan <path> [options].

Full flag set frozen per PLAN.md section 2. M0 implements parsing +
dispatch; scanners/discovery/live attach in M1-M3.
"""
from __future__ import annotations

import argparse
import sys

from repoguard.runner import EXIT_ERROR, run_scan
from repoguard.utils.debug import dprint


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="repoguard", description="Repository VAPT tool")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a repository checkout")
    s.add_argument("path", help="Path to the repo root being tested")
    s.add_argument("--url", default=None, help="Base URL of the running app (enables live + API tests)")
    s.add_argument("--token", default=None, help="Valid auth token for protected endpoints")
    s.add_argument("--token2", default=None, help="Second user token (enables IDOR bonus test)")
    s.add_argument("--output", default=None, help="Output dir (default: <path>/repoguard-report/)")
    s.add_argument(
        "--fail-on",
        default="critical",
        choices=["critical", "high", "medium", "low", "never"],
        help="Exit 2 if findings at/above this severity exist (default: critical)",
    )
    s.add_argument("--timeout", type=int, default=10, help="Per-request timeout secs (default: 10)")
    s.add_argument("-v", "--verbose", action="store_true", help="Enable [DEBUG] println output")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    dprint("cli.main command=", args.command, "path=", args.path, "url=", args.url)  # [DEBUG] REMOVE in T6
    if args.command == "scan":
        if args.verbose:
            import os

            os.environ["REPOGUARD_DEBUG"] = "1"
        try:
            return run_scan(args)
        except FileNotFoundError as e:
            print(f"repoguard: error: {e}", file=sys.stderr)
            return EXIT_ERROR
        except ValueError as e:
            print(f"repoguard: error: {e}", file=sys.stderr)
            return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
