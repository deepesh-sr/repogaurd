"""Temporary debug println helper.

Convention (MILESTONES.md test-gate policy): use dprint() for all
debug output during M0-M5. T6 cleanup = delete all dprint call sites
(plus this file) and verify `grep -rn "dprint" repoguard/` is empty.

Enabled by REPOGUARD_DEBUG=1 env var or --verbose / -v CLI flag.
"""
import os
import sys

DEBUG = os.environ.get("REPOGUARD_DEBUG") == "1" or "--verbose" in sys.argv or "-v" in sys.argv


def dprint(*args):  # [DEBUG] println -- REMOVE in T6
    if DEBUG or os.environ.get("REPOGUARD_DEBUG") == "1":
        print("[DEBUG]", *args, flush=True)
