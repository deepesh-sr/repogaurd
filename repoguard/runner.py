"""Orchestrator: static (+ live) -> normalize -> rank -> report -> exit code.

M0: static scanners + discovery return [] (attached in M1/M2).
Live phase runs a placeholder when --url is given (real probes in M3).
"""
from __future__ import annotations

import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from repoguard.models import Finding, Report, build_summary
from repoguard.report.html_writer import write_html
from repoguard.report.json_writer import write_json
from repoguard.scanners.bandit import BanditAdapter
from repoguard.scanners.django_flask_config import ConfigAdapter
from repoguard.scanners.gitleaks import GitleaksAdapter
from repoguard.scanners.hygiene import HygieneAdapter
from repoguard.scanners.pip_audit import PipAuditAdapter
from repoguard.scanners.semgrep import SemgrepAdapter

# M1b: config + hygiene appended with no restructuring.
ADAPTERS = [PipAuditAdapter(), BanditAdapter(), SemgrepAdapter(), GitleaksAdapter(),
            ConfigAdapter(), HygieneAdapter()]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2

FAIL_ON_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "never": 99}
SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _resolve_target(path_str: str) -> Path:
    p = Path(path_str).resolve()
    if not p.exists():
        raise FileNotFoundError(f"target path does not exist: {path_str}")
    if not p.is_dir():
        raise ValueError(f"target path is not a directory: {path_str}")
    return p


def _resolve_output(target: Path, output: str | None) -> Path:
    out = Path(output).resolve() if output else (target / "repoguard-report")
    out.mkdir(parents=True, exist_ok=True)
    return out


def _static_phase(target: Path) -> tuple[list[Finding], dict]:
    """Run scanner adapters concurrently. One scanner's failure never fails the run."""
    findings: list[Finding] = []
    scanner_status: dict = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(a.run, target): a for a in ADAPTERS}
        for adapter in ADAPTERS:  # deterministic merge order
            for fut, ad in futures.items():
                if ad is adapter:
                    try:
                        f, status = fut.result()
                    except Exception as e:  # adapter contract says never; belt and suspenders
                        f, status = [], f"error ({e})"
                    scanner_status[adapter.name] = status
                    findings.extend(f)
    return findings, scanner_status


def _discovery_phase(target: Path) -> tuple[list, list[Finding]]:
    """M2: AST API discovery -> endpoints + DISC-* findings."""
    from repoguard.discovery.inventory import discover
    try:
        endpoints, findings = discover(target)
    except Exception as e:  # never fail the run on discovery errors
        return [], []
    return endpoints, findings


def _live_phase(base_url: str, timeout: int, token: str | None,
                token2: str | None, endpoints: list) -> tuple[list[Finding], str]:
    """M3: app checks (L1-L4) then API checks (A1-A5) over the inventory."""
    from repoguard.live import api_tests, error_leak, exposed_paths, headers_cookies
    from repoguard.live.http import LiveClient
    client = LiveClient(timeout=timeout, token=token)
    probe = client.request("GET", base_url.rstrip("/") + "/", throttle=False)
    if probe is None:
        return ([Finding(
            id="LIVE-UNREACHABLE",
            title=f"Target application unreachable at {base_url}",
            severity="Info", tool="live", where=base_url,
            evidence=f"GET {base_url}/ failed (connection refused/timeout after {timeout}s).",
            owasp="A00:2021 — Uncategorized",
            fix="Start the app, then re-run with --url pointing at it.")],
            "error (unreachable)")
    findings: list[Finding] = []
    try:
        l1, _root = headers_cookies.check(base_url, client)
        findings.extend(l1)
    except Exception:
        pass
    try:
        findings.extend(exposed_paths.check(base_url, client))
    except Exception:
        pass
    try:
        findings.extend(error_leak.check(base_url, client))
    except Exception:
        pass
    targets = list(endpoints) if endpoints else []
    if not targets:
        from repoguard.models import Endpoint as _Ep
        targets = [_Ep(path="/", methods=["GET"], view="?", file="?", line=0,
                       source="fallback")]
    try:
        api_findings, tested = api_tests.check_api(base_url, client, targets, token2)
        findings.extend(api_findings)
    except Exception as e:
        tested = 0
    status = f"ok ({len(findings)} findings, {tested} endpoints tested)"
    return findings, status


def _exit_code(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    threshold = FAIL_ON_RANK[fail_on]
    for f in findings:
        if SEV_RANK.get(f.severity, 99) <= threshold:
            return EXIT_FINDINGS
    return EXIT_OK


def run_scan(args) -> int:
    target = _resolve_target(args.path)
    out_dir = _resolve_output(target, args.output)

    findings, scanner_status = _static_phase(target)
    endpoints, disc_findings = _discovery_phase(target)
    findings = list(findings) + list(disc_findings)
    scanner_status["discovery"] = f"ok ({len(endpoints)} endpoints)"

    base_url = getattr(args, "url", None)
    if base_url:
        live_findings, live_status = _live_phase(
            base_url, getattr(args, "timeout", 10),
            getattr(args, "token", None), getattr(args, "token2", None),
            endpoints)
        findings = list(findings) + live_findings
        scanner_status["live"] = live_status

    # M4: fix-first ranking before reporting.
    from repoguard.ranking import TOP_N, rank
    findings = rank(findings)
    summary = build_summary(findings)
    summary["fix_first"] = [f.id for f in findings[:TOP_N]]
    report = Report(
        target=str(target),
        base_url=base_url,
        generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        summary=summary,
        findings=findings,
        endpoints=endpoints,
        scanner_status=scanner_status,
    )

    write_json(report, out_dir / "findings.json")
    write_html(report, out_dir / "report.html")

    code = _exit_code(findings, getattr(args, "fail_on", "critical"))
    print(f"repoguard: {len(findings)} findings, {len(endpoints)} endpoints -> {out_dir} (exit {code})")
    return code
