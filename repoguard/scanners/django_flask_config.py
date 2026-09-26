"""S4: hand-written Django/Flask configuration checker (CFG-01..08).

Pure AST, never imports target code. One check_CFG_XX function per rule.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from repoguard.models import Finding
from repoguard.scanners.base import ScannerAdapter
from repoguard.utils.files import iter_files
from repoguard.utils.owasp import TOOL_DEFAULT_OWASP

OWASP = TOOL_DEFAULT_OWASP["config"]
DB_URI_CREDS = re.compile(r"://[^/\s:]+:[^/\s@]+@")


def _parse(path: Path):
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
        return src, ast.parse(src, filename=str(path))
    except (OSError, SyntaxError):
        return None, None


def _top_assigns(tree: ast.Module) -> dict[str, list[tuple[ast.expr, int]]]:
    out: dict[str, list[tuple[ast.expr, int]]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out.setdefault(t.id, []).append((node.value, node.lineno))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            out.setdefault(node.target.id, []).append((node.value, node.lineno))
    return out


def _line(src: str, lineno: int) -> str:
    lines = src.splitlines()
    return lines[lineno - 1].strip()[:500] if 1 <= lineno <= len(lines) else ""


def _mk(rule: str, title: str, severity: str, path: Path, lineno: int,
        evidence: str, fix: str) -> Finding:
    return Finding(
        id=rule, title=title, severity=severity, tool="config",
        where=f"{path}:{lineno}", evidence=evidence[:2000], owasp=OWASP, fix=fix,
        file=str(path), line=lineno,
    )


def check_CFG_01(assigns, src, path) -> list[Finding]:
    out = []
    for val, ln in assigns.get("DEBUG", []):
        if isinstance(val, ast.Constant) and val.value is True:
            out.append(_mk("CFG-01", "DEBUG=True in Django settings", "High", path, ln,
                           _line(src, ln), "Set DEBUG=False in production (env-gated: DEBUG = os.environ.get('DEBUG') == '1')."))
    return out


def check_CFG_02(assigns, src, path) -> list[Finding]:
    out = []
    for val, ln in assigns.get("ALLOWED_HOSTS", []):
        if isinstance(val, (ast.List, ast.Tuple, ast.Set)):
            if any(isinstance(e, ast.Constant) and e.value == "*" for e in val.elts):
                out.append(_mk("CFG-02", "ALLOWED_HOSTS allows '*' (any host)", "High", path, ln,
                               _line(src, ln), "List explicit hostnames, e.g. ALLOWED_HOSTS = ['example.com']."))
    return out


def check_CFG_03(assigns, src, path) -> list[Finding]:
    out = []
    for val, ln in assigns.get("SECRET_KEY", []):
        if isinstance(val, ast.Constant) and isinstance(val.value, str) and len(val.value) > 8:
            out.append(_mk("CFG-03", "Hardcoded Django SECRET_KEY", "High", path, ln,
                           f"SECRET_KEY = <{len(val.value)}-char literal>  (value withheld)",
                           "Load from env/secret manager (SECRET_KEY = os.environ['SECRET_KEY']); rotate the exposed value."))
    return out


def check_CFG_04(assigns, src, path) -> list[Finding]:
    out = []
    for val, ln in assigns.get("DATABASES", []):
        found = False
        for node in ast.walk(val):
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and k.value == "PASSWORD" \
                            and isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value:
                        out.append(_mk("CFG-04", "Hardcoded database PASSWORD in DATABASES", "High", path, ln,
                                       _line(src, ln), "Move DB password to env var; rotate the exposed credential."))
                        found = True
                        break
            if found:
                break
    for key in ("SQLALCHEMY_DATABASE_URI", "DATABASE_URL"):
        for val, ln in assigns.get(key, []):
            if isinstance(val, ast.Constant) and isinstance(val.value, str) \
                    and DB_URI_CREDS.search(val.value):
                out.append(_mk("CFG-04", f"Credentials embedded in {key}", "High", path, ln,
                               f"{key} = <uri with user:pass@ redacted>",
                               "Build the URI from env-var parts; rotate the exposed credential."))
    return out


def check_CFG_05(assigns, src, path) -> list[Finding]:
    out = []
    mw = assigns.get("MIDDLEWARE", assigns.get("MIDDLEWARE_CLASSES", []))
    if not mw:
        return out
    for val, ln in mw:
        if not isinstance(val, (ast.List, ast.Tuple)):
            continue
        names = {e.value for e in val.elts if isinstance(e, ast.Constant)}
        joined = " ".join(names)
        if "CsrfViewMiddleware" not in joined:
            out.append(_mk("CFG-05", "Missing CsrfViewMiddleware in MIDDLEWARE", "Medium", path, ln,
                           _line(src, ln), "Add 'django.middleware.csrf.CsrfViewMiddleware' to MIDDLEWARE."))
        if "SecurityMiddleware" not in joined:
            out.append(_mk("CFG-05", "Missing SecurityMiddleware in MIDDLEWARE", "Medium", path, ln,
                           _line(src, ln), "Add 'django.middleware.security.SecurityMiddleware' to MIDDLEWARE."))
    return out


def check_CFG_06(assigns, src, path) -> list[Finding]:
    out = []
    for key in ("SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE"):
        entries = assigns.get(key, [])
        if not entries:
            out.append(_mk("CFG-06", f"{key} not set (defaults to False)", "Low", path, 1,
                           f"{key} absent; Django default sends cookies over HTTP.",
                           f"Set {key} = True in production."))
        for val, ln in entries:
            if isinstance(val, ast.Constant) and val.value is False:
                out.append(_mk("CFG-06", f"{key} = False (cookies over HTTP)", "Medium", path, ln,
                               _line(src, ln), f"Set {key} = True in production."))
    return out


def check_CFG_07(assigns, src, path) -> list[Finding]:
    out = []
    for key in ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL"):
        for val, ln in assigns.get(key, []):
            if isinstance(val, ast.Constant) and val.value is True:
                out.append(_mk("CFG-07", f"{key} = True (CORS open to all origins)", "High", path, ln,
                               _line(src, ln), "Set CORS_ALLOWED_ORIGINS to an explicit allowlist instead."))
    return out


def check_CFG_08(tree: ast.Module, src: str, path: Path) -> list[Finding]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    out.append(_mk("CFG-08", "app.run(debug=True) enables debugger + reloader", "High",
                                   path, node.lineno, _line(src, node.lineno),
                                   "Use app.run(debug=os.environ.get('FLASK_DEBUG') == '1'); never ship debug=True."))
    return out


DJANGO_CHECKS = [check_CFG_01, check_CFG_02, check_CFG_03, check_CFG_04,
                 check_CFG_05, check_CFG_06, check_CFG_07]


def scan_file(path: Path) -> list[Finding]:
    src, tree = _parse(path)
    if src is None or tree is None:
        return []
    findings: list[Finding] = []
    assigns = _top_assigns(tree)
    is_settings = "settings" in path.name and any(
        k in assigns for k in ("DEBUG", "ALLOWED_HOSTS", "MIDDLEWARE", "SECRET_KEY", "DATABASES"))
    if is_settings:
        for check in DJANGO_CHECKS:
            findings.extend(check(assigns, src, path))
    if "app.run(" in src or "Flask(" in src:
        findings.extend(check_CFG_08(tree, src, path))
    return findings


class ConfigAdapter(ScannerAdapter):
    name = "config"

    @property
    def binary(self) -> str:
        return "builtin"

    def is_available(self) -> bool:
        return True

    def run(self, target: Path) -> tuple[list[Finding], str]:
        if not Path(target).exists():
            return [], f"error (target not found: {target})"
        try:
            findings: list[Finding] = []
            for f in iter_files(target, suffix=".py"):
                findings.extend(scan_file(f))
            return findings, f"ok ({len(findings)} findings)"
        except Exception as e:  # never raise
            return [], f"error ({e})"
