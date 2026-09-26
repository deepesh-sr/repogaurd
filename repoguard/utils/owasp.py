"""Single (tool, rule) -> OWASP Top-10:2021 mapping table.

Unknown rules map to A00, never blank.
"""
from __future__ import annotations

FALLBACK = "A00:2021 — Uncategorized"

# Bandit test-ID -> OWASP (spot-checked against bandit docs).
BANDIT_OWASP: dict[str, str] = {
    "B301": "A08:2021 — Software and Data Integrity Failures",  # pickle
    "B302": "A08:2021 — Software and Data Integrity Failures",  # marshal
    "B303": "A02:2021 — Cryptographic Failures",  # md5/sha1
    "B304": "A02:2021 — Cryptographic Failures",  # insecure cipher
    "B305": "A02:2021 — Cryptographic Failures",
    "B306": "A02:2021 — Cryptographic Failures",  # mktemp
    "B307": "A03:2021 — Injection",  # eval
    "B308": "A08:2021 — Software and Data Integrity Failures",  # mark_safe
    "B310": "A03:2021 — Injection",  # urllib urlopen
    "B311": "A02:2021 — Cryptographic Failures",  # random
    "B312": "A03:2021 — Injection",  # telnetlib
    "B313": "A03:2021 — Injection",  # xml
    "B314": "A03:2021 — Injection",  # xml attacker
    "B315": "A03:2021 — Injection",
    "B316": "A03:2021 — Injection",
    "B317": "A03:2021 — Injection",
    "B318": "A03:2021 — Injection",
    "B319": "A03:2021 — Injection",  # xml
    "B320": "A03:2021 — Injection",  # xml expat
    "B321": "A08:2021 — Software and Data Integrity Failures",  # ftplib
    "B323": "A03:2021 — Injection",  # unmarshalled input
    "B324": "A02:2021 — Cryptographic Failures",  # weak hash
    "B325": "A03:2021 — Injection",  # tempnam
    "B402": "A03:2021 — Injection",  # import pickle
    "B403": "A03:2021 — Injection",  # import pickle
    "B404": "A03:2021 — Injection",  # import subprocess
    "B405": "A03:2021 — Injection",  # import xml
    "B406": "A03:2021 — Injection",  # import xml sax
    "B407": "A03:2021 — Injection",  # import xml etree
    "B408": "A03:2021 — Injection",  # import xml minidom
    "B409": "A03:2021 — Injection",  # import xml pulldom
    "B410": "A03:2021 — Injection",  # import lxml
    "B411": "A03:2021 — Injection",  # import xmlrpclib
    "B412": "A03:2021 — Injection",  # import httpoxy
    "B413": "A03:2021 — Injection",  # import pycrypto
    "B414": "A03:2021 — Injection",  # import pycryptodome
    "B501": "A05:2021 — Security Misconfiguration",  # request with verify=False
    "B502": "A05:2021 — Security Misconfiguration",  # ssl insecure version
    "B503": "A05:2021 — Security Misconfiguration",  # ssl no version
    "B504": "A05:2021 — Security Misconfiguration",  # ssl unverified context
    "B505": "A02:2021 — Cryptographic Failures",  # weak cipher
    "B506": "A03:2021 — Injection",  # yaml load
    "B507": "A05:2021 — Security Misconfiguration",  # ssh no host key verification
    "B508": "A03:2021 — Injection",  # snmp
    "B509": "A03:2021 — Injection",  # snmp
    "B601": "A03:2021 — Injection",  # paramiko calls
    "B602": "A03:2021 — Injection",  # subprocess_popen_with_shell_equals_true
    "B603": "A03:2021 — Injection",  # subprocess without shell equals true
    "B604": "A03:2021 — Injection",  # any_other_function_with_shell_equals_true
    "B605": "A03:2021 — Injection",  # start_process_with_a_shell
    "B606": "A03:2021 — Injection",  # start_process_with_no_shell
    "B607": "A03:2021 — Injection",  # start_process_with_a_partial_path
    "B608": "A03:2021 — Injection",  # hardcoded_sql_expressions
    "B609": "A03:2021 — Injection",  # linux commands wildcard injection
    "B610": "A03:2021 — Injection",  # django_extra_used
    "B611": "A03:2021 — Injection",  # django_rawsql_used
    "B612": "A03:2021 — Injection",  # logging format injection
    "B701": "A01:2021 — Broken Access Control",  # jinja2 autoescape false
    "B702": "A03:2021 — Injection",  # use of mako templates
    "B703": "A04:2021 — Insecure Design",  # django mark_safe
    "B704": "A04:2021 — Insecure Design",  # django raw sql
    "B105": "A07:2021 — Identification and Authentication Failures",  # hardcoded_password_string
    "B106": "A07:2021 — Identification and Authentication Failures",  # hardcoded_password_funcarg
    "B107": "A07:2021 — Identification and Authentication Failures",  # hardcoded_password_default
    "B108": "A05:2021 — Security Misconfiguration",  # hardcoded_tmp_directory
}

TOOL_DEFAULT_OWASP: dict[str, str] = {
    "pip-audit": "A06:2021 — Vulnerable and Outdated Components",
    "bandit": "A03:2021 — Injection",
    "semgrep": "A03:2021 — Injection",
    "gitleaks": "A07:2021 — Identification and Authentication Failures",
    "config": "A05:2021 — Security Misconfiguration",
    "hygiene": "A05:2021 — Security Misconfiguration",
    "discovery": "A01:2021 — Broken Access Control",
    "live": "A05:2021 — Security Misconfiguration",
    "api": "A01:2021 — Broken Access Control",
}


def bandit_owasp(test_id: str) -> str:
    return BANDIT_OWASP.get(test_id.upper(), TOOL_DEFAULT_OWASP["bandit"])


def semgrep_owasp(metadata: dict) -> str:
    """Prefer rule metadata.owasp, then CWE_wrap to a category, else default."""
    if not isinstance(metadata, dict):
        return TOOL_DEFAULT_OWASP["semgrep"]
    owasp = metadata.get("owasp")
    if isinstance(owasp, str) and owasp.strip():
        return owasp.strip()
    if isinstance(owasp, list) and owasp:
        return str(owasp[0])
    cwe = str(metadata.get("cwe", "") or "")
    if "CWE-798" in cwe or "CWE-259" in cwe:
        return "A07:2021 — Identification and Authentication Failures"
    if "CWE-327" in cwe or "CWE-328" in cwe or "CWE-916" in cwe:
        return "A02:2021 — Cryptographic Failures"
    if "CWE-918" in cwe:
        return "A10:2021 — Server-Side Request Forgery (SSRF)"
    if "CWE-22" in cwe:
        return "A01:2021 — Broken Access Control"
    if "CWE-94" in cwe or "CWE-95" in cwe or "CWE-78" in cwe or "CWE-89" in cwe:
        return "A03:2021 — Injection"
    return TOOL_DEFAULT_OWASP["semgrep"]


def cvss_to_severity(score: float | None) -> str:
    """CVSS -> severity bands (ARCHITECTURE section 3, locked in M1a)."""
    if score is None:
        return "High"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"
