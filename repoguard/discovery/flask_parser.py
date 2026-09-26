"""D1-D3 for Flask: @app.route / shortcut decorators / add_url_rule.

AST-only. Blueprint url_prefix resolved same-file best-effort (v1).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from repoguard.discovery.django_parser import RawEndpoint
from repoguard.utils.files import iter_files

SHORTCUTS = {"get": ["GET"], "post": ["POST"], "put": ["PUT"],
             "delete": ["DELETE"], "patch": ["PATCH"], "head": ["HEAD"],
             "options": ["OPTIONS"]}


def _str(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dec_name(dec) -> tuple[str, ast.Call | None]:
    if isinstance(dec, ast.Call):
        f = dec.func
        if isinstance(f, ast.Attribute):
            return f.attr, dec
        if isinstance(f, ast.Name):
            return f.id, dec
    if isinstance(dec, ast.Attribute):
        return dec.attr, None
    if isinstance(dec, ast.Name):
        return dec.id, None
    return "", None


def _methods_from(call: ast.Call) -> list[str] | None:
    for kw in call.keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
            return [e.value.upper() for e in kw.value.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    return None


def _flask_to_path(rule: str) -> str:
    p = re.sub(r"<(?:int|str|uuid|path|float):(\w+)>", r"{\1}", rule)
    p = re.sub(r"<(\w+)>", r"{\1}", p)
    return p if p.startswith("/") else "/" + p


def parse_flask_file(path: Path) -> list[RawEndpoint]:
    out: list[RawEndpoint] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return out
    src = path.read_text(encoding="utf-8", errors="replace")
    if "Flask(" not in src and ".route(" not in src and "add_url_rule" not in src:
        return out

    prefixes: dict[str, str] = {}  # blueprint var -> url_prefix
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) \
                and getattr(node.value.func, "attr", "") == "Blueprint":
            for kw in node.value.keywords:
                if kw.arg == "url_prefix":
                    pre = _str(kw.value)
                    if pre:
                        for t in node.targets:
                            if isinstance(t, ast.Name):
                                prefixes[t.id] = pre

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                name, call = _dec_name(dec)
                if name == "route" and call and call.args:
                    rule = _str(call.args[0])
                    if rule is None:
                        continue
                    recv = call.func.value.id if isinstance(call.func, ast.Attribute) \
                        and isinstance(call.func.value, ast.Name) else ""
                    rule = prefixes.get(recv, "") + rule
                    auth = [d2 for d in node.decorator_list
                            for d2, _ in [_dec_name(d)] if d2 and d2 != "route"]
                    out.append(RawEndpoint(
                        path=_flask_to_path(rule),
                        methods=_methods_from(call) or ["GET"],
                        view=node.name, file=str(path), line=node.lineno,
                        auth=auth, source="flask-route"))
                elif name in SHORTCUTS and call:
                    rule = _str(call.args[0]) if call.args else None
                    if rule is None:
                        continue
                    auth = [d2 for d in node.decorator_list
                            for d2, _ in [_dec_name(d)] if d2 and d2 != name]
                    out.append(RawEndpoint(
                        path=_flask_to_path(rule), methods=list(SHORTCUTS[name]),
                        view=node.name, file=str(path), line=node.lineno,
                        auth=auth, source="flask-route"))
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            fname = getattr(call.func, "attr", "")
            if fname == "add_url_rule" and call.args:
                rule = _str(call.args[0])
                if rule is None:
                    continue
                view = "?"
                for kw in call.keywords:
                    if kw.arg == "view_func":
                        view = kw.value.attr if isinstance(kw.value, ast.Attribute) else (
                            kw.value.id if isinstance(kw.value, ast.Name) else "?")
                out.append(RawEndpoint(
                    path=_flask_to_path(rule), methods=_methods_from(call) or ["GET"],
                    view=view, file=str(path), line=node.lineno, source="flask-route"))
    return out


def discover_flask(target: Path) -> list[RawEndpoint]:
    out: list[RawEndpoint] = []
    for f in iter_files(target, suffix=".py"):
        out.extend(parse_flask_file(f))
    return out
