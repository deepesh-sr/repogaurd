"""D1-D3 for Django/DRF: urls.py + routers -> (path, methods, view, auth).

AST-only, never imports target code. include() recursion depth <=3.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from repoguard.utils.files import iter_files

URL_FUNCS = {"path", "re_path", "url"}
ROUTER_TYPES = {"DefaultRouter", "SimpleRouter"}

# router.register() expands to the standard ViewSet routes.
ROUTER_ROUTES = [
    ("", ["GET", "POST"], "list/create"),
    ("/{id}", ["GET", "PUT", "PATCH", "DELETE"], "retrieve/update/destroy"),
]


@dataclass
class RawEndpoint:
    path: str
    methods: list[str]
    view: str
    file: str
    line: int
    auth: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    source: str = "django-urls"
    is_class: bool = False  # CBV/ViewSet: inherits DRF global default
    methods_known: bool = True  # False -> inferred, M3 may still probe


def _str(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _call_name(func) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _keywords(call: ast.Call) -> dict:
    out = {}
    for kw in call.keywords:
        out[kw.arg or ""] = kw.value
    return out


def _methods_from(kw: dict) -> list[str] | None:
    m = kw.get("methods")
    if m is None:
        return None
    if isinstance(m, (ast.List, ast.Tuple, ast.Set)):
        return [e.value.upper() for e in m.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    return None


def _import_map(tree: ast.Module) -> dict[str, str]:
    """Map imported view names to their source module: {PublicNotes: views}."""
    out: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            mod = node.module.split(".")[-1]
            for a in node.names:
                out[a.asname or a.name] = mod
        elif isinstance(node, ast.Import):
            for a in node.names:
                top = (a.asname or a.name).split(".")[0]
                out[top] = a.name.split(".")[-1]
    return out


def _view_ref(node) -> str:
    """'views.HomeView.as_view()' -> 'views.HomeView'; 'views.home' -> 'views.home'."""
    src = ast.unparse(node) if hasattr(ast, "unparse") else ""
    src = re.sub(r"\.as_view\(.*\)$", "", src)
    return src or "?"


def _route_to_path(route: str) -> str:
    """Django converters -> {id} placeholders; ensure leading slash."""
    p = re.sub(r"<(?:int|str|slug|uuid|path):(\w+)>", r"{\1}", route)
    p = re.sub(r"<(\w+)>", r"{\1}", p)
    # re_path regex: strip ^$ and crude named groups
    p = re.sub(r"\(\?P<(\w+)>[^)]+\)", r"{\1}", p)
    p = p.replace("^", "").replace("$", "")
    if not p.startswith("/"):
        p = "/" + p
    return p or "/"


def _join(prefix: str, route: str) -> str:
    return (prefix.rstrip("/") + "/" + route.lstrip("/")).replace("//", "/") or "/"


class _ViewIndex:
    """Class/function auth info per views file: name -> (auth, permissions, actions)."""

    def __init__(self) -> None:
        self.classes: dict[str, tuple[list[str], list[str]]] = {}
        self.handlers: dict[str, list[str]] = {}  # class -> HTTP verbs it implements
        self.funcs: dict[str, list[str]] = {}
        self.actions: dict[str, dict[str, tuple[list[str], list[str], list[str]]]] = {}

    @staticmethod
    def _class_lists(cls: ast.ClassDef) -> tuple[list[str], list[str]]:
        auth: list[str] = []
        perms: list[str] = []
        for dec in cls.decorator_list:
            name = _call_name(dec.func) if isinstance(dec, ast.Call) else _call_name(dec)
            if name:
                auth.append(name)
        for node in cls.body:
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id in ("authentication_classes", "permission_classes"):
                        vals = [ast.unparse(e) if hasattr(ast, "unparse") else "?"
                                for e in (node.value.elts if isinstance(node.value, (ast.List, ast.Tuple)) else [])]
                        if t.id == "authentication_classes":
                            auth.extend(vals)
                        else:
                            perms.extend(vals)
        return auth, perms

    def add_tree(self, tree: ast.Module) -> None:
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                auth, perms = self._class_lists(node)
                self.classes[node.name] = (auth, perms)
                self.handlers[node.name] = [
                    m for m in ("get", "post", "put", "patch", "delete", "head", "options")
                    if any(isinstance(i, ast.FunctionDef) and i.name == m for i in node.body)]
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        for dec in item.decorator_list:
                            if isinstance(dec, ast.Call) and _call_name(dec.func) == "action":
                                kw = _keywords(dec)
                                methods = _methods_from(kw) or ["GET"]
                                a_auth = [ast.unparse(e) for e in kw.get("permission_classes", ast.List(elts=[])).elts] \
                                    if hasattr(ast, "unparse") else []
                                self.actions.setdefault(node.name, {})[item.name] = (methods, [], a_auth)
            elif isinstance(node, ast.FunctionDef):
                decs = []
                for dec in node.decorator_list:
                    name = _call_name(dec.func) if isinstance(dec, ast.Call) else _call_name(dec)
                    if name:
                        decs.append(name)
                self.funcs[node.name] = decs


def _load_views(sibling: Path, view_module: str) -> _ViewIndex:
    """Resolve 'views'/'api.views'/'.views' to a file next to the urls file."""
    idx = _ViewIndex()
    base = view_module.split(".")[0].lstrip(".") or "views"
    if base in ("", "urls"):
        return idx
    for cand in (sibling.parent / f"{base}.py", sibling.parent / base / "views.py"):
        if cand.is_file():
            try:
                idx.add_tree(ast.parse(cand.read_text(encoding="utf-8", errors="replace")))
            except (OSError, SyntaxError):
                pass
    return idx


def _auth_for(idx: _ViewIndex, view_ref: str) -> tuple[list[str], list[str], bool, list[str]]:
    """Return (auth, permissions, is_class, handler_methods)."""
    leaf = view_ref.split(".")[-1].split(":")[-1]
    if leaf in idx.classes:
        auth, perms = idx.classes[leaf]
        return auth, perms, True, [m.upper() for m in idx.handlers.get(leaf, [])]
    if leaf in idx.funcs:
        return idx.funcs[leaf], [], False, []
    return [], [], False, []


def parse_urls_file(path: Path, prefix: str = "",
                    _depth: int = 0, _seen: set | None = None) -> list[RawEndpoint]:
    out: list[RawEndpoint] = []
    seen = _seen if _seen is not None else set()
    if _depth > 3 or str(path) in seen:
        return out
    seen.add(str(path))
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return out

    # Collect router registrations first (need ViewSet auth from views index).
    routers: list[tuple[str, str, int]] = []  # (prefix, viewset, lineno)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) == "register" and node.args:
            pre = _str(node.args[0])
            vs = _call_name(node.args[1]) if len(node.args) > 1 else "?"
            if pre is not None:
                routers.append((pre.strip("/"), vs, node.lineno))

    view_mods: set[str] = set()  # reserved for cross-module view resolution (M5+)
    urlpatterns = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "urlpatterns" for t in node.targets):
            urlpatterns = node.value
    if urlpatterns is None:
        return out

    imap = _import_map(tree)

    def qualify(ref: str) -> str:
        """'PublicNotes' -> 'views.PublicNotes' via from-imports; dotted refs unchanged."""
        if "." not in ref and ref in imap:
            return f"{imap[ref]}.{ref}"
        return ref

    def view_module_of(call: ast.Call) -> str:
        if call.args and len(call.args) >= 2:
            v = call.args[1]
            if isinstance(v, ast.Call):
                if isinstance(v.func, ast.Name) and v.func.id == "include":
                    return ""  # include() handled by recursion
                if isinstance(v.func, ast.Attribute) and v.func.attr == "as_view":
                    # views.X.as_view() (or bare X.as_view() via from-import)
                    return qualify(_view_ref(v)).split(".")[0]
                return ""
            ref = qualify(_view_ref(v))
            return ref.split(".")[0]
        kw = _keywords(call)
        if "view" in kw:
            return qualify(_view_ref(kw["view"])).split(".")[0]
        return ""

    # Preload the most common views module for auth lookup.
    mods = set()
    for node in ast.walk(urlpatterns):
        if isinstance(node, ast.Call) and _call_name(node.func) in URL_FUNCS:
            m = view_module_of(node)
            if m:
                mods.add(m)
    idx = _ViewIndex()
    idx.add_tree(tree)  # locally-defined views / ViewSets / @actions
    for m in mods:
        sub = _load_views(path, m)
        idx.classes.update(sub.classes)
        idx.handlers.update(sub.handlers)
        idx.funcs.update(sub.funcs)
        for k, v in sub.actions.items():
            idx.actions.setdefault(k, {}).update(v)

    for node in ast.walk(urlpatterns):
        if not (isinstance(node, ast.Call) and _call_name(node.func) in URL_FUNCS):
            continue
        if not node.args:
            continue
        route = _str(node.args[0])
        kw = _keywords(node)
        # include() -> recurse into sibling urls module
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Call) \
                and _call_name(node.args[1].func) == "include":
            inc = node.args[1]
            mod = _str(inc.args[0]) if inc.args else None
            if mod and route is not None:
                sub = path.parent / mod.replace(".", "/")
                cands = [sub.with_suffix(".py"), sub / "urls.py"]
                base = _route_to_path(route)
                for c in cands:
                    if c.is_file():
                        out.extend(parse_urls_file(c, _join(prefix, base), _depth + 1, seen))
                        break
            continue
        if route is None:
            out.append(RawEndpoint(path=_join(prefix, "/?"), methods=["GET"],
                                   view="?", file=str(path), line=node.lineno,
                                   source="django-urls"))
            continue
        full = _route_to_path(_join(prefix, route))
        view = qualify(_view_ref(node.args[1])) if len(node.args) >= 2 else qualify(
            _view_ref(kw.get("view", ast.Constant(value="?"))))
        methods = _methods_from(kw)
        auth, perms, is_class, handlers = _auth_for(idx, view)
        if methods is None:
            # CBV: infer from implemented handlers; FBV/unknown: GET default.
            methods = handlers or ["GET"]
        # CBV as_view(methods...) rare; default: GET (+POST if form-ish unknown -> GET only)
        out.append(RawEndpoint(path=full, methods=methods, view=view,
                               file=str(path), line=node.lineno,
                               auth=auth, permissions=perms, source="django-urls",
                               is_class=is_class))

    # Router expansion (auth from ViewSet class; Q2: unknown if unresolvable).
    for pre, vs, ln in routers:
        auth, perms, _, _ = _auth_for(idx, vs)
        is_vs_class = vs in idx.classes
        for suffix, methods, _kind in ROUTER_ROUTES:
            out.append(RawEndpoint(path=f"/{pre}{suffix}".replace("//", "/") or "/", methods=methods,
                                   view=vs, file=str(path), line=ln,
                                   auth=list(auth), permissions=list(perms),
                                   source="drf-router", is_class=is_vs_class))
        for act, (methods, a_auth, a_perms) in idx.actions.get(vs, {}).items():
            out.append(RawEndpoint(path=f"/{pre}/{{id}}/{act}/", methods=methods,
                                   view=f"{vs}.{act}", file=str(path), line=ln,
                                   auth=auth + a_auth, permissions=perms + a_perms,
                                   source="drf-router"))
    return out


def discover_django(target: Path) -> list[RawEndpoint]:
    out: list[RawEndpoint] = []
    for f in iter_files(target, suffix=".py"):
        if f.name != "urls.py":
            continue
        # Top-level call only; included files are reached via recursion.
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError):
            continue
        if any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "urlpatterns" for t in n.targets)
               for n in tree.body):
            # Skip files that are only include targets if a parent already covers them?
            # Simpler: parse all; dedupe happens in inventory.
            out.extend(parse_urls_file(f))
    return out
