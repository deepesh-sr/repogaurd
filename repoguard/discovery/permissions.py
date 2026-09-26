"""Auth/permission classifier shared by Django + Flask parsers.

One finding per endpoint max: explicit-open beats allowany-default.
"""
from __future__ import annotations

import ast
from pathlib import Path

from repoguard.utils.files import iter_files

# Decorators that prove a view requires authentication.
AUTH_DECORATORS = {
    "login_required",
    "permission_classes",
    "authentication_classes",
    "jwt_required",
    "token_required",
    "auth_required",
    "roles_required",
    "roles_accepted",
}

# DRF permission class names that count as protection.
PROTECTED_PERMISSIONS = {
    "IsAuthenticated",
    "IsAdminUser",
    "IsAuthenticatedOrReadOnly",
    "DjangoModelPermissions",
    "DjangoModelPermissionsOrAnonReadOnly",
    "DjangoObjectPermissions",
    "TokenHasReadWriteScope",
}

# Permission names that mean explicitly open.
OPEN_PERMISSIONS = {"AllowAny"}


def _short(name: str) -> str:
    return name.split(".")[-1]


def names_protect(auth: list[str], permissions: list[str]) -> bool:
    """True if any auth decorator or a protective permission class is present."""
    if any(a in AUTH_DECORATORS or _short(a) in PROTECTED_PERMISSIONS for a in auth):
        return True
    shorts = {_short(p) for p in permissions}
    if shorts & PROTECTED_PERMISSIONS:
        return True
    # Any non-AllowAny permission class is some form of gate.
    if shorts and not (shorts <= OPEN_PERMISSIONS):
        return True
    return False


def names_open(auth: list[str], permissions: list[str]) -> bool:
    """True if explicitly AllowAny and nothing protective."""
    if any(a in AUTH_DECORATORS for a in auth):
        return False
    shorts = {_short(a) for a in auth} | {_short(p) for p in permissions}
    return bool(shorts) and shorts <= OPEN_PERMISSIONS


def classify(auth: list[str], permissions: list[str],
             global_default: str | None, is_class: bool = False) -> str:
    """Return protected | open | allowany-default | unknown.

    Class-based (DRF) views with no explicit classes inherit the global
    default; plain function views never do (DRF defaults don't apply).
    """
    if names_protect(auth, permissions):
        return "protected"
    if names_open(auth, permissions):
        return "open"
    if not auth and not permissions:
        if global_default == "AllowAny":
            return "allowany-default"
        if global_default and is_class:
            return "protected"  # inherits a strict global default
        return "open"
    return "unknown"


def parse_drf_default(target: Path) -> str | None:
    """Read DRF DEFAULT_PERMISSION_CLASSES from settings files.

    Returns 'AllowAny' if any default is AllowAny, else the first class
    short name, else None when no settings declare it.
    """
    found: list[str] = []
    for f in iter_files(target, suffix=".py"):
        if "settings" not in f.name:
            continue
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "REST_FRAMEWORK" for t in node.targets):
                blob = ast.dump(node.value)
                if "AllowAny" in blob:
                    return "AllowAny"
                for cls in sorted(PROTECTED_PERMISSIONS):
                    if cls in blob:
                        found.append(cls)
    if found:
        return found[0]
    return None
