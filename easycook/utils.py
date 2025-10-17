from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Optional

OBJREF_RE = re.compile(
    r'''(?ix)
    ^
    (?:
        [A-Za-z_][A-Za-z0-9_]*
        \s*'\s*
    )?
    (?P<pkg>/Game(?:/[^.'"]+)+)    
    (?:
        \. [^'\"]+               
        \s*'?
    )?
    $
    '''
)


def normalize_asset_path(text: str) -> str:
    """Convert various inputs/obj refs to /Game/... package path."""
    text = text.strip()
    
    m = OBJREF_RE.match(text)
    if m:
        return m.group("pkg")
    if text.lower().startswith("content\\") or text.lower().startswith("content/"):
        p = Path(text.replace("\\", "/"))
        parts = list(p.parts)
        if parts and parts[0].lower() == "content":
            parts = parts[1:]
        if parts:
            parts[-1] = Path(parts[-1]).stem
        return "/Game/" + "/".join(parts)
    if text.startswith("/Game/"):
        p = Path(text)
        parts = list(p.parts)
        if parts:
            parts[-1] = Path(parts[-1]).stem
        return "/".join(parts)
    m2 = re.search(r"(/Game(?:/[^.'\"]+)+)", text)
    if m2:
        return m2.group(1)
    return text


def to_package_from_filesystem(path: Path, content_root: Optional[Path]) -> Optional[str]:
    """
    Convert a filesystem path to a /Game/... package path.
    """
    path = path.resolve()
    if content_root and content_root in path.parents:
        rel = path.relative_to(content_root)
        return "/Game/" + "/".join(rel.with_suffix("").parts)
    parts = [p for p in path.parts]
    if "Content" in parts:
        idx = parts.index("Content")
        rel = Path(*parts[idx + 1 :])
        return "/Game/" + "/".join(rel.with_suffix("").parts)
    return None


def scan_folder_to_packages(folder: Path, content_root: Optional[Path]) -> list[str]:
    pkgs: list[str] = []
    for p in folder.rglob("*.uasset"):
        pkg = to_package_from_filesystem(p, content_root)
        if pkg:
            pkgs.append(pkg)
    return pkgs


def folder_to_game_path(folder: Path, content_root: Optional[Path]) -> Optional[str]:
    """Convert a folder on disk to a /Game/... folder path for display.
    """
    try:
        folder = folder.resolve()
    except Exception:
        folder = Path(folder)

    if content_root:
        try:
            content_root = content_root.resolve()
        except Exception:
            pass
        if folder == content_root:
            return "/Game"
        if content_root in folder.parents:
            rel = folder.relative_to(content_root)
            if not rel.parts:
                return "/Game"
            return "/Game/" + "/".join(rel.parts)

    parts = list(folder.parts)
    if "Content" in parts:
        idx = parts.index("Content")
        after = parts[idx + 1 :]
        if not after:
            return "/Game"
        return "/Game/" + "/".join(after)

    return None


def resource_path(relative_path: str) -> str:
    """Resolve resource path"""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
        if not os.path.exists(os.path.join(base_path, relative_path)):
            resources_dir = os.path.join(base_path, "resources")
            if os.path.exists(os.path.join(resources_dir, relative_path)):
                return os.path.join(resources_dir, relative_path)
    return os.path.join(base_path, relative_path)
