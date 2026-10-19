"""Locate a SUMO installation and its tools.

Works with the pip package (``pip install eclipse-sumo``) and with a system
install that sets ``SUMO_HOME``.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def sumo_home() -> Path:
    env = os.environ.get("SUMO_HOME")
    if env and Path(env).is_dir():
        return Path(env)
    try:
        import sumo  # pip package eclipse-sumo

        return Path(sumo.SUMO_HOME)
    except ImportError as exc:  # pragma: no cover - depends on the machine
        raise RuntimeError(
            "SUMO not found. Run 'pip install eclipse-sumo' or set SUMO_HOME."
        ) from exc


def binary(name: str) -> str:
    """Path to a SUMO binary such as 'sumo', 'netgenerate' or 'netconvert'."""
    home = sumo_home()
    exe = name + (".exe" if os.name == "nt" else "")
    candidate = home / "bin" / exe
    if candidate.exists():
        return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    raise RuntimeError(f"SUMO binary '{name}' not found under {home / 'bin'} or on PATH")


def tool(rel_path: str) -> str:
    """Path to a script under $SUMO_HOME/tools, e.g. 'randomTrips.py'."""
    path = sumo_home() / "tools" / rel_path
    if not path.exists():
        raise RuntimeError(f"SUMO tool not found: {path}")
    return str(path)


def add_tools_to_path() -> None:
    """Make sumolib importable."""
    tools = str(sumo_home() / "tools")
    if tools not in sys.path:
        sys.path.append(tools)
