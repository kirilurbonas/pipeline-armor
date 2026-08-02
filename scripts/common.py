"""Shared helpers for the pipeline-armor parser scripts.

Every parser previously carried its own copy of the severity table, the
Markdown-cell escaper, and the tolerant JSON loader; the copies had already
started to drift (``load_json`` returned ``{}``, ``None``, or ``[]``
depending on the script). This module is the single source of truth.

The scripts are invoked as ``python3 scripts/<name>.py``, which puts this
directory on ``sys.path``, so a plain ``import common`` works both on CI
runners (via the ``.pipeline-armor`` self-checkout, which ships the whole
``scripts/`` directory) and locally. Tests load it via ``tests/conftest.py``,
which inserts the scripts directory into ``sys.path``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Canonical lower-case severity ranking shared by every gate in the library.
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITIES = ("critical", "high", "medium", "low")

# Trivy convention (uppercase). Kept as a distinct constant so scripts that
# talk to Trivy don't silently depend on casing tricks.
SEVERITY_ORDER_UPPER = {k.upper(): v for k, v in SEVERITY_ORDER.items()}


def md_cell(value: Any) -> str:
    """Neutralise a value for safe rendering inside a Markdown table cell.

    Scanners surface attacker-influenced strings (package names, CVE titles,
    resource paths). A stray ``|`` or newline silently corrupts the table and
    a backtick breaks the inline-code span values are wrapped in.
    """
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "'")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def md_link_url(url: str) -> str:
    """Escape a URL so it can't break out of a Markdown ``[text](url)`` span."""
    return str(url).replace(" ", "%20").replace("(", "%28").replace(")", "%29")


def load_json(path: str | Path, default: Any = None) -> Any:
    """Read JSON tolerantly: missing, empty, or malformed input yields
    ``default`` instead of raising, so a failed scanner can never crash the
    reporting step. Pass the default each call site expects (``{}``, ``[]``,
    or ``None``)."""
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return default
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return default
