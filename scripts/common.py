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


def cvss_to_bucket(score: Any) -> str | None:
    """Map a numeric CVSS / SARIF ``security-severity`` score to a bucket
    using the standard thresholds (>=9 critical, >=7 high, >=4 medium, else
    low). Returns ``None`` when ``score`` is not numeric."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    return "low"


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


# ---- License normalization ---------------------------------------------------
# Scanners report licenses inconsistently: npm usually gives SPDX ids (with a
# trailing "*" when license-checker guessed), pip-licenses gives trove
# classifier names ("GNU General Public License v3 (GPLv3)"), and SPDX itself
# has "-only"/"-or-later" variants. Everything is reduced to SPDX ids, and
# allow/deny matching compares the *base* id so that denying GPL-3.0 also
# catches GPL-3.0-only and GPL-3.0-or-later.

LICENSE_ALIASES = {
    "mit license": "MIT",
    "the mit license": "MIT",
    "mit-0": "MIT-0",
    "isc license": "ISC",
    "isc license (iscl)": "ISC",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "bsd license": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "python software foundation license": "PSF-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "the unlicense (unlicense)": "Unlicense",
    "cc0 1.0 universal (cc0 1.0) public domain dedication": "CC0-1.0",
    "public domain": "Unlicense",
    "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.0-only",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.0-or-later",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    "gnu lesser general public license v3 or later (lgplv3+)": "LGPL-3.0-or-later",
    "gnu library or lesser general public license (lgpl)": "LGPL-2.0-or-later",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "gnu affero general public license v3 or later (agplv3+)": "AGPL-3.0-or-later",
    "server side public license": "SSPL-1.0",
    "unknown": "UNKNOWN",
    "": "UNKNOWN",
}


def spdx_id(raw: Any) -> str:
    """Normalize one license name to an SPDX id (best effort)."""
    text = str(raw or "").strip().rstrip("*").strip()
    alias = LICENSE_ALIASES.get(text.lower())
    if alias:
        return alias
    if text.lower().startswith("license :: osi approved :: "):
        return spdx_id(text.split("::")[-1])
    return text


def spdx_base(license_id: str) -> str:
    """Strip version-scope suffixes: GPL-3.0-only / -or-later / + -> GPL-3.0."""
    lid = license_id.strip()
    for suffix in ("-only", "-or-later", "+"):
        if lid.endswith(suffix):
            return lid[: -len(suffix)]
    return lid


def license_alternatives(raw: Any) -> list[list[str]]:
    """Parse a license field into OR-alternatives, each a list of AND-terms.

    Accepts SPDX expressions ("(MIT OR Apache-2.0)", "GPL-2.0 WITH
    Classpath-exception-2.0"), lists (npm's legacy dual-license arrays), and
    pip-licenses' "A; B" classifier joins. Lists and ";" joins are treated as
    OR — the package is offered under any of them. Nested parentheses are
    flattened, which is conservative for the deny check.
    """
    if isinstance(raw, (list, tuple)):
        parts = [str(p) for p in raw]
    else:
        parts = str(raw if raw is not None else "").split(";")
    alternatives: list[list[str]] = []
    for part in parts:
        # Whole-name aliases first: trove classifiers contain "or" and
        # parentheses ("GNU General Public License v3 or later (GPLv3+)").
        if part.strip().rstrip("*").strip().lower() in LICENSE_ALIASES:
            alternatives.append([spdx_id(part)])
            continue
        expr = part.replace("(", " ").replace(")", " ")
        for alt in _split_word(expr, "OR"):
            terms = [
                spdx_id(_split_word(term, "WITH")[0])
                for term in _split_word(alt, "AND")
            ]
            terms = [t for t in terms if t] or ["UNKNOWN"]
            alternatives.append(terms)
    return alternatives or [["UNKNOWN"]]


def _split_word(text: str, word: str) -> list[str]:
    tokens = text.split()
    out: list[list[str]] = [[]]
    for tok in tokens:
        # SPDX operators are upper-case; matching case-insensitively would
        # split free-text names like "... or later".
        if tok == word:
            out.append([])
        else:
            out[-1].append(tok)
    return [" ".join(chunk) for chunk in out if chunk]
