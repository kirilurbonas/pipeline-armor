#!/usr/bin/env python3
"""Check pinned scanner-CLI versions against the latest upstream releases.

Dependabot keeps the SHA-pinned *actions* current but cannot see the CLI
tools these workflows download with curl/pip (Gitleaks, Trufflehog, Trivy,
Snyk, OSV-Scanner, Semgrep, Checkov). This script extracts those pins from
the workflow YAML, queries the upstream release source (GitHub releases or
PyPI), and renders a Markdown report; the tool-currency workflow turns a
stale report into a tracking issue.

Network access is isolated in ``fetch_latest`` so the extraction and
comparison logic stays unit-testable offline.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

# (tool, workflow file, regex with one version group, source kind, source ref)
TOOLS: list[tuple[str, str, str, str, str]] = [
    (
        "gitleaks",
        "reusable-secret-scan.yml",
        r"GITLEAKS_VERSION: '([\d.]+)'",
        "github",
        "gitleaks/gitleaks",
    ),
    (
        "trufflehog",
        "reusable-secret-scan.yml",
        r"TRUFFLEHOG_VERSION: '([\d.]+)'",
        "github",
        "trufflesecurity/trufflehog",
    ),
    (
        "trivy",
        "reusable-container-scan.yml",
        r"TRIVY_VERSION: '([\d.]+)'",
        "github",
        "aquasecurity/trivy",
    ),
    (
        "snyk",
        "reusable-sast.yml",
        r"SNYK_VERSION: 'v([\d.]+)'",
        "github",
        "snyk/cli",
    ),
    (
        "osv-scanner",
        "reusable-osv-scan.yml",
        r"OSV_SCANNER_VERSION: '([\d.]+)'",
        "github",
        "google/osv-scanner",
    ),
    (
        "semgrep",
        "reusable-sast.yml",
        r"semgrep==([\d.]+)",
        "pypi",
        "semgrep",
    ),
    (
        "checkov",
        "reusable-iac-scan.yml",
        r"checkov==([\d.]+)",
        "pypi",
        "checkov",
    ),
]


def extract_pinned(workflows_dir: Path, filename: str, pattern: str) -> str | None:
    path = workflows_dir / filename
    if not path.exists():
        return None
    match = re.search(pattern, path.read_text())
    return match.group(1) if match else None


def parse_version(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return ()


def is_stale(pinned: str, latest: str) -> bool:
    pinned_v, latest_v = parse_version(pinned), parse_version(latest)
    if not pinned_v or not latest_v:
        return pinned != latest
    return pinned_v < latest_v


def fetch_latest(kind: str, ref: str, token: str | None = None) -> str | None:
    """Return the latest upstream version string, or None on any failure."""
    if kind == "github":
        url = f"https://api.github.com/repos/{ref}/releases/latest"
    elif kind == "pypi":
        url = f"https://pypi.org/pypi/{ref}/json"
    else:
        return None
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    if token and kind == "github":
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read())
    except Exception:  # noqa: BLE001 - any network failure means "unknown"
        return None
    if kind == "github":
        tag = data.get("tag_name", "")
        return tag.lstrip("v") or None
    return (data.get("info") or {}).get("version")


def render_report(rows: list[dict[str, str | bool | None]]) -> str:
    lines = [
        "## Scanner CLI currency",
        "",
        "| Tool | Pinned | Latest | Status |",
        "|---|---|---|---|",
    ]
    for row in rows:
        if row["pinned"] is None:
            status = "⚠️ pin not found"
        elif row["latest"] is None:
            status = "⚠️ lookup failed"
        elif row["stale"]:
            status = "🔴 stale"
        else:
            status = "✅ current"
        lines.append(
            f"| {row['tool']} | {row['pinned'] or '?'} | "
            f"{row['latest'] or '?'} | {status} |"
        )
    lines.append("")
    lines.append(
        "Bump procedure: update the version pin **and** its SHA256 (from the "
        "upstream release checksums) in the workflow file, then let "
        "ci-self-test validate. Pins live in `.github/workflows/`."
    )
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflows-dir", default=".github/workflows")
    parser.add_argument("--report-out", required=True)
    parser.add_argument("--outputs-out", default=None, help="GITHUB_OUTPUT path.")
    parser.add_argument("--github-token", default=None)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    workflows_dir = Path(args.workflows_dir)

    rows: list[dict[str, str | bool | None]] = []
    stale_count = 0
    for tool, filename, pattern, kind, ref in TOOLS:
        pinned = extract_pinned(workflows_dir, filename, pattern)
        latest = fetch_latest(kind, ref, args.github_token)
        stale = bool(pinned and latest and is_stale(pinned, latest))
        stale_count += int(stale)
        rows.append({"tool": tool, "pinned": pinned, "latest": latest, "stale": stale})

    Path(args.report_out).write_text(render_report(rows))
    if args.outputs_out:
        with Path(args.outputs_out).open("a") as out:
            out.write(f"stale={stale_count}\n")
    print(f"Tool currency: {stale_count} stale pin(s) of {len(TOOLS)} tools.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
