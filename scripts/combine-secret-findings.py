#!/usr/bin/env python3
"""Combine, deduplicate, and render Gitleaks + Trufflehog secret findings.

Per policy, the secret value itself is NEVER emitted — only the rule that
fired, file:line, and scanner metadata. Verified findings (confirmed live by
Trufflehog against the provider) count as critical deploy-gate breaches;
unverified findings remain informational.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_report(path: Path) -> list[dict[str, Any]]:
    """Load a scanner report that may be a JSON array or NDJSON."""
    if not path.exists() or path.stat().st_size == 0:
        return []
    try:
        text = path.read_text().strip()
        if not text:
            return []
        if text.startswith("["):
            data = json.loads(text)
            return data if isinstance(data, list) else []
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []


def normalize_gitleaks(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "source": "gitleaks",
            "rule": f.get("RuleID", "unknown"),
            "file": f.get("File", "?"),
            "line": f.get("StartLine", 0),
            "secret_type": f.get("Description", "secret"),
            "verified": False,
        }
        for f in findings
        if isinstance(f, dict)
    ]


def normalize_trufflehog(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        src = (f.get("SourceMetadata", {}) or {}).get("Data", {}) or {}
        fs = src.get("Filesystem", {}) or {}
        normalized.append(
            {
                "source": "trufflehog",
                "rule": f.get("DetectorName", "unknown"),
                "file": fs.get("file", "?"),
                "line": fs.get("line", 0),
                "secret_type": f.get("DetectorName", "secret"),
                "verified": bool(f.get("Verified", False)),
            }
        )
    return normalized


def dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, Any, Any]] = set()
    deduped = []
    for f in findings:
        key = (f["file"], f["line"], f["rule"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def build_summary_json(deduped: list[dict[str, Any]]) -> dict[str, Any]:
    verified = [f for f in deduped if f["verified"]]
    unverified = [f for f in deduped if not f["verified"]]
    return {
        "total": len(deduped),
        "verified": len(verified),
        "unverified": len(unverified),
        "counts": {
            "critical": len(verified),
            "high": 0,
            "medium": 0,
            "low": len(unverified),
        },
        "breaches": len(verified),
        "findings": deduped,
    }


def render_markdown(summary: dict[str, Any], baseline_file: str) -> str:
    deduped = summary["findings"]
    lines = ["## Secret Scan Results", ""]
    lines.append(f"- **Total findings:** {summary['total']}")
    lines.append(f"- **Verified (live):** {summary['verified']}")
    lines.append(f"- **Unverified:** {summary['unverified']}")
    lines.append(
        "- **Gate behavior:** verified findings are counted as critical "
        "deploy-gate breaches; unverified findings remain informational."
    )
    lines.append("")
    if deduped:
        lines.append("| Scanner | Rule | Type | File | Line | Verified |")
        lines.append("|---|---|---|---|---|---|")
        for f in deduped[:50]:
            v = "yes" if f["verified"] else "no"
            lines.append(
                f"| {f['source']} | `{f['rule']}` | {f['secret_type']} | "
                f"`{f['file']}` | {f['line']} | {v} |"
            )
        lines.append("")
        lines.append(
            "### Remediation\n"
            "1. **Rotate the credential immediately** at the provider.\n"
            "2. Remove the secret from history (`git filter-repo` or BFG).\n"
            "3. Store the new value in GitHub Encrypted Secrets or your "
            "organization's secrets manager (Vault, AWS Secrets Manager).\n"
            "4. If this finding is a known false positive, add it to "
            f"`{baseline_file}` "
            "and reference it from the job inputs.\n"
        )
    else:
        lines.append("_No secrets detected._")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks-report", required=True)
    parser.add_argument("--trufflehog-report", required=True)
    parser.add_argument("--baseline-file", default=".gitleaks.baseline.json")
    parser.add_argument("--summary-json-out", required=True)
    parser.add_argument("--summary-md-out", required=True)
    parser.add_argument("--outputs-out", required=True, help="Appended to (step outputs).")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    findings = normalize_gitleaks(load_report(Path(args.gitleaks_report)))
    findings += normalize_trufflehog(load_report(Path(args.trufflehog_report)))
    deduped = dedupe(findings)

    summary = build_summary_json(deduped)
    Path(args.summary_json_out).write_text(json.dumps(summary, indent=2))
    Path(args.summary_md_out).write_text(render_markdown(summary, args.baseline_file))

    with Path(args.outputs_out).open("a") as out:
        out.write(f"verified={summary['verified']}\n")
        out.write(f"unverified={summary['unverified']}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
