#!/usr/bin/env python3
"""Summarize Snyk Code and Semgrep SARIF output for the SAST workflow.

Reads the SARIF reports emitted by the scanners, normalizes severities to
low/medium/high/critical, renders a job-summary markdown table, exposes
per-severity counts as step outputs, persists a compact findings JSON for
the PR-comment step, and writes the breach count used by the severity gate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from common import SEVERITY_ORDER, load_json

# Snyk uses "error/warning/note"; Semgrep uses "ERROR/WARNING/INFO";
# SARIF has level. Everything is normalized to low/medium/high/critical.
SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "info": "low",
    "none": "low",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def normalize_severity(severity: Any) -> str:
    if not severity:
        return "low"
    return SEVERITY_MAP.get(str(severity).lower(), "low")


def extract_findings(sarif: Any, tool: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(sarif, dict):
        return findings
    for run in sarif.get("runs", []) or []:
        for result in run.get("results", []) or []:
            sev = normalize_severity(
                (result.get("properties", {}) or {}).get("security-severity")
                or result.get("level")
            )
            rule = result.get("ruleId", "unknown")
            msg = (result.get("message", {}) or {}).get("text", "")
            loc = ""
            for location in result.get("locations", []) or []:
                art = location.get("physicalLocation", {}).get("artifactLocation", {})
                region = location.get("physicalLocation", {}).get("region", {})
                loc = f"{art.get('uri', '?')}:{region.get('startLine', '?')}"
                break
            findings.append(
                {
                    "tool": tool,
                    "rule": rule,
                    "severity": sev,
                    "message": msg[:140],
                    "location": loc,
                }
            )
    return findings


def count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


def rank(findings: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda f: -SEVERITY_ORDER[f["severity"]])[:limit]


def render_summary(
    findings: list[dict[str, Any]], counts: dict[str, int], fail_on: str
) -> str:
    lines = ["## SAST Results", "", "| Severity | Count |", "|---|---|"]
    for sev in ("critical", "high", "medium", "low"):
        lines.append(f"| {sev.title()} | {counts[sev]} |")
    lines.append(f"\n**Fail threshold:** `{fail_on}` and above.\n")
    if findings:
        lines.append("### Top findings")
        lines.append("")
        lines.append("| Tool | Severity | Rule | Location | Message |")
        lines.append("|---|---|---|---|---|")
        for f in rank(findings, 5):
            lines.append(
                f"| {f['tool']} | {f['severity']} | `{f['rule']}` |"
                f" `{f['location']}` | {f['message']} |"
            )
    lines.append(
        "\nSee the [Security tab](../../security/code-scanning) for the full list.\n"
    )
    return "\n".join(lines)


def count_breaches(counts: dict[str, int], fail_on: str) -> int:
    threshold = SEVERITY_ORDER[fail_on]
    return sum(n for sev, n in counts.items() if SEVERITY_ORDER[sev] >= threshold)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snyk-sarif", required=True)
    parser.add_argument("--semgrep-sarif", required=True)
    parser.add_argument(
        "--fail-on", required=True, type=str.lower, choices=sorted(SEVERITY_ORDER)
    )
    parser.add_argument("--summary-out", required=True, help="Appended to (job summary).")
    parser.add_argument("--outputs-out", required=True, help="Appended to (step outputs).")
    parser.add_argument("--findings-out", required=True)
    parser.add_argument("--breaches-out", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()

    findings: list[dict[str, Any]] = []
    for path, tool in ((args.snyk_sarif, "snyk"), (args.semgrep_sarif, "semgrep")):
        data = load_json(Path(path))
        if data:
            findings.extend(extract_findings(data, tool))

    counts = count_by_severity(findings)

    with Path(args.summary_out).open("a") as fh:
        fh.write(render_summary(findings, counts, args.fail_on))

    with Path(args.outputs_out).open("a") as out:
        for sev, n in counts.items():
            out.write(f"{sev}={n}\n")

    Path(args.findings_out).write_text(
        json.dumps({"counts": counts, "top": rank(findings, 10)})
    )

    breaches = count_breaches(counts, args.fail_on)
    Path(args.breaches_out).write_text(str(breaches))
    return 0


if __name__ == "__main__":
    sys.exit(main())
