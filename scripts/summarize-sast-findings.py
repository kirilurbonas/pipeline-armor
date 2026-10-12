#!/usr/bin/env python3
"""Summarize Snyk Code and Semgrep SARIF output for the SAST workflow.

Reads the SARIF reports emitted by the scanners, normalizes severities to
low/medium/high/critical (numeric ``security-severity`` scores, looked up on
the result first and then on its rule, take precedence over ``level``),
renders a job-summary markdown table, exposes per-severity counts as step
outputs, persists a compact findings JSON for the PR-comment step, and writes
the breach count used by the severity gate. Scanner failures (bad exit code,
missing SARIF) are recorded as ``tool_errors`` and count as breaches.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from common import SEVERITY_ORDER, cvss_to_bucket, load_json, md_cell

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


# Scanner exit codes that mean "ran successfully" (findings or not). Snyk
# exits 3 when the tree has no supported files, which is not a failure.
OK_EXIT_CODES = {"snyk": {0, 1, 3}, "semgrep": {0, 1}}


def normalize_severity(severity: Any) -> str:
    if not severity:
        return "low"
    bucket = cvss_to_bucket(severity)
    if bucket:
        return bucket
    return SEVERITY_MAP.get(str(severity).lower(), "low")


def rule_severities(run: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    """Map ruleId -> the rule's own severity signal.

    Semgrep (and often Snyk) put ``security-severity`` in the rule
    ``properties`` and the SARIF ``level`` in ``defaultConfiguration``,
    leaving the individual results without either. Returns
    ``(security_severity, default_level)`` per rule.
    """
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    out: dict[str, tuple[Any, Any]] = {}
    for r in rules:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        out[r["id"]] = (
            (r.get("properties") or {}).get("security-severity"),
            (r.get("defaultConfiguration") or {}).get("level"),
        )
    return out


def tool_errors(name: str, exit_code: str | None, sarif_present: bool) -> list[str]:
    """Describe why a scanner's result can't be trusted, if it can't.

    ``exit_code`` is ``None`` when the scanner was intentionally skipped.
    """
    if exit_code is None or exit_code == "":
        return []
    try:
        code = int(exit_code)
    except ValueError:
        return [f"{name}: unparseable exit code {exit_code!r}"]
    if code not in OK_EXIT_CODES[name]:
        return [f"{name}: exited with code {code}"]
    if not sarif_present and code != 3:
        return [f"{name}: produced no SARIF output"]
    return []


def extract_findings(sarif: Any, tool: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(sarif, dict):
        return findings
    for run in sarif.get("runs", []) or []:
        rules = rule_severities(run)
        for result in run.get("results", []) or []:
            rule = result.get("ruleId", "unknown")
            rule_score, rule_level = rules.get(rule, (None, None))
            # Precedence: numeric/explicit score (result, then rule) beats
            # the coarse SARIF level (result, then rule default).
            sev = normalize_severity(
                (result.get("properties", {}) or {}).get("security-severity")
                or rule_score
                or result.get("level")
                or rule_level
            )
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


def render_errors(errors: list[str]) -> list[str]:
    if not errors:
        return []
    lines = ["", "**Scanner errors (gate fails closed):**", ""]
    lines.extend(f"- {md_cell(e)}" for e in errors)
    lines.append("")
    return lines


def render_summary(
    findings: list[dict[str, Any]],
    counts: dict[str, int],
    fail_on: str,
    errors: list[str] | None = None,
) -> str:
    lines = ["## SAST Results", "", "| Severity | Count |", "|---|---|"]
    for sev in ("critical", "high", "medium", "low"):
        lines.append(f"| {sev.title()} | {counts[sev]} |")
    lines.append(f"\n**Fail threshold:** `{fail_on}` and above.\n")
    lines.extend(render_errors(errors or []))
    if findings:
        lines.append("### Top findings")
        lines.append("")
        lines.append("| Tool | Severity | Rule | Location | Message |")
        lines.append("|---|---|---|---|---|")
        for f in rank(findings, 5):
            lines.append(
                f"| {md_cell(f['tool'])} | {md_cell(f['severity'])} | `{md_cell(f['rule'])}` |"
                f" `{md_cell(f['location'])}` | {md_cell(f['message'])} |"
            )
    lines.append(
        "\nSee the [Security tab](../../security/code-scanning) for the full list.\n"
    )
    return "\n".join(lines)


def render_comment(
    findings: list[dict[str, Any]],
    counts: dict[str, int],
    fail_on: str,
    errors: list[str] | None = None,
) -> str:
    """Short PR-comment body (the upsert action prepends the marker)."""
    lines = [
        "### SAST scan results",
        "",
        "| Critical | High | Medium | Low |",
        "|---|---|---|---|",
        f"| {counts['critical']} | {counts['high']} | "
        f"{counts['medium']} | {counts['low']} |",
        *render_errors(errors or []),
        "",
        "#### Top findings",
        "| Tool | Severity | Rule | Location |",
        "|---|---|---|---|",
    ]
    top = rank(findings, 10)
    if top:
        for f in top:
            lines.append(
                f"| {md_cell(f['tool'])} | {md_cell(f['severity'])} | "
                f"`{md_cell(f['rule'])}` | `{md_cell(f['location'])}` |"
            )
    else:
        lines.append("_No findings._")
    lines.append("")
    lines.append(f"_Fail threshold: `{fail_on}`._")
    return "\n".join(lines) + "\n"


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
    parser.add_argument("--comment-out", required=True)
    parser.add_argument("--breaches-out", required=True)
    parser.add_argument(
        "--snyk-exit", default=None, help="Snyk exit code; omit when Snyk was skipped."
    )
    parser.add_argument(
        "--semgrep-exit", default=None, help="Semgrep exit code; omit when skipped."
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for path, tool, exit_code in (
        (args.snyk_sarif, "snyk", args.snyk_exit),
        (args.semgrep_sarif, "semgrep", args.semgrep_exit),
    ):
        data = load_json(Path(path))
        if data:
            findings.extend(extract_findings(data, tool))
        errors.extend(tool_errors(tool, exit_code, isinstance(data, dict)))

    counts = count_by_severity(findings)

    with Path(args.summary_out).open("a") as fh:
        fh.write(render_summary(findings, counts, args.fail_on, errors))

    with Path(args.outputs_out).open("a") as out:
        for sev, n in counts.items():
            out.write(f"{sev}={n}\n")

    Path(args.findings_out).write_text(
        json.dumps(
            {
                "counts": counts,
                "top": rank(findings, 10),
                "tool_errors": len(errors),
                "errors": errors,
            }
        )
    )
    Path(args.comment_out).write_text(
        render_comment(findings, counts, args.fail_on, errors)
    )

    # A scanner that failed to run is a breach: never report "0 findings,
    # pass" for a scan that didn't happen.
    breaches = count_breaches(counts, args.fail_on) + len(errors)
    Path(args.breaches_out).write_text(str(breaches))
    return 0


if __name__ == "__main__":
    sys.exit(main())
