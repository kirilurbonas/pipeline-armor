#!/usr/bin/env python3
"""Parse dependency-scan outputs into Markdown summaries + gate counts.

The reusable dependency workflow combines several signals:

* GitHub's dependency-review action for PR-diff regressions.
* Snyk Open Source for full dependency-tree vulnerability data.
* License-policy enforcement from the workflow's own evaluation step.

This script normalizes those inputs into:

* A human-readable job summary.
* A shorter PR-comment-friendly Markdown block.
* A machine-readable JSON artifact consumed by the deploy gate.

Policy breaches that are not inherently severity-based (for example license
violations or a failed dependency-review step) are modeled as synthetic
``critical`` findings so downstream gates fail closed across environments.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from common import SEVERITY_ORDER, load_json, md_cell


def normalize_severity(value: Any) -> str:
    """Collapse scanner-specific severities into low/medium/high/critical."""
    if not value:
        return "low"
    sev = str(value).lower()
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "info": "low",
        "note": "low",
        "none": "low",
    }.get(sev, "low")


def extract_fixed_version(vuln: dict[str, Any]) -> str:
    for key in ("nearestFixedInVersion", "fixedIn", "fixedVersion"):
        value = vuln.get(key)
        if value:
            return str(value)

    upgrade_path = vuln.get("upgradePath")
    if isinstance(upgrade_path, list):
        for value in reversed(upgrade_path):
            if value and not str(value).startswith("false"):
                return str(value)
    return "—"


def _iter_issue_candidates(data: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return

        if not isinstance(node, dict):
            return

        vulnerabilities = node.get("vulnerabilities")
        if isinstance(vulnerabilities, list):
            for vuln in vulnerabilities:
                if isinstance(vuln, dict):
                    found.append(vuln)

        issues = node.get("issues")
        if isinstance(issues, list):
            for issue in issues:
                if isinstance(issue, dict):
                    found.append(issue)
        elif isinstance(issues, dict):
            for value in issues.values():
                if isinstance(value, list):
                    for issue in value:
                        if isinstance(issue, dict):
                            found.append(issue)

        for key, value in node.items():
            if key in {"vulnerabilities", "issues"}:
                continue
            walk(value)

    walk(data)
    return found


def collect_vulnerabilities(data: Any) -> list[dict[str, str]]:
    """Extract a deduplicated list of vulnerability-like entries."""
    if data is None:
        return []

    seen: set[tuple[str, str, str, str, str]] = set()
    out: list[dict[str, str]] = []
    for vuln in _iter_issue_candidates(data):
        severity = normalize_severity(vuln.get("severity"))
        vuln_id = (
            vuln.get("id")
            or vuln.get("issueId")
            or vuln.get("name")
            or vuln.get("title")
            or "unknown"
        )
        package = vuln.get("packageName") or vuln.get("package") or vuln.get("pkgName") or "?"
        version = vuln.get("version") or vuln.get("versionFrom") or vuln.get("semver") or "?"
        title = vuln.get("title") or vuln.get("name") or str(vuln_id)
        fixed = extract_fixed_version(vuln)
        key = (str(vuln_id), str(package), str(version), severity, str(title))
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "id": str(vuln_id),
                "package": str(package),
                "version": str(version),
                "fixed": str(fixed),
                "severity": severity,
                "title": str(title).strip(),
            }
        )
    return out


def severity_counts(items: list[dict[str, str]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in items:
        counts[item["severity"]] += 1
    return counts


def render_summary(
    args: argparse.Namespace, vulns: list[dict[str, str]]
) -> tuple[str, str, dict[str, Any]]:
    vuln_counts = severity_counts(vulns)
    synthetic_critical = 0
    notes: list[str] = []

    if args.license_violations > 0:
        synthetic_critical += args.license_violations
        notes.append(
            f"{args.license_violations} license policy violation(s) "
            "counted as critical gate breaches."
        )

    if args.github_review_failed:
        synthetic_critical += 1
        notes.append(
            "GitHub dependency review reported a failing PR-diff regression "
            "and is counted as a critical gate breach."
        )

    tool_errors = 0
    if args.snyk_ran and args.snyk_report_present == 0:
        tool_errors += 1
        notes.append(
            "Snyk was enabled but did not produce a readable JSON report; the gate fails closed."
        )
    elif args.snyk_ran and args.snyk_exit_code == 2:
        tool_errors += 1
        notes.append(
            "Snyk exited with an execution error and is counted as a critical gate breach."
        )

    synthetic_critical += tool_errors

    counts = {
        "critical": vuln_counts["critical"] + synthetic_critical,
        "high": vuln_counts["high"],
        "medium": vuln_counts["medium"],
        "low": vuln_counts["low"],
    }

    threshold = SEVERITY_ORDER.get(args.fail_on.lower(), SEVERITY_ORDER["high"])
    breaches = sum(
        count for sev, count in counts.items() if SEVERITY_ORDER[sev] >= threshold
    )

    top = sorted(
        vulns,
        key=lambda item: (-SEVERITY_ORDER[item["severity"]], item["package"], item["id"]),
    )[:10]

    summary = [
        "## Dependency Review",
        "",
        f"- **Fail threshold:** `{args.fail_on.lower()}` and above",
        f"- **Snyk enabled:** {'yes' if args.snyk_ran else 'no'}",
        f"- **Snyk report available:** {'yes' if args.snyk_report_present else 'no'}",
        f"- **License violations:** {args.license_violations}",
        f"- **License gate:** {args.license_status}"
        + (
            " ⚠️ (not evaluated — do not read 0 violations as clean)"
            if args.license_status != "evaluated"
            else ""
        ),
        f"- **GitHub dependency review failed:** {'yes' if args.github_review_failed else 'no'}",
        f"- **Tool errors:** {tool_errors}",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in ("critical", "high", "medium", "low"):
        summary.append(f"| {sev.title()} | {counts[sev]} |")

    if notes:
        summary.extend(["", "### Gate notes", ""])
        for note in notes:
            summary.append(f"- {note}")

    if top:
        summary.extend(
            [
                "",
                "### Top vulnerabilities",
                "",
                "| ID | Package | Installed | Fixed | Severity |",
                "|---|---|---|---|---|",
            ]
        )
        for vuln in top:
            summary.append(
                f"| `{md_cell(vuln['id'])}` | `{md_cell(vuln['package'])}` | "
                f"`{md_cell(vuln['version'])}` | `{md_cell(vuln['fixed'])}` | "
                f"{md_cell(vuln['severity'])} |"
            )

    comment = [
        "### Dependency Review",
        "",
        f"Fail on `{args.fail_on.lower()}` and above.",
        "",
        "| Critical | High | Medium | Low |",
        "|---|---|---|---|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |",
    ]
    if args.license_violations:
        comment.append("")
        comment.append(
            f"License policy violations: **{args.license_violations}** "
            "(counted as critical gate breaches)."
        )
    if args.license_status != "evaluated":
        comment.append("")
        comment.append(
            f"⚠️ License gate **not evaluated** ({args.license_status}) — "
            "0 violations does not mean clean."
        )
    if args.github_review_failed:
        comment.append("")
        comment.append(
            "GitHub dependency review detected a failing PR-diff regression."
        )
    if tool_errors:
        comment.append("")
        comment.append("Scanner execution errors were detected; the gate fails closed.")

    counts_out: dict[str, Any] = {
        **counts,
        "breaches": breaches,
        "total_vulnerabilities": len(vulns),
        "vulnerability_counts": vuln_counts,
        "license_violations": args.license_violations,
        "license_status": args.license_status,
        "github_review_failed": bool(args.github_review_failed),
        "snyk_ran": bool(args.snyk_ran),
        "snyk_report_present": bool(args.snyk_report_present),
        "snyk_exit_code": args.snyk_exit_code,
        "tool_errors": tool_errors,
        "status": "fail" if breaches else "pass",
    }
    return "\n".join(summary) + "\n", "\n".join(comment) + "\n", counts_out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snyk-report", required=True, help="Path to snyk-deps.json")
    parser.add_argument("--fail-on", required=True)
    parser.add_argument("--license-violations", type=int, default=0)
    parser.add_argument(
        "--license-status",
        default="evaluated",
        choices=("evaluated", "missing", "unsupported"),
        help="Whether the license gate was actually evaluated for this ecosystem.",
    )
    parser.add_argument("--github-review-failed", type=int, choices=(0, 1), default=0)
    parser.add_argument("--snyk-ran", type=int, choices=(0, 1), default=0)
    parser.add_argument("--snyk-report-present", type=int, choices=(0, 1), default=0)
    parser.add_argument("--snyk-exit-code", type=int, default=0)
    parser.add_argument("--summary-out", required=True)
    parser.add_argument("--comment-out", required=True)
    parser.add_argument("--counts-out", required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    report = load_json(args.snyk_report)
    args.snyk_report_present = 1 if report is not None else 0
    vulns = collect_vulnerabilities(report)
    summary_md, comment_md, counts = render_summary(args, vulns)
    Path(args.summary_out).write_text(summary_md)
    Path(args.comment_out).write_text(comment_md)
    Path(args.counts_out).write_text(json.dumps(counts, indent=2))
    print(
        "Dependency review:"
        f" vulns={len(vulns)}"
        f" license_violations={args.license_violations}"
        f" breaches@{args.fail_on.lower()}={counts['breaches']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
