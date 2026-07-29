#!/usr/bin/env python3
"""Parse osv-scanner JSON output into Markdown summaries + gate counts.

OSV severity data is heterogeneous: some advisories carry a textual
``database_specific.severity`` (CRITICAL/HIGH/…), others only a CVSS score
surfaced via the result ``groups[].max_severity``. Both are honored; CVSS
scores map to buckets with the standard thresholds (>=9 critical, >=7 high,
>=4 medium, else low). Findings with no severity signal at all default to
low, consistent with the other parsers in this library.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITIES = ("critical", "high", "medium", "low")


def md_cell(value: Any) -> str:
    """Escape scanner-controlled values for safe Markdown table rendering."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "'")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def load_json(path: str) -> Any | None:
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def cvss_to_bucket(score: Any) -> str | None:
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


def normalize_severity(vuln: dict[str, Any], group_score: Any) -> str:
    text = ((vuln.get("database_specific") or {}).get("severity") or "").lower()
    if text in SEVERITY_ORDER:
        return text
    bucket = cvss_to_bucket(group_score)
    if bucket:
        return bucket
    return "low"


def collect_findings(report: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(report, dict):
        return findings
    for result in report.get("results", []) or []:
        if not isinstance(result, dict):
            continue
        source = (result.get("source") or {}).get("path", "?")
        for pkg in result.get("packages", []) or []:
            if not isinstance(pkg, dict):
                continue
            info = pkg.get("package") or {}
            # groups[].max_severity holds the highest CVSS score per advisory
            # group; index it by vulnerability id.
            score_by_id: dict[str, Any] = {}
            for group in pkg.get("groups", []) or []:
                if not isinstance(group, dict):
                    continue
                for vuln_id in group.get("ids", []) or []:
                    score_by_id[vuln_id] = group.get("max_severity")
            for vuln in pkg.get("vulnerabilities", []) or []:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = vuln.get("id", "unknown")
                findings.append(
                    {
                        "id": vuln_id,
                        "package": info.get("name", "?"),
                        "version": info.get("version", "?"),
                        "ecosystem": info.get("ecosystem", "?"),
                        "source": source,
                        "severity": normalize_severity(
                            vuln, score_by_id.get(vuln_id)
                        ),
                        "summary": str(vuln.get("summary", ""))[:140],
                    }
                )
    return findings


def count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITIES}
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


def count_breaches(counts: dict[str, int], fail_on: str) -> int:
    threshold = SEVERITY_ORDER[fail_on]
    return sum(n for sev, n in counts.items() if SEVERITY_ORDER[sev] >= threshold)


def render(
    findings: list[dict[str, Any]],
    counts: dict[str, int],
    fail_on: str,
    breaches: int,
    tool_errors: int,
) -> tuple[str, str]:
    summary = [
        "## OSV Vulnerability Scan",
        "",
        f"- **Fail threshold:** `{fail_on}` and above",
        f"- **Total findings:** {len(findings)}",
        f"- **Gate breaches:** {breaches}",
        f"- **Tool errors:** {tool_errors}",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in SEVERITIES:
        summary.append(f"| {sev.title()} | {counts[sev]} |")

    top = sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["package"], f["id"]),
    )[:10]
    if top:
        summary.extend(
            [
                "",
                "### Top vulnerabilities",
                "",
                "| ID | Package | Version | Ecosystem | Severity |",
                "|---|---|---|---|---|",
            ]
        )
        for f in top:
            summary.append(
                f"| `{md_cell(f['id'])}` | `{md_cell(f['package'])}` | "
                f"`{md_cell(f['version'])}` | {md_cell(f['ecosystem'])} | "
                f"{md_cell(f['severity'])} |"
            )

    comment = [
        "### OSV Vulnerability Scan",
        "",
        f"Fail on `{fail_on}` and above.",
        "",
        "| Critical | High | Medium | Low |",
        "|---|---|---|---|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |",
    ]
    if breaches:
        comment.append("")
        comment.append(f"**{breaches} finding(s) breach the gate threshold.**")
    if tool_errors:
        comment.append("")
        comment.append("Scanner execution errors were detected; the gate fails closed.")

    return "\n".join(summary) + "\n", "\n".join(comment) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, help="Path to osv-results.json")
    parser.add_argument(
        "--fail-on", required=True, type=str.lower, choices=sorted(SEVERITY_ORDER)
    )
    parser.add_argument(
        "--scanner-exit-code",
        type=int,
        default=0,
        help="osv-scanner exit code; codes other than 0 (clean) and 1 "
        "(findings) are treated as tool errors and fail closed.",
    )
    parser.add_argument("--summary-out", required=True)
    parser.add_argument("--comment-out", required=True)
    parser.add_argument("--counts-out", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()

    report = load_json(args.report)
    findings = collect_findings(report)
    counts = count_by_severity(findings)
    breaches = count_breaches(counts, args.fail_on)

    # Exit code 0 = clean, 1 = findings (already reflected in the report);
    # anything else means the scanner itself failed and we cannot trust the
    # (possibly empty) report — fail closed via tool_errors.
    tool_errors = 0 if args.scanner_exit_code in (0, 1) else 1
    if report is None and args.scanner_exit_code == 1:
        # Findings were reported but the JSON is missing/unreadable.
        tool_errors = 1

    summary, comment = render(findings, counts, args.fail_on, breaches, tool_errors)
    Path(args.summary_out).write_text(summary)
    Path(args.comment_out).write_text(comment)
    Path(args.counts_out).write_text(
        json.dumps(
            {
                **counts,
                "breaches": breaches,
                "total_vulnerabilities": len(findings),
                "tool_errors": tool_errors,
                "status": "fail" if breaches or tool_errors else "pass",
            },
            indent=2,
        )
    )
    print(
        f"OSV scan: findings={len(findings)} breaches={breaches} "
        f"tool_errors={tool_errors}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
