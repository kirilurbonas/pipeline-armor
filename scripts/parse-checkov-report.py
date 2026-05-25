#!/usr/bin/env python3
"""Parse a Checkov JSON report into Markdown summary + counts.

Checkov's JSON varies subtly between versions: older versions return a single
object, newer versions return a list of objects (one per framework). This
script normalizes both, applies a severity tally compatible with the deploy
gate, and emits the same artifacts as parse-trivy-report.py.

A small static map of Checkov ``check_id`` -> compliance frameworks is used
to render the "frameworks affected" table; the map is not exhaustive, but
covers the most common AWS controls. The mapping intentionally lives in this
file so the workflow remains self-contained.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Severities Checkov reports range over (string, sometimes None).
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# A small, opinionated subset — extend as needed.
COMPLIANCE_MAP: dict[str, list[str]] = {
    "CKV_AWS_18": ["CIS-1.20", "SOC2-CC6.1"],   # S3 bucket logging
    "CKV_AWS_19": ["CIS-2.1", "PCI-DSS-3.4"],   # S3 SSE
    "CKV_AWS_20": ["CIS-2.1.5"],                # S3 public read
    "CKV_AWS_21": ["CIS-2.1.2"],                # S3 versioning
    "CKV_AWS_23": ["CIS-4.3"],                  # SG descriptions
    "CKV_AWS_24": ["CIS-4.1", "PCI-DSS-1.2"],   # SG ingress 0.0.0.0/0 SSH
    "CKV_AWS_25": ["CIS-4.2"],                  # SG ingress 0.0.0.0/0 RDP
    "CKV_AWS_40": ["CIS-1.16"],                 # IAM policies on users
    "CKV_AWS_45": ["CIS-1.20"],                 # Lambda env secrets
    "CKV_AWS_46": ["CIS-1.20"],                 # ECS env secrets
    "CKV_AWS_50": ["SOC2-CC7.2"],               # Lambda tracing
    "CKV_AWS_52": ["CIS-2.1.2"],                # S3 MFA delete
    "CKV_K8S_8":  ["CIS-K8S-5.1.5"],            # Privileged containers
    "CKV_K8S_20": ["CIS-K8S-5.2.5"],            # allowPrivilegeEscalation
}


def load_report(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return []
    try:
        raw = json.loads(p.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    return []


def normalize_severity(check: dict) -> str:
    # Checkov sets severity in different places depending on version: top
    # level, or under ``check_result``, or absent. We default to "medium" so
    # un-rated checks don't silently slip below the gate threshold.
    sev = check.get("severity") or (
        check.get("check_result", {}) or {}
    ).get("severity")
    if not sev:
        return "medium"
    sev = str(sev).lower()
    return sev if sev in SEVERITY_ORDER else "medium"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", required=True)
    p.add_argument("--fail-on", required=True)
    p.add_argument("--summary-out", required=True)
    p.add_argument("--comment-out", required=True)
    p.add_argument("--counts-out", required=True)
    args = p.parse_args()

    blocks = load_report(args.report)
    passed = failed = skipped = 0
    failed_checks: list[dict] = []
    framework_hits: dict[str, int] = {}

    for block in blocks:
        results = (block.get("results") or {})
        for check in results.get("passed_checks", []) or []:
            passed += 1
        for check in results.get("skipped_checks", []) or []:
            skipped += 1
        for check in results.get("failed_checks", []) or []:
            failed += 1
            sev = normalize_severity(check)
            check_id = check.get("check_id", "?")
            file_path = check.get("file_path", "?")
            file_line = (check.get("file_line_range") or [None])[0]
            failed_checks.append(
                {
                    "id": check_id,
                    "name": check.get("check_name", ""),
                    "resource": check.get("resource", "?"),
                    "file": f"{file_path}:{file_line}" if file_line else file_path,
                    "severity": sev,
                    "guideline": check.get("guideline", ""),
                }
            )
            for fw in COMPLIANCE_MAP.get(check_id, []):
                framework_hits[fw] = framework_hits.get(fw, 0) + 1

    total = passed + failed + skipped
    pct = lambda n: f"{(n/total*100):.1f}%" if total else "0.0%"

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for c in failed_checks:
        counts[c["severity"]] += 1

    fail_on = args.fail_on.lower()
    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["high"])
    breaches = sum(
        n for s, n in counts.items() if SEVERITY_ORDER[s] >= threshold
    )

    # ---- Job summary -------------------------------------------------------
    s = []
    s.append("## IaC Scan (Checkov)\n")
    s.append(f"- **Passed:** {passed} ({pct(passed)})")
    s.append(f"- **Failed:** {failed} ({pct(failed)})")
    s.append(f"- **Skipped:** {skipped} ({pct(skipped)})")
    s.append(f"- **Fail threshold:** `{fail_on}` and above ({breaches} breaching)")
    s.append("")
    if failed_checks:
        s.append("### Failed checks\n")
        s.append("| Check | Severity | Resource | File | Description |")
        s.append("|---|---|---|---|---|")
        for c in failed_checks[:25]:
            guideline_link = f"[link]({c['guideline']})" if c['guideline'] else ""
            s.append(
                f"| `{c['id']}` | {c['severity']} | `{c['resource']}` | "
                f"`{c['file']}` | {c['name']} {guideline_link} |"
            )
        s.append("")
    if framework_hits:
        s.append("### Compliance frameworks affected\n")
        s.append("| Framework | Failing checks |")
        s.append("|---|---|")
        for fw, n in sorted(framework_hits.items(), key=lambda kv: -kv[1]):
            s.append(f"| {fw} | {n} |")
        s.append("")

    summary_md = "\n".join(s)

    # ---- PR comment --------------------------------------------------------
    c_lines = []
    c_lines.append("### IaC Scan (Checkov)")
    c_lines.append(
        f"Passed {passed} · Failed {failed} · Skipped {skipped} · "
        f"Threshold `{fail_on}`"
    )
    c_lines.append("")
    c_lines.append("| Critical | High | Medium | Low |")
    c_lines.append("|---|---|---|---|")
    c_lines.append(
        f"| {counts['critical']} | {counts['high']} | "
        f"{counts['medium']} | {counts['low']} |"
    )
    if failed_checks:
        c_lines.append("")
        c_lines.append("**Top failing checks:**")
        c_lines.append("")
        c_lines.append("| Check | Severity | Resource |")
        c_lines.append("|---|---|---|")
        for c in failed_checks[:5]:
            c_lines.append(
                f"| `{c['id']}` | {c['severity']} | `{c['resource']}` |"
            )
    comment_md = "\n".join(c_lines) + "\n"

    Path(args.summary_out).write_text(summary_md)
    Path(args.comment_out).write_text(comment_md)
    Path(args.counts_out).write_text(
        json.dumps({**counts, "breaches": breaches,
                    "passed": passed, "failed": failed, "skipped": skipped},
                   indent=2)
    )

    print(
        f"Checkov: passed={passed} failed={failed} skipped={skipped} "
        f"breaches@{fail_on}={breaches}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
