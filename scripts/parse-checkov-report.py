#!/usr/bin/env python3
"""Parse a Checkov JSON report into Markdown summary + counts.

Checkov's JSON varies subtly between versions: older versions return a single
object, newer versions return a list of objects (one per framework). This
script normalizes both, applies a severity tally compatible with the deploy
gate, and emits the same artifacts as parse-trivy-report.py.

Checkov OSS emits no severities without a Prisma Cloud API key. Severities
therefore come from (in order): the check itself when Checkov does supply one,
``policies/checkov-severity.json`` (pipeline-armor's ratings, optionally
overlaid by a caller map), and finally ``--default-severity`` (``high``) so
unrated findings fail closed instead of slipping under the gate. The same
policy file carries a small check -> compliance-framework map.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import common
from common import SEVERITY_ORDER, md_cell, md_link_url

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policies" / "checkov-severity.json"


def load_policy(paths: list[str]) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Merge severity + compliance maps; later files override earlier ones."""
    severities: dict[str, str] = {}
    compliance: dict[str, list[str]] = {}
    for path in paths:
        data = common.load_json(path, default={})
        if not isinstance(data, dict):
            continue
        for check_id, sev in (data.get("severities") or {}).items():
            if str(sev).lower() in SEVERITY_ORDER:
                severities[check_id] = str(sev).lower()
        for check_id, frameworks in (data.get("compliance") or {}).items():
            if isinstance(frameworks, list):
                compliance[check_id] = [str(f) for f in frameworks]
    return severities, compliance


def load_report(path: str) -> list[dict]:
    """Normalize Checkov's version-dependent output (dict vs list) to a list."""
    raw = common.load_json(path, default=[])
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    return []


def normalize_severity(
    check: dict, severity_map: dict[str, str] | None = None, default: str = "high"
) -> str:
    # Checkov sets severity in different places depending on version: top
    # level, or under ``check_result``, or absent (always absent in OSS
    # without an API key).
    sev = check.get("severity") or (
        check.get("check_result", {}) or {}
    ).get("severity")
    sev = str(sev).lower() if sev else ""
    if sev in SEVERITY_ORDER:
        return sev
    mapped = (severity_map or {}).get(check.get("check_id", ""))
    return mapped or default


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", required=True)
    p.add_argument("--fail-on", required=True)
    p.add_argument("--summary-out", required=True)
    p.add_argument("--comment-out", required=True)
    p.add_argument("--counts-out", required=True)
    p.add_argument("--sarif-in", required=False, help="Path to SARIF file to patch with severities")
    p.add_argument(
        "--default-severity",
        default="high",
        type=str.lower,
        choices=sorted(SEVERITY_ORDER),
        help="Severity for checks with no rating from Checkov or the policy map.",
    )
    p.add_argument(
        "--severity-map",
        action="append",
        default=[],
        help="Extra checkov-severity.json-style file(s) overlaid on the built-in map.",
    )
    p.add_argument(
        "--checkov-exit",
        default=None,
        help="Checkov exit code. Non-zero (Checkov runs with --soft-fail) or a "
        "missing report with a zero exit marks a tool error.",
    )
    args = p.parse_args()

    severity_map, compliance_map = load_policy([str(DEFAULT_POLICY), *args.severity_map])

    def rate(check: dict) -> str:
        return normalize_severity(check, severity_map, args.default_severity)

    tool_errors: list[str] = []
    if args.checkov_exit not in (None, ""):
        if args.checkov_exit != "0":
            tool_errors.append(f"checkov exited with code {args.checkov_exit}")
        elif not Path(args.report).exists():
            tool_errors.append("checkov produced no JSON report")

    blocks = load_report(args.report)
    passed = failed = skipped = 0
    failed_checks: list[dict] = []
    framework_hits: dict[str, int] = {}
    check_severities: dict[str, str] = {}

    for block in blocks:
        results = (block.get("results") or {})
        for check in results.get("passed_checks", []) or []:
            passed += 1
            check_severities[check.get("check_id")] = rate(check)
        for check in results.get("skipped_checks", []) or []:
            skipped += 1
            check_severities[check.get("check_id")] = rate(check)
        for check in results.get("failed_checks", []) or []:
            failed += 1
            sev = rate(check)
            check_id = check.get("check_id", "?")
            check_severities[check_id] = sev
            file_path = check.get("file_path", "?")
            line_range = check.get("file_line_range")
            file_line = line_range[0] if isinstance(line_range, list) and line_range else None
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
            for fw in compliance_map.get(check_id, []):
                framework_hits[fw] = framework_hits.get(fw, 0) + 1

    # With --quiet, Checkov omits passed_checks from the per-check lists;
    # its own ``summary`` block still has the true totals.
    summaries = [b.get("summary") for b in blocks if isinstance(b.get("summary"), dict)]
    if summaries:
        def total_of(key: str) -> int:
            return sum(int(x.get(key, 0) or 0) for x in summaries)

        passed = max(passed, total_of("passed"))
        skipped = max(skipped, total_of("skipped"))

    total = passed + failed + skipped
    def pct(n: int) -> str:
        return f"{(n/total*100):.1f}%" if total else "0.0%"

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for c in failed_checks:
        counts[c["severity"]] += 1

    fail_on = args.fail_on.lower()
    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["high"])
    breaches = sum(
        n for s, n in counts.items() if SEVERITY_ORDER[s] >= threshold
    ) + len(tool_errors)

    # ---- Job summary -------------------------------------------------------
    s = []
    s.append("## IaC Scan (Checkov)\n")
    s.append(f"- **Passed:** {passed} ({pct(passed)})")
    s.append(f"- **Failed:** {failed} ({pct(failed)})")
    s.append(f"- **Skipped:** {skipped} ({pct(skipped)})")
    s.append(f"- **Fail threshold:** `{fail_on}` and above ({breaches} breaching)")
    s.append(f"- **Unrated checks default to:** `{args.default_severity}`")
    for err in tool_errors:
        s.append(f"- **Scanner error (gate fails closed):** {md_cell(err)}")
    s.append("")
    if failed_checks:
        s.append("### Failed checks\n")
        s.append("| Check | Severity | Resource | File | Description |")
        s.append("|---|---|---|---|---|")
        for c in failed_checks[:25]:
            guideline_link = (
                f"[link]({md_link_url(c['guideline'])})" if c['guideline'] else ""
            )
            s.append(
                f"| `{md_cell(c['id'])}` | {md_cell(c['severity'])} | "
                f"`{md_cell(c['resource'])}` | `{md_cell(c['file'])}` | "
                f"{md_cell(c['name'])} {guideline_link} |"
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
    for err in tool_errors:
        c_lines.append(f"\n**Scanner error (gate fails closed):** {md_cell(err)}")
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
                f"| `{md_cell(c['id'])}` | {md_cell(c['severity'])} | "
                f"`{md_cell(c['resource'])}` |"
            )
    if framework_hits:
        c_lines.append("")
        c_lines.append("**Compliance frameworks affected:**")
        c_lines.append("")
        c_lines.append("| Framework | Failing checks |")
        c_lines.append("|---|---|")
        for fw, n in sorted(framework_hits.items(), key=lambda kv: -kv[1])[:5]:
            c_lines.append(f"| {fw} | {n} |")
    comment_md = "\n".join(c_lines) + "\n"

    Path(args.summary_out).write_text(summary_md)
    Path(args.comment_out).write_text(comment_md)
    Path(args.counts_out).write_text(
        json.dumps({**counts, "breaches": breaches,
                    "passed": passed, "failed": failed, "skipped": skipped,
                    "tool_errors": len(tool_errors)},
                   indent=2)
    )

    if args.sarif_in:
        sarif_path = Path(args.sarif_in)
        if sarif_path.exists():
            try:
                sarif_data = json.loads(sarif_path.read_text())
                for run in sarif_data.get("runs", []):
                    # Filter out suppressed results so GitHub Code Scanning closes them
                    if "results" in run:
                        run["results"] = [
                            res for res in run["results"]
                            if not res.get("suppressions")
                        ]

                    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
                    for rule in rules:
                        rule_id = rule.get("id")
                        sev = check_severities.get(
                            rule_id, severity_map.get(rule_id, args.default_severity)
                        )
                        sev_map = {"critical": "9.0", "high": "7.0", "medium": "5.0", "low": "2.0"}
                        score = sev_map.get(sev, "5.0")
                        if "properties" not in rule:
                            rule["properties"] = {}
                        rule["properties"]["security-severity"] = score
                        rule["properties"]["tags"] = ["security", sev.upper()]
                sarif_path.write_text(json.dumps(sarif_data, indent=2))
            except Exception as e:
                print(f"Failed to patch SARIF: {e}", file=sys.stderr)

    print(
        f"Checkov: passed={passed} failed={failed} skipped={skipped} "
        f"breaches@{fail_on}={breaches}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
