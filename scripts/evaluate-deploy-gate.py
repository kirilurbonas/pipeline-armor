#!/usr/bin/env python3
"""Evaluate scan artifacts and compute a final deploy-gate decision."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITIES = ("critical", "high", "medium", "low")

SCAN_ARTIFACTS = {
    "sast": ("sast-reports", "sast-findings.json"),
    "container": ("container-scan-reports", "trivy-counts.json"),
    "iac": ("iac-scan-reports", "checkov-counts.json"),
    "secrets": ("secret-scan-reports", "secrets-summary.json"),
    "dependencies": ("dependency-reports", "dependency-summary.json"),
    "osv": ("osv-scan-reports", "osv-counts.json"),
}

ENV_POLICIES = {
    "dev": {"fail_on": {"critical"}},
    "staging": {"fail_on": {"high", "critical"}},
    "prod": {"fail_on": {"medium", "high", "critical"}},
}


def parse_policy_file(path: Path) -> dict[str, dict[str, set[str]]] | None:
    """Read `environments.<env>.fail_on` lists from severity-thresholds.yml.

    Deliberately a minimal, indentation-aware scanner instead of a YAML
    dependency: helper scripts are stdlib-only, and the only data the gate
    needs is a two-level nesting of scalar lists. Returns None when the file
    is missing, unparseable, or contains no usable environment policies —
    callers fall back to the built-in ENV_POLICIES.
    """
    try:
        text = path.read_text()
    except OSError:
        return None

    policies: dict[str, dict[str, set[str]]] = {}
    in_environments = False
    current_env: str | None = None
    collecting_fail_on = False

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()

        if indent == 0:
            in_environments = stripped == "environments:"
            current_env = None
            collecting_fail_on = False
        elif in_environments and indent == 2 and stripped.endswith(":"):
            current_env = stripped[:-1]
            collecting_fail_on = False
        elif in_environments and current_env and indent == 4:
            collecting_fail_on = stripped == "fail_on:"
        elif collecting_fail_on and current_env and indent == 6 and stripped.startswith("- "):
            sev = stripped[2:].strip().lower()
            if sev in SEVERITY_ORDER:
                policies.setdefault(current_env, {"fail_on": set()})["fail_on"].add(sev)

    return policies or None


def md_cell(value: Any) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "'")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def load_json(path: Path) -> Any | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def extract_counts(payload: Any) -> dict[str, int] | None:
    if not isinstance(payload, dict):
        return None

    raw_counts = payload.get("counts")
    if isinstance(raw_counts, dict):
        source = raw_counts
    else:
        source = payload

    counts: dict[str, int] = {}
    for sev in SEVERITIES:
        if sev not in source:
            return None
        try:
            counts[sev] = int(source.get(sev, 0))
        except (TypeError, ValueError):
            return None
    return counts


def locate_artifact(artifact_dir: Path, filename: str) -> tuple[Path | None, str | None]:
    direct = artifact_dir / filename
    if direct.exists():
        return direct, None

    matches = sorted(path for path in artifact_dir.rglob(filename) if path.is_file())
    if not matches:
        return direct, "missing"
    if len(matches) > 1:
        joined = ", ".join(str(path) for path in matches[:3])
        return None, f"Multiple matching artifacts found: {joined}"
    return matches[0], None


def evaluate_scan(
    scan: str, artifacts_dir: Path, fail_on: set[str]
) -> tuple[dict[str, Any], dict[str, int], int]:
    if scan not in SCAN_ARTIFACTS:
        return (
            {
                "scan": scan,
                "status": "unknown",
                "detail": "No artifact mapping is defined for this required scan.",
                "counts": {sev: 0 for sev in SEVERITIES},
            },
            {sev: 0 for sev in SEVERITIES},
            1,
        )

    dirname, filename = SCAN_ARTIFACTS[scan]
    path, locate_error = locate_artifact(artifacts_dir / dirname, filename)
    if locate_error:
        status = "missing" if locate_error == "missing" else "invalid"
        detail = (
            f"Missing artifact. Expected `{artifacts_dir / dirname / filename}`."
            if status == "missing"
            else locate_error
        )
        return (
            {
                "scan": scan,
                "status": status,
                "detail": detail,
                "counts": {sev: 0 for sev in SEVERITIES},
            },
            {sev: 0 for sev in SEVERITIES},
            1,
        )

    assert path is not None
    payload = load_json(path)
    if payload is None:
        return (
            {
                "scan": scan,
                "status": "unreadable",
                "detail": f"Unreadable artifact. Expected valid JSON at `{path}`.",
                "counts": {sev: 0 for sev in SEVERITIES},
            },
            {sev: 0 for sev in SEVERITIES},
            1,
        )

    counts = extract_counts(payload)
    if counts is None:
        return (
            {
                "scan": scan,
                "status": "invalid",
                "detail": f"Artifact `{path}` did not contain standardized severity counts.",
                "counts": {sev: 0 for sev in SEVERITIES},
            },
            {sev: 0 for sev in SEVERITIES},
            1,
        )

    tool_errors = 0
    try:
        tool_errors = int(payload.get("tool_errors", 0)) if isinstance(payload, dict) else 0
    except (TypeError, ValueError):
        tool_errors = 0

    breach_count = sum(counts[sev] for sev in SEVERITIES if sev in fail_on)
    detail = f"Artifact `{path}` evaluated successfully."
    status = "pass"
    if tool_errors > 0:
        status = "fail"
        detail = f"Artifact `{path}` reported {tool_errors} tool error(s)."
    elif breach_count > 0:
        status = "fail"
        detail = (
            f"{breach_count} finding(s) at or above the "
            f"environment threshold ({', '.join(sorted(fail_on))})."
        )

    return (
        {
            "scan": scan,
            "status": status,
            "detail": detail,
            "counts": counts,
            "tool_errors": tool_errors,
        },
        counts,
        0,
    )


def evaluate(
    required_scans: list[str],
    artifacts_dir: Path,
    environment: str,
    run_id: str,
    env_policies: dict[str, dict[str, set[str]]] | None = None,
) -> dict[str, Any]:
    policies = env_policies or ENV_POLICIES
    if environment not in policies:
        raise ValueError(f"Unsupported environment: {environment}")

    fail_on = policies[environment]["fail_on"]
    totals = {sev: 0 for sev in SEVERITIES}
    statuses: list[dict[str, Any]] = []
    evidence_failures = 0
    tool_errors = 0
    breaches = 0

    for scan in required_scans:
        status, counts, evidence_failure = evaluate_scan(scan, artifacts_dir, fail_on)
        statuses.append(status)
        evidence_failures += evidence_failure
        for sev in SEVERITIES:
            totals[sev] += counts[sev]
        tool_errors += int(status.get("tool_errors", 0))
        if status["status"] == "fail":
            breaches += sum(counts[sev] for sev in SEVERITIES if sev in fail_on)
            if int(status.get("tool_errors", 0)) > 0 and sum(
                counts[sev] for sev in SEVERITIES if sev in fail_on
            ) == 0:
                breaches += 1

    weights = {"critical": 10, "high": 4, "medium": 1, "low": 0.25}
    severity_penalty = sum(weights[sev] * totals[sev] for sev in SEVERITIES)
    evidence_penalty = 20 * evidence_failures
    score = max(0, int(round(100 - severity_penalty - evidence_penalty)))

    decision = "fail" if evidence_failures or breaches or tool_errors else "pass"
    return {
        "environment": environment,
        "decision": decision,
        "score": score,
        "totals": totals,
        "statuses": statuses,
        "policy": {"fail_on": sorted(fail_on)},
        "run_id": run_id,
        "evidence_failures": evidence_failures,
        "tool_errors": tool_errors,
        "breaches": breaches,
    }


def render_summary(report: dict[str, Any]) -> str:
    lines = [
        f"## Deploy Gate — `{report['environment']}`",
        "",
        f"**Decision:** {'PASS' if report['decision'] == 'pass' else 'FAIL'}",
        f"**Security score:** {report['score']}/100",
        f"**Policy:** fail on `{', '.join(report['policy']['fail_on'])}`",
        f"**Evidence failures:** {report['evidence_failures']}",
        "",
        "### Scan results",
        "",
        "| Scan | Status | Critical | High | Medium | Low | Detail |",
        "|---|---|---|---|---|---|---|",
    ]
    for status in report["statuses"]:
        counts = status["counts"]
        lines.append(
            f"| {md_cell(status['scan'])} | {md_cell(status['status'])} | "
            f"{counts['critical']} | {counts['high']} | {counts['medium']} | "
            f"{counts['low']} | {md_cell(status.get('detail', ''))} |"
        )
    lines.append("")
    lines.append(f"**Totals:** {report['totals']}")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--required-scans", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--summary-out", required=True)
    parser.add_argument("--report-out", required=True)
    parser.add_argument(
        "--policy-file",
        default=None,
        help="Optional severity-thresholds.yml; overrides built-in environment "
        "policies when readable, falls back to built-ins otherwise.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    required_scans = [scan.strip() for scan in args.required_scans.split(",") if scan.strip()]

    env_policies = None
    policy_source = "built-in"
    if args.policy_file:
        env_policies = parse_policy_file(Path(args.policy_file))
        if env_policies is not None:
            policy_source = args.policy_file
        else:
            print(
                f"Warning: could not read environment policies from "
                f"{args.policy_file}; using built-in defaults."
            )

    report = evaluate(
        required_scans,
        Path(args.artifacts_dir),
        args.environment,
        args.run_id,
        env_policies=env_policies,
    )
    report["policy"]["source"] = policy_source
    Path(args.report_out).write_text(json.dumps(report, indent=2))
    Path(args.summary_out).write_text(render_summary(report))
    print(
        f"Deploy gate: decision={report['decision']} score={report['score']} "
        f"evidence_failures={report['evidence_failures']} breaches={report['breaches']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
