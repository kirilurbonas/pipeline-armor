#!/usr/bin/env python3
"""Combine, deduplicate, and render Gitleaks + Trufflehog secret findings.

Per policy, the secret value itself is NEVER emitted — only the rule that
fired, file:line, and scanner metadata. Verified findings (confirmed live by
Trufflehog against the provider) count as critical; unverified findings
(regex hits) count as high, so the deploy gate blocks them in staging/prod
while dev only warns. Scanner failures are reported as ``tool_errors`` so a
crashed scanner can never look like a clean scan.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from common import md_cell

# Gitleaks exits 1 when it finds leaks; Trufflehog exits 0 unless it crashes
# (we don't pass --fail). Anything else means the scan did not complete.
OK_EXIT_CODES = {"gitleaks": {0, 1}, "trufflehog": {0}}


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
        # `trufflehog git` reports under Data.Git; `filesystem` under
        # Data.Filesystem. Accept either.
        fs = src.get("Git") or src.get("Filesystem") or {}
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
    """Collapse findings at the same file:line, across scanners.

    Gitleaks and Trufflehog name rules differently, so keying on the rule
    double-counted every secret both tools found. A verified finding wins
    over an unverified one at the same location.
    """
    by_location: dict[tuple[Any, Any], dict[str, Any]] = {}
    for f in findings:
        key = (f["file"], f["line"])
        current = by_location.get(key)
        if current is None or (f["verified"] and not current["verified"]):
            by_location[key] = f
    return list(by_location.values())


def tool_errors(exit_codes: dict[str, str | None]) -> list[str]:
    errors = []
    for tool, code in exit_codes.items():
        if code is None or code == "":
            continue
        try:
            value = int(code)
        except ValueError:
            errors.append(f"{tool}: unparseable exit code {code!r}")
            continue
        if value not in OK_EXIT_CODES[tool]:
            errors.append(f"{tool}: exited with code {value}")
    return errors


def build_summary_json(
    deduped: list[dict[str, Any]], errors: list[str] | None = None
) -> dict[str, Any]:
    verified = [f for f in deduped if f["verified"]]
    unverified = [f for f in deduped if not f["verified"]]
    errors = errors or []
    return {
        "total": len(deduped),
        "verified": len(verified),
        "unverified": len(unverified),
        "counts": {
            "critical": len(verified),
            "high": len(unverified),
            "medium": 0,
            "low": 0,
        },
        "breaches": len(verified),
        "tool_errors": len(errors),
        "errors": errors,
        "findings": deduped,
    }


def build_sarif(deduped: list[dict[str, Any]]) -> dict[str, Any]:
    """SARIF for the Security tab. Carries rule + location only — never the
    secret value."""
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in deduped:
        rule_id = f"{f['source']}/{f['rule']}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": str(f["rule"]),
                "shortDescription": {"text": f"Secret detected: {f['secret_type']}"},
                "properties": {"tags": ["security", "secret"]},
            },
        )
        line = f["line"] if isinstance(f["line"], int) and f["line"] > 0 else 1
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {
                    "text": (
                        f"{'Verified live' if f['verified'] else 'Possible'} "
                        f"{f['secret_type']} secret. Rotate it and remove it from history."
                    )
                },
                "properties": {"security-severity": "9.5" if f["verified"] else "7.5"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(f["file"])},
                            "region": {"startLine": line},
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pipeline-armor-secrets",
                        "informationUri": "https://github.com/kirilurbonas/pipeline-armor",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def render_markdown(summary: dict[str, Any], baseline_file: str) -> str:
    deduped = summary["findings"]
    lines = ["## Secret Scan Results", ""]
    lines.append(f"- **Total findings:** {summary['total']}")
    lines.append(f"- **Verified (live):** {summary['verified']}")
    lines.append(f"- **Unverified:** {summary['unverified']}")
    lines.append(
        "- **Gate behavior:** verified findings count as critical; unverified "
        "findings count as high (the deploy gate blocks them in staging/prod)."
    )
    for err in summary.get("errors", []):
        lines.append(f"- **Scanner error (gate fails closed):** {md_cell(err)}")
    lines.append("")
    if deduped:
        lines.append("| Scanner | Rule | Type | File | Line | Verified |")
        lines.append("|---|---|---|---|---|---|")
        for f in deduped[:50]:
            v = "yes" if f["verified"] else "no"
            lines.append(
                f"| {md_cell(f['source'])} | `{md_cell(f['rule'])}` | "
                f"{md_cell(f['secret_type'])} | `{md_cell(f['file'])}` | "
                f"{md_cell(f['line'])} | {v} |"
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
    parser.add_argument("--sarif-out", default=None)
    parser.add_argument("--gitleaks-exit", default=None)
    parser.add_argument("--trufflehog-exit", default=None)
    return parser


def main() -> int:
    args = build_parser().parse_args()

    findings = normalize_gitleaks(load_report(Path(args.gitleaks_report)))
    findings += normalize_trufflehog(load_report(Path(args.trufflehog_report)))
    deduped = dedupe(findings)
    errors = tool_errors(
        {"gitleaks": args.gitleaks_exit, "trufflehog": args.trufflehog_exit}
    )

    summary = build_summary_json(deduped, errors)
    Path(args.summary_json_out).write_text(json.dumps(summary, indent=2))
    Path(args.summary_md_out).write_text(render_markdown(summary, args.baseline_file))
    if args.sarif_out:
        Path(args.sarif_out).write_text(json.dumps(build_sarif(deduped), indent=2))

    with Path(args.outputs_out).open("a") as out:
        out.write(f"verified={summary['verified']}\n")
        out.write(f"unverified={summary['unverified']}\n")
        out.write(f"tool_errors={summary['tool_errors']}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
