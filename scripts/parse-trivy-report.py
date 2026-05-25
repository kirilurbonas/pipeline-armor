#!/usr/bin/env python3
"""Parse a Trivy JSON report into a human-readable Markdown summary.

Trivy emits a deeply nested structure: one entry per scanned target
(OS layer, language ecosystem, config file), each with an arbitrary list of
``Vulnerabilities`` / ``Misconfigurations`` / ``Secrets``. This script
collapses the report into:

    * A per-severity tally suitable for the GitHub Actions job summary.
    * A short PR-comment-friendly Markdown block.
    * A machine-readable counts JSON file used by the deploy gate.

The script is intentionally tolerant of empty / malformed input so it
doesn't blow up the workflow if Trivy itself fails to write a report.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def load_json(path: str) -> Any:
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return {}
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}


def collect_vulns(report: dict) -> list[dict]:
    """Flatten Trivy's nested ``Results[].Vulnerabilities[]`` into a list."""
    out: list[dict] = []
    for res in report.get("Results", []) or []:
        target = res.get("Target", "?")
        for v in res.get("Vulnerabilities", []) or []:
            out.append(
                {
                    "target": target,
                    "id": v.get("VulnerabilityID", "?"),
                    "pkg": v.get("PkgName", "?"),
                    "installed": v.get("InstalledVersion", "?"),
                    "fixed": v.get("FixedVersion", "—"),
                    "severity": (v.get("Severity") or "UNKNOWN").upper(),
                    "title": (v.get("Title") or "").strip(),
                }
            )
    return out


def collect_misconfigs(report: dict) -> list[dict]:
    """Flatten Trivy config-scan misconfigurations."""
    out: list[dict] = []
    for res in report.get("Results", []) or []:
        for m in res.get("Misconfigurations", []) or []:
            out.append(
                {
                    "id": m.get("ID", "?"),
                    "title": m.get("Title", ""),
                    "severity": (m.get("Severity") or "UNKNOWN").upper(),
                    "message": (m.get("Message") or "")[:200],
                }
            )
    return out


def severity_counts(items: list[dict]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for it in items:
        sev = it["severity"].lower()
        if sev in out:
            out[sev] += 1
    return out


def render_summary(args: argparse.Namespace, vulns: list[dict],
                   misconfigs: list[dict], sbom: dict) -> tuple[str, str, dict]:
    counts = severity_counts(vulns)
    fail_on = args.fail_on.upper()
    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["HIGH"])
    breaches = sum(
        c for s, c in counts.items() if SEVERITY_ORDER[s.upper()] >= threshold
    )

    # Top 10 by severity, then by package name for stable ordering.
    top = sorted(
        vulns,
        key=lambda v: (-SEVERITY_ORDER.get(v["severity"], -1), v["pkg"]),
    )[:10]

    # ---- Job summary (longer, includes everything) -------------------------
    s = []
    s.append(f"## Container Scan — `{args.image}`\n")
    s.append(f"- **Build time:** {args.build_duration}s")
    s.append(f"- **Image size:** {args.image_size_mb} MB")
    s.append(f"- **Fail threshold:** `{fail_on}`")
    s.append("")
    s.append("| Severity | Count |")
    s.append("|---|---|")
    for sev in ("critical", "high", "medium", "low"):
        s.append(f"| {sev.title()} | {counts[sev]} |")
    s.append("")
    if top:
        s.append("### Top vulnerabilities\n")
        s.append("| CVE | Package | Installed | Fixed | Severity |")
        s.append("|---|---|---|---|---|")
        for v in top:
            s.append(
                f"| `{v['id']}` | `{v['pkg']}` | `{v['installed']}` | "
                f"`{v['fixed']}` | {v['severity']} |"
            )
        s.append("")
    if misconfigs:
        s.append("### Dockerfile misconfigurations\n")
        s.append("| ID | Severity | Title |")
        s.append("|---|---|---|")
        for m in misconfigs[:15]:
            s.append(f"| `{m['id']}` | {m['severity']} | {m['title']} |")
        s.append("")
    if sbom:
        s.append("### SBOM\n")
        s.append(f"- **Packages:** {sbom.get('package_count', 0)}")
        licenses = sbom.get("license_distribution", {}) or {}
        if licenses:
            s.append("- **Licenses:**")
            for lic, n in sorted(licenses.items(), key=lambda kv: -kv[1])[:10]:
                s.append(f"  - `{lic}`: {n}")
        s.append("")

    summary_md = "\n".join(s)

    # ---- PR comment (shorter) ----------------------------------------------
    c = []
    c.append(f"### Container Scan — `{args.image}`")
    c.append(
        f"Build: {args.build_duration}s · Size: {args.image_size_mb} MB · "
        f"Fail on: `{fail_on}`"
    )
    c.append("")
    c.append("| Critical | High | Medium | Low |")
    c.append("|---|---|---|---|")
    c.append(
        f"| {counts['critical']} | {counts['high']} | "
        f"{counts['medium']} | {counts['low']} |"
    )
    if top:
        c.append("")
        c.append("**Top vulnerabilities:**")
        c.append("")
        c.append("| CVE | Package | Fixed | Severity |")
        c.append("|---|---|---|---|")
        for v in top[:5]:
            c.append(
                f"| `{v['id']}` | `{v['pkg']}` | `{v['fixed']}` | {v['severity']} |"
            )
    comment_md = "\n".join(c) + "\n"

    counts_out = {
        **counts,
        "breaches": breaches,
        "total_vulns": len(vulns),
        "total_misconfigs": len(misconfigs),
    }
    return summary_md, comment_md, counts_out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", required=True, help="trivy-full.json")
    p.add_argument("--config-report", required=True, help="trivy-config.json")
    p.add_argument("--sbom-summary", required=True, help="sbom-summary.json")
    p.add_argument("--image", required=True)
    p.add_argument("--build-duration", required=True)
    p.add_argument("--image-size-mb", required=True)
    p.add_argument("--fail-on", required=True)
    p.add_argument("--summary-out", required=True)
    p.add_argument("--comment-out", required=True)
    p.add_argument("--counts-out", required=True)
    args = p.parse_args()

    report = load_json(args.report)
    cfg = load_json(args.config_report)
    sbom = load_json(args.sbom_summary)

    vulns = collect_vulns(report)
    misconfigs = collect_misconfigs(cfg) + collect_misconfigs(report)

    summary_md, comment_md, counts = render_summary(args, vulns, misconfigs, sbom)
    Path(args.summary_out).write_text(summary_md)
    Path(args.comment_out).write_text(comment_md)
    Path(args.counts_out).write_text(json.dumps(counts, indent=2))

    print(
        f"Vulnerabilities: {len(vulns)} (breaches at {args.fail_on}: {counts['breaches']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
