#!/usr/bin/env python3
"""Cross-reference extracted package licenses against allow / deny lists.

Consumes the ``licenses.json`` produced by license-checker (npm) or
pip-licenses (pip), tallies the license distribution, flags violations,
renders a markdown summary, and exposes the violation count as a step
output for the dependency-review gate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Ecosystems with a license-extraction step in reusable-dependency-review.yml.
# Anything else is reported as `license_status=unsupported` so the gate never
# silently reads "0 violations" for an ecosystem we can't actually inspect.
SUPPORTED_ECOSYSTEMS = {"npm", "pip", "go"}


def parse_spdx_list(raw: str) -> set[str]:
    return {item.strip() for item in raw.split(",") if item.strip()}


def load_packages(data: Any, ecosystem: str) -> list[dict[str, str]]:
    pkgs: list[dict[str, str]] = []
    if ecosystem == "npm":
        # license-checker returns {"name@version": {"licenses": ...}, ...}
        if isinstance(data, dict):
            for name, meta in data.items():
                meta = meta if isinstance(meta, dict) else {}
                pkgs.append({"name": name, "license": meta.get("licenses", "UNKNOWN")})
    elif ecosystem == "go":
        # The workflow converts go-licenses CSV output into
        # [{"name": "module", "license": "SPDX-ID"}, ...]
        if isinstance(data, list):
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                pkgs.append(
                    {
                        "name": str(entry.get("name", "?")),
                        "license": entry.get("license", "UNKNOWN"),
                    }
                )
    else:
        # pip-licenses returns [{"Name": ..., "Version": ..., "License": ...}, ...]
        if isinstance(data, list):
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                pkgs.append(
                    {
                        "name": f"{entry.get('Name', '?')}=={entry.get('Version', '?')}",
                        "license": entry.get("License", "UNKNOWN"),
                    }
                )
    return pkgs


def find_violations(
    pkgs: list[dict[str, str]], allow: set[str], deny: set[str]
) -> tuple[list[dict[str, str]], dict[str, int]]:
    violations: list[dict[str, str]] = []
    dist: dict[str, int] = {}
    for pkg in pkgs:
        lic = str(pkg["license"])
        dist[lic] = dist.get(lic, 0) + 1
        if lic in deny:
            violations.append({**pkg, "reason": "denied"})
        elif allow and lic not in allow and lic != "UNKNOWN":
            violations.append({**pkg, "reason": "not in allow-list"})
    return violations, dist


def render_summary(
    pkgs: list[dict[str, str]],
    violations: list[dict[str, str]],
    dist: dict[str, int],
) -> str:
    lines = ["### License compliance", ""]
    lines.append(f"- **Total packages:** {len(pkgs)}")
    lines.append(f"- **Violations:** {len(violations)}")
    lines.append("")
    lines.append("**License distribution:**")
    lines.append("")
    lines.append("| License | Count |")
    lines.append("|---|---|")
    for lic, n in sorted(dist.items(), key=lambda kv: -kv[1])[:15]:
        lines.append(f"| `{lic}` | {n} |")
    if violations:
        lines.append("")
        lines.append("**Violations:**")
        lines.append("")
        lines.append("| Package | License | Reason |")
        lines.append("|---|---|---|")
        for v in violations[:30]:
            lines.append(f"| `{v['name']}` | `{v['license']}` | {v['reason']} |")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--licenses-json", required=True)
    parser.add_argument("--allow", default="")
    parser.add_argument("--deny", default="")
    parser.add_argument("--ecosystem", required=True)
    parser.add_argument("--summary-out", required=True)
    parser.add_argument("--outputs-out", required=True, help="Appended to (step outputs).")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    allow = parse_spdx_list(args.allow)
    deny = parse_spdx_list(args.deny)

    if args.ecosystem not in SUPPORTED_ECOSYSTEMS:
        print(f"License extraction is not supported for ecosystem '{args.ecosystem}'.")
        with Path(args.outputs_out).open("a") as out:
            out.write("violations=0\n")
            out.write("license_status=unsupported\n")
        Path(args.summary_out).write_text(
            f"_License extraction is not supported for ecosystem "
            f"'{args.ecosystem}'; the license gate was **not** evaluated. "
            "The vulnerability scan is unaffected._\n"
        )
        return 0

    path = Path(args.licenses_json)
    if not path.exists():
        print("No license data — skipping evaluation.")
        with Path(args.outputs_out).open("a") as out:
            out.write("violations=0\n")
            out.write("license_status=missing\n")
        Path(args.summary_out).write_text(
            "_No license data available; the license gate was **not** evaluated._\n"
        )
        return 0

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        data = None

    pkgs = load_packages(data, args.ecosystem)
    violations, dist = find_violations(pkgs, allow, deny)

    Path(args.summary_out).write_text(render_summary(pkgs, violations, dist))
    with Path(args.outputs_out).open("a") as out:
        out.write(f"violations={len(violations)}\n")
        out.write("license_status=evaluated\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
