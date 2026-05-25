#!/usr/bin/env python3
"""Summarize a CycloneDX SBOM into a compact JSON object.

Trivy's CycloneDX output is faithful but bulky — each ``component`` has a
PURL, hashes, license expression, etc. For the PR comment we only need:

    * Total package count.
    * License distribution (top N).
    * A short list of components per ecosystem (PURL prefix).

Usage:
    generate-sbom-summary.py path/to/sbom.json > sbom-summary.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def normalize_license(component: dict) -> str:
    """CycloneDX licenses can be expressed several ways. We collapse to
    the first non-empty representation, falling back to 'UNKNOWN'."""
    licenses = component.get("licenses") or []
    for entry in licenses:
        if "expression" in entry and entry["expression"]:
            return entry["expression"]
        lic = entry.get("license") or {}
        if "id" in lic and lic["id"]:
            return lic["id"]
        if "name" in lic and lic["name"]:
            return lic["name"]
    return "UNKNOWN"


def purl_ecosystem(purl: str) -> str:
    # pkg:npm/foo@1.2.3 -> npm; pkg:pypi/foo@1.2.3 -> pypi; etc.
    if not purl or not purl.startswith("pkg:"):
        return "unknown"
    return purl.split(":", 1)[1].split("/", 1)[0]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("sbom", help="Path to a CycloneDX JSON SBOM.")
    args = p.parse_args()

    path = Path(args.sbom)
    if not path.exists() or path.stat().st_size == 0:
        json.dump({"package_count": 0, "license_distribution": {},
                   "ecosystem_distribution": {}}, sys.stdout)
        return 0

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        json.dump({"package_count": 0, "license_distribution": {},
                   "ecosystem_distribution": {}}, sys.stdout)
        return 0

    components = data.get("components") or []
    licenses = Counter(normalize_license(c) for c in components)
    ecosystems = Counter(purl_ecosystem(c.get("purl", "")) for c in components)

    summary = {
        "package_count": len(components),
        "license_distribution": dict(licenses.most_common(20)),
        "ecosystem_distribution": dict(ecosystems.most_common(20)),
    }
    json.dump(summary, sys.stdout, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
