"""Unit tests for scripts/parse-trivy-report.py."""
from __future__ import annotations

import argparse
import json


def test_load_json_missing_and_empty(trivy, tmp_path):
    assert trivy.load_json(str(tmp_path / "nope.json")) == {}
    empty = tmp_path / "empty.json"
    empty.write_text("")
    assert trivy.load_json(str(empty)) == {}


def test_load_json_malformed(trivy, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert trivy.load_json(str(bad)) == {}


def test_collect_vulns_flattens_results(trivy):
    report = {
        "Results": [
            {
                "Target": "os",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "PkgName": "p", "Severity": "high"},
                    {"VulnerabilityID": "CVE-2", "PkgName": "q"},  # no severity
                ],
            },
            {"Target": "lib", "Vulnerabilities": None},  # tolerated
        ]
    }
    vulns = trivy.collect_vulns(report)
    assert [v["id"] for v in vulns] == ["CVE-1", "CVE-2"]
    assert vulns[0]["severity"] == "HIGH"  # upper-cased
    assert vulns[1]["severity"] == "UNKNOWN"  # missing -> UNKNOWN


def test_severity_counts_ignores_unknown(trivy):
    items = [
        {"severity": "CRITICAL"},
        {"severity": "HIGH"},
        {"severity": "UNKNOWN"},  # not in the four buckets
    ]
    assert trivy.severity_counts(items) == {
        "critical": 1, "high": 1, "medium": 0, "low": 0
    }


def _args(**over):
    base = dict(
        image="app:test", build_duration="1", image_size_mb="2", fail_on="high",
    )
    base.update(over)
    return argparse.Namespace(**base)


def test_breaches_respect_threshold(trivy):
    vulns = [
        {"severity": "CRITICAL", "id": "a", "pkg": "p", "installed": "1",
         "fixed": "2", "title": ""},
        {"severity": "MEDIUM", "id": "b", "pkg": "q", "installed": "1",
         "fixed": "2", "title": ""},
    ]
    _, _, counts = trivy.render_summary(_args(fail_on="high"), vulns, [], {})
    # only CRITICAL is >= HIGH threshold
    assert counts["breaches"] == 1
    assert counts["total_vulns"] == 2


def test_breaches_unknown_fail_on_defaults_to_high(trivy):
    vulns = [
        {"severity": "HIGH", "id": "a", "pkg": "p", "installed": "1",
         "fixed": "2", "title": ""},
    ]
    _, _, counts = trivy.render_summary(_args(fail_on="bogus"), vulns, [], {})
    assert counts["breaches"] == 1  # HIGH >= default HIGH


def test_md_cell_escapes_table_breakers(trivy):
    out = trivy.md_cell("a|b`c\nd")
    assert "|" not in out.replace("\\|", "")  # only escaped pipes remain
    assert "`" not in out
    assert "\n" not in out


def test_render_output_is_valid_markdown_and_json(trivy):
    vulns = [
        {"severity": "CRITICAL", "id": "CVE|x", "pkg": "evil`pkg", "installed": "1",
         "fixed": "2", "title": "t"},
    ]
    summary, comment, counts = trivy.render_summary(_args(), vulns, [], {})
    # injection payload did not produce a raw pipe inside the value
    assert "CVE\\|x" in summary
    assert "CVE\\|x" in comment
    # counts is JSON-serialisable
    json.loads(json.dumps(counts))
