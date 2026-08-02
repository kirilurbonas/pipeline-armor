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


def _trivy_report(vulns=0, misconfigs=0, severity="HIGH"):
    return {
        "Results": [
            {
                "Target": "app (alpine 3.20)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": f"CVE-2026-{1000 + i}",
                        "PkgName": f"pkg{i}",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Severity": severity,
                        "Title": "a vuln | with `breakers`",
                    }
                    for i in range(vulns)
                ],
                "Misconfigurations": [
                    {
                        "ID": f"DS{i:03d}",
                        "Title": f"misconfig {i}",
                        "Severity": "MEDIUM",
                        "Message": "m" * 300,
                    }
                    for i in range(misconfigs)
                ],
            }
        ]
    }


def _run_main(trivy, tmp_path, monkeypatch, report, config=None, sbom=None, fail_on="HIGH"):
    import json

    paths = {}
    for name, payload in (
        ("report", report),
        ("config", config if config is not None else {}),
        ("sbom", sbom if sbom is not None else {}),
    ):
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(payload))
        paths[name] = p
    monkeypatch.setattr(
        "sys.argv",
        [
            "parse-trivy-report.py",
            "--report", str(paths["report"]),
            "--config-report", str(paths["config"]),
            "--sbom-summary", str(paths["sbom"]),
            "--image", "myapp:abc123",
            "--build-duration", "42",
            "--image-size-mb", "123.4",
            "--fail-on", fail_on,
            "--summary-out", str(tmp_path / "summary.md"),
            "--comment-out", str(tmp_path / "comment.md"),
            "--counts-out", str(tmp_path / "counts.json"),
        ],
    )
    assert trivy.main() == 0
    return tmp_path


def test_main_end_to_end_with_misconfigs_and_sbom(trivy, tmp_path, monkeypatch):
    import json

    sbom = {
        "package_count": 87,
        "license_distribution": {"MIT": 40, "Apache-2.0": 30, "ISC": 17},
    }
    out = _run_main(
        trivy,
        tmp_path,
        monkeypatch,
        report=_trivy_report(vulns=2, severity="CRITICAL"),
        config=_trivy_report(misconfigs=20),
        sbom=sbom,
    )
    counts = json.loads((out / "counts.json").read_text())
    assert counts["critical"] == 2
    assert counts["breaches"] == 2
    assert counts["total_misconfigs"] == 20
    summary = (out / "summary.md").read_text()
    assert "Dockerfile misconfigurations" in summary
    # [:15] truncation: 20 misconfigs but at most 15 table rows.
    assert summary.count("| `DS0") == 15
    assert "### SBOM" in summary
    assert "`MIT`: 40" in summary
    comment = (out / "comment.md").read_text()
    assert "Top vulnerabilities" in comment
    assert "`CVE-2026-1000`" in comment


def test_main_merges_misconfigs_from_both_reports(trivy, tmp_path, monkeypatch):
    import json

    out = _run_main(
        trivy,
        tmp_path,
        monkeypatch,
        report=_trivy_report(misconfigs=1),
        config=_trivy_report(misconfigs=2),
    )
    counts = json.loads((out / "counts.json").read_text())
    assert counts["total_misconfigs"] == 3


def test_main_empty_inputs_write_zero_counts(trivy, tmp_path, monkeypatch):
    import json

    out = _run_main(trivy, tmp_path, monkeypatch, report={}, fail_on="LOW")
    counts = json.loads((out / "counts.json").read_text())
    assert counts["breaches"] == 0
    assert counts["total_vulns"] == 0
    assert "Container Scan" in (out / "summary.md").read_text()
