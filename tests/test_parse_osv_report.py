"""Unit tests for scripts/parse-osv-report.py."""
from __future__ import annotations

import json


def _report(packages: list[dict]) -> dict:
    return {"results": [{"source": {"path": "package-lock.json"}, "packages": packages}]}


def _package(
    name: str = "left-pad",
    vulns: list[dict] | None = None,
    groups: list[dict] | None = None,
) -> dict:
    return {
        "package": {"name": name, "version": "1.0.0", "ecosystem": "npm"},
        "groups": groups or [],
        "vulnerabilities": vulns or [],
    }


def test_cvss_to_bucket_thresholds(osv):
    assert osv.cvss_to_bucket("9.8") == "critical"
    assert osv.cvss_to_bucket(7.0) == "high"
    assert osv.cvss_to_bucket("4.0") == "medium"
    assert osv.cvss_to_bucket("3.7") == "low"
    assert osv.cvss_to_bucket("garbage") is None
    assert osv.cvss_to_bucket(None) is None


def test_textual_severity_wins_over_group_score(osv):
    findings = osv.collect_findings(
        _report(
            [
                _package(
                    vulns=[
                        {"id": "GHSA-1", "database_specific": {"severity": "CRITICAL"}}
                    ],
                    groups=[{"ids": ["GHSA-1"], "max_severity": "3.7"}],
                )
            ]
        )
    )
    assert findings[0]["severity"] == "critical"


def test_group_max_severity_used_when_no_text(osv):
    findings = osv.collect_findings(
        _report(
            [
                _package(
                    vulns=[{"id": "GHSA-2", "database_specific": {}}],
                    groups=[{"ids": ["GHSA-2"], "max_severity": "8.1"}],
                )
            ]
        )
    )
    assert findings[0]["severity"] == "high"


def test_no_severity_signal_defaults_low(osv):
    findings = osv.collect_findings(_report([_package(vulns=[{"id": "GHSA-3"}])]))
    assert findings[0]["severity"] == "low"


def test_collect_findings_tolerates_malformed_report(osv):
    assert osv.collect_findings(None) == []
    assert osv.collect_findings({"results": None}) == []
    assert osv.collect_findings({"results": [{"packages": [None]}]}) == []


def test_count_breaches_threshold(osv):
    counts = {"critical": 1, "high": 2, "medium": 0, "low": 5}
    assert osv.count_breaches(counts, "critical") == 1
    assert osv.count_breaches(counts, "high") == 3


def test_main_end_to_end(osv, tmp_path, monkeypatch):
    report = tmp_path / "osv.json"
    report.write_text(
        json.dumps(
            _report(
                [
                    _package(
                        vulns=[{"id": "GHSA-4", "summary": "bad", "database_specific": {}}],
                        groups=[{"ids": ["GHSA-4"], "max_severity": "9.9"}],
                    )
                ]
            )
        )
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "parse-osv-report.py",
            "--report", str(report),
            "--fail-on", "HIGH",
            "--scanner-exit-code", "1",
            "--summary-out", str(tmp_path / "s.md"),
            "--comment-out", str(tmp_path / "c.md"),
            "--counts-out", str(tmp_path / "k.json"),
        ],
    )
    assert osv.main() == 0
    counts = json.loads((tmp_path / "k.json").read_text())
    assert counts["critical"] == 1
    assert counts["breaches"] == 1
    assert counts["status"] == "fail"
    assert "OSV Vulnerability Scan" in (tmp_path / "s.md").read_text()


def test_main_tool_error_fails_closed(osv, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "parse-osv-report.py",
            "--report", str(tmp_path / "missing.json"),
            "--fail-on", "high",
            "--scanner-exit-code", "127",
            "--summary-out", str(tmp_path / "s.md"),
            "--comment-out", str(tmp_path / "c.md"),
            "--counts-out", str(tmp_path / "k.json"),
        ],
    )
    assert osv.main() == 0
    counts = json.loads((tmp_path / "k.json").read_text())
    assert counts["tool_errors"] == 1
    assert counts["status"] == "fail"


def test_main_clean_report(osv, tmp_path, monkeypatch):
    report = tmp_path / "osv.json"
    report.write_text(json.dumps({"results": []}))
    monkeypatch.setattr(
        "sys.argv",
        [
            "parse-osv-report.py",
            "--report", str(report),
            "--fail-on", "low",
            "--summary-out", str(tmp_path / "s.md"),
            "--comment-out", str(tmp_path / "c.md"),
            "--counts-out", str(tmp_path / "k.json"),
        ],
    )
    assert osv.main() == 0
    counts = json.loads((tmp_path / "k.json").read_text())
    assert counts["status"] == "pass"
    assert counts["breaches"] == 0
