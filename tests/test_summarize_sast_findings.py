"""Unit tests for scripts/summarize-sast-findings.py."""
from __future__ import annotations

import json


def _sarif(results: list[dict]) -> dict:
    return {"runs": [{"results": results}]}


def _result(level: str | None = None, security_severity: str | None = None, **kw) -> dict:
    result = {
        "ruleId": kw.get("rule", "rule-1"),
        "message": {"text": kw.get("message", "a finding")},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": kw.get("uri", "src/app.py")},
                    "region": {"startLine": kw.get("line", 3)},
                }
            }
        ],
    }
    if level is not None:
        result["level"] = level
    if security_severity is not None:
        result["properties"] = {"security-severity": security_severity}
    return result


def test_normalize_severity_mappings(sast):
    assert sast.normalize_severity("error") == "high"
    assert sast.normalize_severity("WARNING") == "medium"
    assert sast.normalize_severity("note") == "low"
    assert sast.normalize_severity("critical") == "critical"
    assert sast.normalize_severity(None) == "low"
    assert sast.normalize_severity("bogus") == "low"


def test_security_severity_property_wins_over_level(sast):
    findings = sast.extract_findings(
        _sarif([_result(level="warning", security_severity="critical")]), "snyk"
    )
    assert findings[0]["severity"] == "critical"


def test_extract_findings_location_and_truncation(sast):
    findings = sast.extract_findings(
        _sarif([_result(level="error", message="x" * 300)]), "semgrep"
    )
    assert findings[0]["location"] == "src/app.py:3"
    assert len(findings[0]["message"]) == 140
    assert findings[0]["tool"] == "semgrep"


def test_extract_findings_tolerates_malformed_sarif(sast):
    assert sast.extract_findings(None, "snyk") == []
    assert sast.extract_findings([], "snyk") == []
    assert sast.extract_findings({"runs": None}, "snyk") == []


def test_count_breaches_respects_threshold(sast):
    counts = {"critical": 1, "high": 2, "medium": 3, "low": 4}
    assert sast.count_breaches(counts, "critical") == 1
    assert sast.count_breaches(counts, "high") == 3
    assert sast.count_breaches(counts, "low") == 10


def test_main_end_to_end(sast, tmp_path, monkeypatch):
    snyk = tmp_path / "snyk.sarif"
    snyk.write_text(json.dumps(_sarif([_result(level="error")])))
    semgrep = tmp_path / "semgrep.sarif"
    semgrep.write_text("not json")
    summary = tmp_path / "summary.md"
    outputs = tmp_path / "outputs.txt"
    findings_out = tmp_path / "sast-findings.json"
    breaches_out = tmp_path / "sast-breaches"

    monkeypatch.setattr(
        "sys.argv",
        [
            "summarize-sast-findings.py",
            "--snyk-sarif", str(snyk),
            "--semgrep-sarif", str(semgrep),
            "--fail-on", "HIGH",
            "--summary-out", str(summary),
            "--outputs-out", str(outputs),
            "--findings-out", str(findings_out),
            "--comment-out", str(tmp_path / "sast-comment.md"),
            "--breaches-out", str(breaches_out),
        ],
    )
    assert sast.main() == 0
    assert "## SAST Results" in summary.read_text()
    assert "high=1" in outputs.read_text()
    data = json.loads(findings_out.read_text())
    assert data["counts"]["high"] == 1
    assert breaches_out.read_text() == "1"


def test_main_with_missing_reports_writes_zero_breaches(sast, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "summarize-sast-findings.py",
            "--snyk-sarif", str(tmp_path / "missing1.sarif"),
            "--semgrep-sarif", str(tmp_path / "missing2.sarif"),
            "--fail-on", "low",
            "--summary-out", str(tmp_path / "summary.md"),
            "--outputs-out", str(tmp_path / "outputs.txt"),
            "--findings-out", str(tmp_path / "findings.json"),
            "--comment-out", str(tmp_path / "comment.md"),
            "--breaches-out", str(tmp_path / "breaches"),
        ],
    )
    assert sast.main() == 0
    assert (tmp_path / "breaches").read_text() == "0"
    assert "critical=0" in (tmp_path / "outputs.txt").read_text()


def test_numeric_security_severity_maps_to_cvss_bucket(sast):
    assert sast.normalize_severity("9.8") == "critical"
    assert sast.normalize_severity("7.5") == "high"
    assert sast.normalize_severity("5.0") == "medium"
    assert sast.normalize_severity("2.0") == "low"
    findings = sast.extract_findings(
        _sarif([_result(level="note", security_severity="9.1")]), "semgrep"
    )
    assert findings[0]["severity"] == "critical"


def test_rule_level_security_severity_is_used(sast):
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "sqli", "properties": {"security-severity": "8.2"}}
                        ]
                    }
                },
                "results": [_result(level="warning", rule="sqli")],
            }
        ]
    }
    assert sast.extract_findings(sarif, "semgrep")[0]["severity"] == "high"


def test_tool_errors(sast):
    assert sast.tool_errors("semgrep", None, False) == []
    assert sast.tool_errors("semgrep", "0", True) == []
    assert sast.tool_errors("semgrep", "1", True) == []
    assert sast.tool_errors("semgrep", "2", False) == ["semgrep: exited with code 2"]
    assert sast.tool_errors("semgrep", "0", False) == ["semgrep: produced no SARIF output"]
    assert sast.tool_errors("snyk", "3", False) == []
    assert sast.tool_errors("snyk", "2", True) == ["snyk: exited with code 2"]


def test_semgrep_failure_fails_closed(sast, tmp_path, monkeypatch):
    findings_out = tmp_path / "findings.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "summarize-sast-findings.py",
            "--snyk-sarif", str(tmp_path / "missing1.sarif"),
            "--semgrep-sarif", str(tmp_path / "missing2.sarif"),
            "--semgrep-exit", "2",
            "--fail-on", "critical",
            "--summary-out", str(tmp_path / "summary.md"),
            "--outputs-out", str(tmp_path / "outputs.txt"),
            "--findings-out", str(findings_out),
            "--comment-out", str(tmp_path / "comment.md"),
            "--breaches-out", str(tmp_path / "breaches"),
        ],
    )
    assert sast.main() == 0
    assert (tmp_path / "breaches").read_text() == "1"
    data = json.loads(findings_out.read_text())
    assert data["tool_errors"] == 1
    assert "Scanner errors" in (tmp_path / "summary.md").read_text()
    assert "exited with code 2" in (tmp_path / "comment.md").read_text()


def test_rule_default_level_used_when_result_has_no_level(sast):
    # Real Semgrep SARIF: results carry no `level`; it lives on the rule.
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "cmdi", "defaultConfiguration": {"level": "error"}}
                        ]
                    }
                },
                "results": [_result(rule="cmdi")],
            }
        ]
    }
    assert sast.extract_findings(sarif, "semgrep")[0]["severity"] == "high"


def test_rule_score_beats_result_level(sast):
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [{"id": "r", "properties": {"security-severity": "9.5"}}]
                    }
                },
                "results": [_result(level="warning", rule="r")],
            }
        ]
    }
    assert sast.extract_findings(sarif, "snyk")[0]["severity"] == "critical"


def test_real_semgrep_sarif_is_not_all_low(sast):
    # Captured from semgrep 1.172.0 (p/default p/secrets p/python) on a
    # deliberately vulnerable Flask handler.
    from pathlib import Path

    path = Path(__file__).parent / "fixtures/real/semgrep/vulnerable-python.sarif"
    findings = sast.extract_findings(json.loads(path.read_text()), "semgrep")
    counts = sast.count_by_severity(findings)
    assert counts["high"] >= 5
    assert counts["low"] == 0
