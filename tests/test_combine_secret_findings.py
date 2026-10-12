"""Unit tests for scripts/combine-secret-findings.py."""
from __future__ import annotations

import json

SECRET_VALUE = "AKIAIOSFODNN7EXAMPLE-super-secret"  # noqa: S105 - synthetic test value


def _gitleaks_finding(file: str = "config.py", line: int = 12) -> dict:
    return {
        "RuleID": "aws-access-key",
        "File": file,
        "StartLine": line,
        "Description": "AWS access key",
        "Secret": SECRET_VALUE,
        "Match": SECRET_VALUE,
    }


def _trufflehog_finding(file: str = "config.py", line: int = 12, verified: bool = True) -> dict:
    return {
        "DetectorName": "AWS",
        "Verified": verified,
        "Raw": SECRET_VALUE,
        "SourceMetadata": {"Data": {"Filesystem": {"file": file, "line": line}}},
    }


def test_load_report_accepts_array_and_ndjson(secrets, tmp_path):
    array_path = tmp_path / "array.json"
    array_path.write_text(json.dumps([{"a": 1}, {"b": 2}]))
    assert len(secrets.load_report(array_path)) == 2

    ndjson_path = tmp_path / "nd.json"
    ndjson_path.write_text('{"a": 1}\n{"b": 2}\n')
    assert len(secrets.load_report(ndjson_path)) == 2


def test_load_report_tolerates_missing_and_malformed(secrets, tmp_path):
    assert secrets.load_report(tmp_path / "missing.json") == []
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert secrets.load_report(bad) == []


def test_dedupe_by_file_line_rule(secrets):
    findings = secrets.normalize_gitleaks([_gitleaks_finding(), _gitleaks_finding()])
    assert len(secrets.dedupe(findings)) == 1


def test_gitleaks_findings_are_always_unverified(secrets):
    findings = secrets.normalize_gitleaks([_gitleaks_finding()])
    assert findings[0]["verified"] is False


def test_verified_split_and_counts(secrets):
    deduped = secrets.dedupe(
        secrets.normalize_gitleaks([_gitleaks_finding(file="a.py")])
        + secrets.normalize_trufflehog([_trufflehog_finding(file="b.py", verified=True)])
    )
    summary = secrets.build_summary_json(deduped)
    assert summary["verified"] == 1
    assert summary["unverified"] == 1
    # Unverified regex hits are high: blocking in staging/prod, warning in dev.
    assert summary["counts"] == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert summary["breaches"] == 1


def test_secret_values_never_appear_in_outputs(secrets, tmp_path, monkeypatch):
    gl = tmp_path / "gitleaks-report.json"
    gl.write_text(json.dumps([_gitleaks_finding()]))
    th = tmp_path / "trufflehog-report.json"
    th.write_text(json.dumps(_trufflehog_finding()) + "\n")
    json_out = tmp_path / "secrets-summary.json"
    md_out = tmp_path / "secrets-summary.md"
    outputs = tmp_path / "outputs.txt"

    monkeypatch.setattr(
        "sys.argv",
        [
            "combine-secret-findings.py",
            "--gitleaks-report", str(gl),
            "--trufflehog-report", str(th),
            "--summary-json-out", str(json_out),
            "--summary-md-out", str(md_out),
            "--outputs-out", str(outputs),
            "--sarif-out", str(tmp_path / "secrets.sarif"),
        ],
    )
    assert secrets.main() == 0
    for path in (json_out, md_out, outputs, tmp_path / "secrets.sarif"):
        assert SECRET_VALUE not in path.read_text()
    assert "verified=1" in outputs.read_text()


def test_main_no_findings(secrets, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "combine-secret-findings.py",
            "--gitleaks-report", str(tmp_path / "gl.json"),
            "--trufflehog-report", str(tmp_path / "th.json"),
            "--summary-json-out", str(tmp_path / "s.json"),
            "--summary-md-out", str(tmp_path / "s.md"),
            "--outputs-out", str(tmp_path / "out.txt"),
        ],
    )
    assert secrets.main() == 0
    assert "_No secrets detected._" in (tmp_path / "s.md").read_text()
    assert json.loads((tmp_path / "s.json").read_text())["breaches"] == 0


def _trufflehog_git_finding(file: str, line: int, verified: bool = True) -> dict:
    return {
        "DetectorName": "Github",
        "Verified": verified,
        "Raw": SECRET_VALUE,
        "SourceMetadata": {
            "Data": {"Git": {"file": file, "line": line, "commit": "abc123"}}
        },
    }


def test_trufflehog_git_mode_metadata(secrets):
    findings = secrets.normalize_trufflehog([_trufflehog_git_finding("src/x.py", 4)])
    assert findings[0]["file"] == "src/x.py"
    assert findings[0]["line"] == 4


def test_dedupe_across_scanners_prefers_verified(secrets):
    # Same secret found by both tools: one finding, and it keeps the
    # verified status rather than double-counting.
    findings = secrets.normalize_gitleaks([_gitleaks_finding()]) + secrets.normalize_trufflehog(
        [_trufflehog_finding(verified=True)]
    )
    deduped = secrets.dedupe(findings)
    assert len(deduped) == 1
    assert deduped[0]["verified"] is True


def test_tool_errors(secrets):
    assert secrets.tool_errors({"gitleaks": "1", "trufflehog": "0"}) == []
    assert secrets.tool_errors({"gitleaks": None, "trufflehog": ""}) == []
    assert secrets.tool_errors({"gitleaks": "126", "trufflehog": "1"}) == [
        "gitleaks: exited with code 126",
        "trufflehog: exited with code 1",
    ]


def test_scanner_crash_reported_as_tool_error(secrets, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "combine-secret-findings.py",
            "--gitleaks-report", str(tmp_path / "gl.json"),
            "--trufflehog-report", str(tmp_path / "th.json"),
            "--summary-json-out", str(tmp_path / "s.json"),
            "--summary-md-out", str(tmp_path / "s.md"),
            "--outputs-out", str(tmp_path / "out.txt"),
            "--trufflehog-exit", "2",
        ],
    )
    assert secrets.main() == 0
    assert json.loads((tmp_path / "s.json").read_text())["tool_errors"] == 1
    assert "tool_errors=1" in (tmp_path / "out.txt").read_text()
    assert "Scanner error" in (tmp_path / "s.md").read_text()


def test_sarif_shape(secrets):
    deduped = secrets.normalize_trufflehog([_trufflehog_git_finding("a.py", 0)])
    sarif = secrets.build_sarif(deduped)
    result = sarif["runs"][0]["results"][0]
    assert result["properties"]["security-severity"] == "9.5"
    # SARIF requires startLine >= 1.
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
