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
    assert summary["counts"] == {"critical": 1, "high": 0, "medium": 0, "low": 1}
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
        ],
    )
    assert secrets.main() == 0
    for path in (json_out, md_out, outputs):
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
