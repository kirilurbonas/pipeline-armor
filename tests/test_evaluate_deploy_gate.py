"""Unit tests for scripts/evaluate-deploy-gate.py."""
from __future__ import annotations

import json
from pathlib import Path


def _write_json(root: Path, relative: str, payload: dict) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def test_missing_required_artifact_fails_closed(deploy_gate, tmp_path):
    report = deploy_gate.evaluate(["sast"], tmp_path, "prod", "123")
    assert report["decision"] == "fail"
    assert report["evidence_failures"] == 1
    assert report["statuses"][0]["status"] == "missing"


def test_staging_only_fails_on_high_and_above(deploy_gate, tmp_path):
    _write_json(
        tmp_path,
        "container-scan-reports/trivy-counts.json",
        {"critical": 0, "high": 0, "medium": 4, "low": 2, "breaches": 0},
    )
    report = deploy_gate.evaluate(["container"], tmp_path, "staging", "run-1")
    assert report["decision"] == "pass"
    assert report["totals"] == {"critical": 0, "high": 0, "medium": 4, "low": 2}


def test_nested_counts_payload_is_supported(deploy_gate, tmp_path):
    _write_json(
        tmp_path,
        "secret-scan-reports/secrets-summary.json",
        {
            "verified": 1,
            "counts": {"critical": 1, "high": 0, "medium": 0, "low": 3},
        },
    )
    report = deploy_gate.evaluate(["secrets"], tmp_path, "dev", "run-2")
    assert report["decision"] == "fail"
    assert report["breaches"] == 1
    assert report["statuses"][0]["status"] == "fail"


def test_nested_artifact_paths_are_supported(deploy_gate, tmp_path):
    _write_json(
        tmp_path,
        "dependency-reports/examples/nodejs-app/dependency-summary.json",
        {"critical": 0, "high": 0, "medium": 0, "low": 0, "breaches": 0},
    )
    report = deploy_gate.evaluate(["dependencies"], tmp_path, "prod", "run-nested")
    assert report["decision"] == "pass"
    assert report["statuses"][0]["status"] == "pass"


def test_unknown_required_scan_is_reported(deploy_gate, tmp_path):
    report = deploy_gate.evaluate(["custom-scan"], tmp_path, "prod", "run-3")
    assert report["decision"] == "fail"
    assert report["statuses"][0]["status"] == "unknown"


def test_main_writes_summary_and_report(deploy_gate, tmp_path, monkeypatch):
    _write_json(
        tmp_path,
        "dependency-reports/dependency-summary.json",
        {"critical": 0, "high": 0, "medium": 0, "low": 0, "breaches": 0},
    )
    summary = tmp_path / "summary.md"
    report_path = tmp_path / "report.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "evaluate-deploy-gate.py",
            "--artifacts-dir",
            str(tmp_path),
            "--environment",
            "prod",
            "--required-scans",
            "dependencies",
            "--run-id",
            "run-4",
            "--summary-out",
            str(summary),
            "--report-out",
            str(report_path),
        ],
    )
    assert deploy_gate.main() == 0
    data = json.loads(report_path.read_text())
    assert data["decision"] == "pass"
    assert "Deploy Gate" in summary.read_text()
