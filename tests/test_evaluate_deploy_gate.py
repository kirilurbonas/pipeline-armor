"""Unit tests for scripts/evaluate-deploy-gate.py."""
from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ALL_SCANS = ["sast", "container", "iac", "secrets", "dependencies"]


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


def test_blocking_fixture_fails_every_environment(deploy_gate):
    for env in ("dev", "staging", "prod"):
        report = deploy_gate.evaluate(ALL_SCANS, FIXTURES / "gate-blocking", env, "fx-1")
        assert report["decision"] == "fail", f"expected block in {env}"
        assert report["breaches"] > 0
        assert report["evidence_failures"] == 0


def test_passing_fixture_allows_every_environment(deploy_gate):
    for env in ("dev", "staging", "prod"):
        report = deploy_gate.evaluate(ALL_SCANS, FIXTURES / "gate-passing", env, "fx-2")
        assert report["decision"] == "pass", f"expected allow in {env}"
        assert report["breaches"] == 0
        assert report["score"] == 100


def test_prod_blocks_on_medium_but_dev_does_not(deploy_gate, tmp_path):
    _write_json(
        tmp_path,
        "container-scan-reports/trivy-counts.json",
        {"critical": 0, "high": 0, "medium": 2, "low": 0, "breaches": 0},
    )
    prod = deploy_gate.evaluate(["container"], tmp_path, "prod", "fx-3")
    dev = deploy_gate.evaluate(["container"], tmp_path, "dev", "fx-3")
    assert prod["decision"] == "fail"
    assert dev["decision"] == "pass"


def test_policy_file_parses_environments(deploy_gate):
    policy_file = (
        Path(__file__).resolve().parent.parent / "policies" / "severity-thresholds.yml"
    )
    policies = deploy_gate.parse_policy_file(policy_file)
    assert policies is not None
    assert set(policies) >= {"dev", "staging", "prod"}


def test_policy_file_matches_builtin_defaults(deploy_gate):
    """Drift detector: policies/severity-thresholds.yml and the built-in
    ENV_POLICIES are two statements of the same policy — they must agree."""
    policy_file = (
        Path(__file__).resolve().parent.parent / "policies" / "severity-thresholds.yml"
    )
    policies = deploy_gate.parse_policy_file(policy_file)
    assert policies is not None
    for env, policy in deploy_gate.ENV_POLICIES.items():
        assert policies[env]["fail_on"] == policy["fail_on"], f"drift in {env}"


def test_policy_file_missing_or_garbage_falls_back(deploy_gate, tmp_path):
    assert deploy_gate.parse_policy_file(tmp_path / "missing.yml") is None
    garbage = tmp_path / "garbage.yml"
    garbage.write_text("scanners:\n  sast:\n    fail_on_severity: high\n")
    assert deploy_gate.parse_policy_file(garbage) is None


def test_policy_file_overrides_evaluation(deploy_gate, tmp_path):
    # A custom policy that makes dev fail on medium.
    policy = tmp_path / "policy.yml"
    policy.write_text("environments:\n  dev:\n    fail_on:\n      - medium\n")
    _write_json(
        tmp_path,
        "container-scan-reports/trivy-counts.json",
        {"critical": 0, "high": 0, "medium": 1, "low": 0, "breaches": 0},
    )
    policies = deploy_gate.parse_policy_file(policy)
    report = deploy_gate.evaluate(
        ["container"], tmp_path, "dev", "run-p", env_policies=policies
    )
    assert report["decision"] == "fail"


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
