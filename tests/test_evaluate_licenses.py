"""Unit tests for scripts/evaluate-licenses.py."""
from __future__ import annotations

import json


def test_parse_spdx_list(licenses):
    assert licenses.parse_spdx_list("MIT, Apache-2.0 ,,") == {"MIT", "Apache-2.0"}
    assert licenses.parse_spdx_list("") == set()


def test_load_packages_npm_shape(licenses):
    data = {"left-pad@1.0.0": {"licenses": "MIT"}, "weird@2.0.0": {}}
    pkgs = licenses.load_packages(data, "npm")
    assert {"name": "left-pad@1.0.0", "license": "MIT"} in pkgs
    assert {"name": "weird@2.0.0", "license": "UNKNOWN"} in pkgs


def test_load_packages_pip_shape(licenses):
    data = [{"Name": "fastapi", "Version": "0.100.0", "License": "MIT"}]
    pkgs = licenses.load_packages(data, "pip")
    assert pkgs == [{"name": "fastapi==0.100.0", "license": "MIT"}]


def test_load_packages_tolerates_malformed_data(licenses):
    assert licenses.load_packages(None, "npm") == []
    assert licenses.load_packages("garbage", "pip") == []
    assert licenses.load_packages([None, 4], "pip") == []


def test_deny_list_violation(licenses):
    pkgs = [{"name": "a", "license": "GPL-3.0"}, {"name": "b", "license": "MIT"}]
    violations, dist = licenses.find_violations(pkgs, set(), {"GPL-3.0"})
    assert len(violations) == 1
    assert violations[0]["reason"] == "denied"
    assert dist == {"GPL-3.0": 1, "MIT": 1}


def test_allow_list_violation_but_unknown_is_exempt(licenses):
    pkgs = [
        {"name": "a", "license": "MIT"},
        {"name": "b", "license": "BSD-3-Clause"},
        {"name": "c", "license": "UNKNOWN"},
    ]
    violations, _ = licenses.find_violations(pkgs, {"MIT"}, set())
    assert [v["name"] for v in violations] == ["b"]
    assert violations[0]["reason"] == "not in allow-list"


def test_load_packages_go_shape(licenses):
    data = [{"name": "github.com/pkg/errors", "license": "BSD-2-Clause"}, {"bogus": 1}]
    pkgs = licenses.load_packages(data, "go")
    assert pkgs[0] == {"name": "github.com/pkg/errors", "license": "BSD-2-Clause"}
    assert pkgs[1]["license"] == "UNKNOWN"


def test_main_unsupported_ecosystem_reports_status(licenses, tmp_path, monkeypatch):
    summary = tmp_path / "summary.md"
    outputs = tmp_path / "outputs.txt"
    monkeypatch.setattr(
        "sys.argv",
        [
            "evaluate-licenses.py",
            "--licenses-json", str(tmp_path / "licenses.json"),
            "--ecosystem", "maven",
            "--summary-out", str(summary),
            "--outputs-out", str(outputs),
        ],
    )
    assert licenses.main() == 0
    text = outputs.read_text()
    assert "violations=0" in text
    assert "license_status=unsupported" in text
    assert "not supported" in summary.read_text()


def test_main_missing_licenses_file(licenses, tmp_path, monkeypatch):
    summary = tmp_path / "summary.md"
    outputs = tmp_path / "outputs.txt"
    monkeypatch.setattr(
        "sys.argv",
        [
            "evaluate-licenses.py",
            "--licenses-json", str(tmp_path / "licenses.json"),
            "--ecosystem", "npm",
            "--summary-out", str(summary),
            "--outputs-out", str(outputs),
        ],
    )
    assert licenses.main() == 0
    assert outputs.read_text() == "violations=0\nlicense_status=missing\n"
    assert "No license data" in summary.read_text()


def test_main_end_to_end_npm(licenses, tmp_path, monkeypatch):
    licenses_json = tmp_path / "licenses.json"
    licenses_json.write_text(
        json.dumps({"a@1.0.0": {"licenses": "AGPL-3.0"}, "b@1.0.0": {"licenses": "MIT"}})
    )
    summary = tmp_path / "summary.md"
    outputs = tmp_path / "outputs.txt"
    monkeypatch.setattr(
        "sys.argv",
        [
            "evaluate-licenses.py",
            "--licenses-json", str(licenses_json),
            "--deny", "GPL-3.0,AGPL-3.0",
            "--ecosystem", "npm",
            "--summary-out", str(summary),
            "--outputs-out", str(outputs),
        ],
    )
    assert licenses.main() == 0
    assert "violations=1" in outputs.read_text()
    text = summary.read_text()
    assert "License compliance" in text
    assert "`a@1.0.0`" in text
