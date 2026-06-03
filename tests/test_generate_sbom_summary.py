"""Unit tests for scripts/generate-sbom-summary.py."""
from __future__ import annotations


def test_purl_ecosystem(sbom):
    assert sbom.purl_ecosystem("pkg:npm/foo@1.2.3") == "npm"
    assert sbom.purl_ecosystem("pkg:pypi/bar@2.0") == "pypi"
    assert sbom.purl_ecosystem("") == "unknown"
    assert sbom.purl_ecosystem("not-a-purl") == "unknown"


def test_normalize_license_prefers_expression(sbom):
    assert sbom.normalize_license(
        {"licenses": [{"expression": "MIT OR Apache-2.0"}]}
    ) == "MIT OR Apache-2.0"


def test_normalize_license_falls_back_to_id_then_name(sbom):
    assert sbom.normalize_license(
        {"licenses": [{"license": {"id": "MIT"}}]}
    ) == "MIT"
    assert sbom.normalize_license(
        {"licenses": [{"license": {"name": "Custom"}}]}
    ) == "Custom"


def test_normalize_license_unknown_when_absent(sbom):
    assert sbom.normalize_license({}) == "UNKNOWN"
    assert sbom.normalize_license({"licenses": []}) == "UNKNOWN"


def test_main_empty_file_produces_zero_summary(sbom, tmp_path, capsys, monkeypatch):
    import json

    empty = tmp_path / "empty.json"
    empty.write_text("")
    monkeypatch.setattr("sys.argv", ["generate-sbom-summary.py", str(empty)])
    assert sbom.main() == 0
    out = json.loads(capsys.readouterr().out)
    assert out["package_count"] == 0


def test_main_counts_components(sbom, tmp_path, capsys, monkeypatch):
    import json

    f = tmp_path / "sbom.json"
    f.write_text(json.dumps({"components": [
        {"purl": "pkg:npm/a@1", "licenses": [{"license": {"id": "MIT"}}]},
        {"purl": "pkg:npm/b@1", "licenses": [{"license": {"id": "MIT"}}]},
        {"purl": "pkg:pypi/c@1"},
    ]}))
    monkeypatch.setattr("sys.argv", ["generate-sbom-summary.py", str(f)])
    assert sbom.main() == 0
    out = json.loads(capsys.readouterr().out)
    assert out["package_count"] == 3
    assert out["ecosystem_distribution"] == {"npm": 2, "pypi": 1}
    assert out["license_distribution"]["MIT"] == 2
