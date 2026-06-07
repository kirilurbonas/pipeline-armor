"""Unit tests for scripts/parse-checkov-report.py."""
from __future__ import annotations


def test_load_report_normalizes_dict_to_list(checkov, tmp_path):
    f = tmp_path / "r.json"
    f.write_text('{"results": {"passed_checks": []}}')
    out = checkov.load_report(str(f))
    assert isinstance(out, list) and len(out) == 1


def test_load_report_passes_list_through(checkov, tmp_path):
    f = tmp_path / "r.json"
    f.write_text('[{"a": 1}, {"b": 2}]')
    assert checkov.load_report(str(f)) == [{"a": 1}, {"b": 2}]


def test_load_report_missing_empty_malformed(checkov, tmp_path):
    assert checkov.load_report(str(tmp_path / "nope.json")) == []
    empty = tmp_path / "e.json"
    empty.write_text("")
    assert checkov.load_report(str(empty)) == []
    bad = tmp_path / "b.json"
    bad.write_text("{nope")
    assert checkov.load_report(str(bad)) == []


def test_normalize_severity_defaults_to_medium(checkov):
    assert checkov.normalize_severity({}) == "medium"
    assert checkov.normalize_severity({"severity": None}) == "medium"
    assert checkov.normalize_severity({"severity": "WEIRD"}) == "medium"


def test_normalize_severity_reads_nested(checkov):
    assert checkov.normalize_severity({"severity": "HIGH"}) == "high"
    assert checkov.normalize_severity(
        {"check_result": {"severity": "critical"}}
    ) == "critical"


def test_md_cell_neutralises_breakers(checkov):
    out = checkov.md_cell("res|name`x\ny")
    assert out == "res\\|name'x y"


def test_md_link_url_escapes_parens(checkov):
    assert checkov.md_link_url("https://x/a(b)c d") == "https://x/a%28b%29c%20d"
