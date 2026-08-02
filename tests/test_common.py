"""Unit tests for scripts/common.py (shared parser helpers)."""
from __future__ import annotations

import json

import common


def test_severity_tables_are_consistent():
    assert set(common.SEVERITIES) == set(common.SEVERITY_ORDER)
    assert common.SEVERITY_ORDER_UPPER == {
        k.upper(): v for k, v in common.SEVERITY_ORDER.items()
    }
    assert common.SEVERITY_ORDER["critical"] > common.SEVERITY_ORDER["low"]


def test_md_cell_neutralises_table_breakers():
    assert common.md_cell("a|b`c\nd\re\\f") == "a\\|b'c d e\\\\f"
    assert common.md_cell(123) == "123"


def test_md_link_url_escapes():
    assert common.md_link_url("https://x/a b(c)") == "https://x/a%20b%28c%29"


def test_load_json_defaults(tmp_path):
    missing = tmp_path / "missing.json"
    assert common.load_json(missing) is None
    assert common.load_json(missing, default={}) == {}
    assert common.load_json(missing, default=[]) == []

    empty = tmp_path / "empty.json"
    empty.write_text("")
    assert common.load_json(empty, default={}) == {}

    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    assert common.load_json(bad, default=[]) == []

    good = tmp_path / "good.json"
    good.write_text(json.dumps({"a": 1}))
    assert common.load_json(good) == {"a": 1}
