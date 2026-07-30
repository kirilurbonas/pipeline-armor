"""Unit tests for scripts/check-tool-currency.py (offline logic only)."""
from __future__ import annotations


def test_extract_pinned_versions_from_real_workflows(currency):
    """Every configured tool's regex must match the actual workflow files —
    this fails if a pin is renamed/moved without updating the checker."""
    from pathlib import Path

    workflows_dir = Path(__file__).resolve().parent.parent / ".github" / "workflows"
    for tool, filename, pattern, _kind, _ref in currency.TOOLS:
        pinned = currency.extract_pinned(workflows_dir, filename, pattern)
        assert pinned, f"pin for {tool} not found in {filename}"
        assert currency.parse_version(pinned), f"unparseable pin for {tool}: {pinned}"


def test_extract_pinned_missing_file(currency, tmp_path):
    assert currency.extract_pinned(tmp_path, "nope.yml", r"X: '([\d.]+)'") is None


def test_is_stale_semver_comparison(currency):
    assert currency.is_stale("1.2.3", "1.2.4") is True
    assert currency.is_stale("1.2.3", "1.10.0") is True  # not lexicographic
    assert currency.is_stale("1.10.0", "1.9.9") is False
    assert currency.is_stale("2.0.0", "2.0.0") is False


def test_is_stale_unparseable_falls_back_to_inequality(currency):
    assert currency.is_stale("abc", "def") is True
    assert currency.is_stale("abc", "abc") is False


def test_render_report_statuses(currency):
    rows = [
        {"tool": "a", "pinned": "1.0.0", "latest": "1.1.0", "stale": True},
        {"tool": "b", "pinned": "2.0.0", "latest": "2.0.0", "stale": False},
        {"tool": "c", "pinned": None, "latest": "1.0.0", "stale": False},
        {"tool": "d", "pinned": "1.0.0", "latest": None, "stale": False},
    ]
    report = currency.render_report(rows)
    assert "🔴 stale" in report
    assert "✅ current" in report
    assert "⚠️ pin not found" in report
    assert "⚠️ lookup failed" in report
