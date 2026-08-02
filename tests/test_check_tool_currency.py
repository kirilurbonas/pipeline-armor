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


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        import json

        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_fetch_latest_github_strips_v_prefix(currency, monkeypatch):
    def fake_urlopen(request, timeout=30):
        assert "api.github.com/repos/o/r/releases/latest" in request.full_url
        return _FakeResponse({"tag_name": "v1.2.3"})

    monkeypatch.setattr(currency.urllib.request, "urlopen", fake_urlopen)
    assert currency.fetch_latest("github", "o/r") == "1.2.3"


def test_fetch_latest_github_sends_token(currency, monkeypatch):
    seen = {}

    def fake_urlopen(request, timeout=30):
        seen["auth"] = request.get_header("Authorization")
        return _FakeResponse({"tag_name": "v2.0.0"})

    monkeypatch.setattr(currency.urllib.request, "urlopen", fake_urlopen)
    assert currency.fetch_latest("github", "o/r", token="tok") == "2.0.0"
    assert seen["auth"] == "Bearer tok"


def test_fetch_latest_pypi(currency, monkeypatch):
    def fake_urlopen(request, timeout=30):
        assert "pypi.org/pypi/semgrep/json" in request.full_url
        return _FakeResponse({"info": {"version": "1.99.0"}})

    monkeypatch.setattr(currency.urllib.request, "urlopen", fake_urlopen)
    assert currency.fetch_latest("pypi", "semgrep") == "1.99.0"


def test_fetch_latest_failure_and_unknown_kind(currency, monkeypatch):
    def boom(request, timeout=30):
        raise OSError("network down")

    monkeypatch.setattr(currency.urllib.request, "urlopen", boom)
    assert currency.fetch_latest("github", "o/r") is None
    assert currency.fetch_latest("bogus", "x") is None


def test_main_end_to_end_with_mocked_fetch(currency, tmp_path, monkeypatch):
    # Pretend the first tool is stale and the rest are current.
    stale_tool = currency.TOOLS[0][0]

    def fake_fetch(kind, ref, token=None):
        for tool, _f, _p, k, r in currency.TOOLS:
            if (k, r) == (kind, ref):
                return "999.0.0" if tool == stale_tool else None
        return None

    monkeypatch.setattr(currency, "fetch_latest", fake_fetch)
    report = tmp_path / "report.md"
    outputs = tmp_path / "outputs.txt"
    monkeypatch.setattr(
        "sys.argv",
        [
            "check-tool-currency.py",
            "--workflows-dir", ".github/workflows",
            "--report-out", str(report),
            "--outputs-out", str(outputs),
        ],
    )
    assert currency.main() == 0
    assert "stale=1" in outputs.read_text()
    text = report.read_text()
    assert "🔴 stale" in text
    assert "⚠️ lookup failed" in text
