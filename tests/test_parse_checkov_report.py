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


def test_normalize_severity_unrated_fails_closed(checkov):
    # Checkov OSS gives no severity; unrated checks default to `high` so they
    # can't slip under the default gate threshold.
    assert checkov.normalize_severity({}) == "high"
    assert checkov.normalize_severity({"severity": None}) == "high"
    assert checkov.normalize_severity({"severity": "WEIRD"}) == "high"
    assert checkov.normalize_severity({}, default="medium") == "medium"


def test_normalize_severity_uses_policy_map(checkov):
    sev_map = {"CKV_AWS_23": "low"}
    assert checkov.normalize_severity({"check_id": "CKV_AWS_23"}, sev_map) == "low"
    # Checkov's own rating (e.g. with a Prisma key) still wins.
    assert (
        checkov.normalize_severity({"check_id": "CKV_AWS_23", "severity": "HIGH"}, sev_map)
        == "high"
    )


def test_builtin_policy_loads(checkov):
    severities, compliance = checkov.load_policy([str(checkov.DEFAULT_POLICY)])
    assert severities["CKV_K8S_16"] == "critical"
    assert "CIS-4.1" in compliance["CKV_AWS_24"]


def test_caller_policy_overrides_builtin(checkov, tmp_path):
    override = tmp_path / "mine.json"
    override.write_text('{"severities": {"CKV_K8S_16": "low", "CKV_X": "bogus"}}')
    severities, _ = checkov.load_policy([str(checkov.DEFAULT_POLICY), str(override)])
    assert severities["CKV_K8S_16"] == "low"
    assert "CKV_X" not in severities


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


def _checkov_report(failed=None, passed=0, skipped=0):
    def _check(check_id, severity=None, **kw):
        return {
            "check_id": check_id,
            "check_name": kw.get("name", "a check"),
            "resource": kw.get("resource", "aws_s3_bucket.b"),
            "file_path": "/main.tf",
            "file_line_range": [3, 9],
            "severity": severity,
            "guideline": kw.get("guideline", "https://docs.example/g (1)"),
        }

    return [
        {
            "results": {
                "passed_checks": [_check(f"CKV_PASS_{i}") for i in range(passed)],
                "skipped_checks": [_check(f"CKV_SKIP_{i}") for i in range(skipped)],
                "failed_checks": [_check(cid, sev) for cid, sev in (failed or [])],
            }
        }
    ]


def _run_main(
    checkov, tmp_path, monkeypatch, report, fail_on="high", sarif=None, extra=()
):
    import json as _json

    report_path = tmp_path / "report.json"
    report_path.write_text(_json.dumps(report))
    argv = [
        "parse-checkov-report.py",
        "--report", str(report_path),
        "--fail-on", fail_on,
        "--summary-out", str(tmp_path / "summary.md"),
        "--comment-out", str(tmp_path / "comment.md"),
        "--counts-out", str(tmp_path / "counts.json"),
        *extra,
    ]
    if sarif is not None:
        sarif_path = tmp_path / "checkov.sarif"
        sarif_path.write_text(_json.dumps(sarif))
        argv += ["--sarif-in", str(sarif_path)]
    monkeypatch.setattr("sys.argv", argv)
    assert checkov.main() == 0
    return tmp_path


def test_main_counts_breaches_and_compliance(checkov, tmp_path, monkeypatch):
    import json

    out = _run_main(
        checkov,
        tmp_path,
        monkeypatch,
        _checkov_report(
            failed=[("CKV_AWS_24", "high"), ("CKV_AWS_19", None), ("CKV_X", "low")],
            # CKV_AWS_19 is unrated by Checkov; the built-in map says medium.
            passed=2,
            skipped=1,
        ),
    )
    counts = json.loads((out / "counts.json").read_text())
    assert counts == {
        "critical": 0, "high": 1, "medium": 1, "low": 1,
        "breaches": 1, "passed": 2, "failed": 3, "skipped": 1, "tool_errors": 0,
    }
    summary = (out / "summary.md").read_text()
    assert "Compliance frameworks affected" in summary
    assert "CIS-4.1" in summary  # CKV_AWS_24 mapping
    assert "%28" in summary  # guideline URL parens escaped
    comment = (out / "comment.md").read_text()
    assert "Top failing checks" in comment


def test_main_sarif_patched_with_security_severity(checkov, tmp_path, monkeypatch):
    import json

    sarif = {
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "CKV_AWS_24"}, {"id": "CKV_NEW"}]}},
                "results": [
                    {"ruleId": "CKV_AWS_24"},
                    {"ruleId": "CKV_SKIP_0", "suppressions": [{"kind": "external"}]},
                ],
            }
        ]
    }
    out = _run_main(
        checkov,
        tmp_path,
        monkeypatch,
        _checkov_report(failed=[("CKV_AWS_24", "critical")]),
        sarif=sarif,
    )
    patched = json.loads((out / "checkov.sarif").read_text())
    run = patched["runs"][0]
    # Suppressed results are removed so GitHub closes those alerts.
    assert [r["ruleId"] for r in run["results"]] == ["CKV_AWS_24"]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert rules["CKV_AWS_24"]["properties"]["security-severity"] == "9.0"
    # Rules with no observed or mapped severity get the (high) default.
    assert rules["CKV_NEW"]["properties"]["security-severity"] == "7.0"


def test_main_empty_report_writes_zero_counts(checkov, tmp_path, monkeypatch):
    import json

    out = _run_main(checkov, tmp_path, monkeypatch, [], fail_on="low")
    counts = json.loads((out / "counts.json").read_text())
    assert counts["breaches"] == 0
    assert counts["failed"] == 0


def test_main_corrupt_sarif_fails_open(checkov, tmp_path, monkeypatch, capsys):
    import json as _json

    report_path = tmp_path / "report.json"
    report_path.write_text(_json.dumps(_checkov_report(failed=[("CKV_AWS_24", "high")])))
    sarif_path = tmp_path / "checkov.sarif"
    sarif_path.write_text("{not valid json")
    monkeypatch.setattr(
        "sys.argv",
        [
            "parse-checkov-report.py",
            "--report", str(report_path),
            "--fail-on", "high",
            "--summary-out", str(tmp_path / "summary.md"),
            "--comment-out", str(tmp_path / "comment.md"),
            "--counts-out", str(tmp_path / "counts.json"),
            "--sarif-in", str(sarif_path),
        ],
    )
    # Fail-open by design: a bad SARIF must not kill the reporting step.
    assert checkov.main() == 0
    assert "Failed to patch SARIF" in capsys.readouterr().err
    assert sarif_path.read_text() == "{not valid json"
    assert (tmp_path / "counts.json").exists()


def test_comment_includes_compliance_table(checkov, tmp_path, monkeypatch):
    out = _run_main(
        checkov,
        tmp_path,
        monkeypatch,
        _checkov_report(failed=[("CKV_AWS_24", "high"), ("CKV_AWS_19", "high")]),
    )
    comment = (out / "comment.md").read_text()
    assert "Compliance frameworks affected" in comment
    assert "CIS-4.1" in comment


def test_unrated_finding_blocks_at_default_threshold(checkov, tmp_path, monkeypatch):
    import json

    out = _run_main(
        checkov, tmp_path, monkeypatch, _checkov_report(failed=[("CKV_UNMAPPED", None)])
    )
    counts = json.loads((out / "counts.json").read_text())
    assert counts["high"] == 1 and counts["breaches"] == 1


def test_checkov_crash_is_tool_error(checkov, tmp_path, monkeypatch):
    import json

    out = _run_main(
        checkov, tmp_path, monkeypatch, [], fail_on="critical", extra=("--checkov-exit", "2")
    )
    counts = json.loads((out / "counts.json").read_text())
    assert counts["tool_errors"] == 1
    assert counts["breaches"] == 1
    assert "Scanner error" in (out / "summary.md").read_text()


def test_real_checkov_oss_output(checkov, tmp_path, monkeypatch):
    # Captured from checkov 3.3.8 (OSS, no API key, --quiet) on a Terraform
    # file with world-open SSH and a public-read S3 bucket. Every check has
    # severity=None; before the policy map this all collapsed to "medium" and
    # never tripped the default `high` gate.
    import json
    from pathlib import Path

    report = json.loads(
        (Path(__file__).parent / "fixtures/real/checkov/vulnerable-terraform.json").read_text()
    )
    out = _run_main(checkov, tmp_path, monkeypatch, report)
    counts = json.loads((out / "counts.json").read_text())
    assert counts["critical"] == 1  # CKV_AWS_20 public-read bucket
    assert counts["high"] == 2  # CKV_AWS_24 open SSH, CKV2_AWS_6 no public-access block
    assert counts["breaches"] == 3
    assert counts["passed"] == 7  # from Checkov's summary block under --quiet
