"""Unit tests for scripts/parse-dependency-report.py."""
from __future__ import annotations

import argparse
import json


def _args(**overrides):
    base = dict(
        fail_on="high",
        license_violations=0,
        github_review_failed=0,
        snyk_ran=0,
        snyk_report_present=0,
        snyk_exit_code=0,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_collect_vulnerabilities_recurses_nested_reports(deps):
    report = {
        "projects": [
            {
                "vulnerabilities": [
                    {
                        "id": "SNYK-1",
                        "packageName": "left-pad",
                        "version": "1.0.0",
                        "severity": "high",
                    }
                ]
            }
        ],
        "issues": {
            "vulnerabilities": [
                {
                    "issueId": "SNYK-2",
                    "package": "requests",
                    "versionFrom": "2.0.0",
                    "severity": "medium",
                }
            ]
        },
    }
    vulns = deps.collect_vulnerabilities(report)
    assert {(item["id"], item["severity"]) for item in vulns} == {
        ("SNYK-1", "high"),
        ("SNYK-2", "medium"),
    }


def test_render_summary_counts_policy_breaches_as_critical(deps):
    vulns = [
        {
            "id": "SNYK-1",
            "package": "pkg",
            "version": "1.0.0",
            "fixed": "2.0.0",
            "severity": "medium",
            "title": "issue",
        }
    ]
    _, comment, counts = deps.render_summary(
        _args(license_violations=2, github_review_failed=1), vulns
    )
    assert counts["critical"] == 3
    assert counts["medium"] == 1
    assert counts["breaches"] == 3
    assert "License policy violations" in comment


def test_render_summary_fails_closed_when_snyk_enabled_but_report_missing(deps):
    _, _, counts = deps.render_summary(
        _args(snyk_ran=1, snyk_report_present=0, snyk_exit_code=2), []
    )
    assert counts["critical"] == 1
    assert counts["tool_errors"] == 1
    assert counts["status"] == "fail"


def test_md_cell_escapes_table_breakers(deps):
    out = deps.md_cell("GPL|3`x\ny")
    assert out == "GPL\\|3'x y"


def test_main_writes_json_outputs(deps, tmp_path, monkeypatch):
    report = tmp_path / "snyk.json"
    report.write_text(json.dumps({"vulnerabilities": []}))
    summary = tmp_path / "summary.md"
    comment = tmp_path / "comment.md"
    counts = tmp_path / "counts.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "parse-dependency-report.py",
            "--snyk-report",
            str(report),
            "--fail-on",
            "high",
            "--summary-out",
            str(summary),
            "--comment-out",
            str(comment),
            "--counts-out",
            str(counts),
        ],
    )
    assert deps.main() == 0
    data = json.loads(counts.read_text())
    assert data["breaches"] == 0
    assert summary.exists()
    assert comment.exists()
