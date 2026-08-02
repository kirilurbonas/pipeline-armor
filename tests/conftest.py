"""Shared fixtures: import the hyphenated helper scripts as modules.

The scripts under ``scripts/`` are named with hyphens (``parse-trivy-report.py``)
so they can't be imported with a plain ``import``. We load them by path via
importlib and expose one module-level fixture per script.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"

# The scripts do `import common` (resolved from their own directory when run
# as `python3 scripts/<name>.py`); make that work under importlib loading too.
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def _load(filename: str, modname: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(modname, SCRIPTS_DIR / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def trivy() -> ModuleType:
    return _load("parse-trivy-report.py", "parse_trivy_report")


@pytest.fixture(scope="session")
def checkov() -> ModuleType:
    return _load("parse-checkov-report.py", "parse_checkov_report")


@pytest.fixture(scope="session")
def sbom() -> ModuleType:
    return _load("generate-sbom-summary.py", "generate_sbom_summary")


@pytest.fixture(scope="session")
def deps() -> ModuleType:
    return _load("parse-dependency-report.py", "parse_dependency_report")


@pytest.fixture(scope="session")
def deploy_gate() -> ModuleType:
    return _load("evaluate-deploy-gate.py", "evaluate_deploy_gate")


@pytest.fixture(scope="session")
def sast() -> ModuleType:
    return _load("summarize-sast-findings.py", "summarize_sast_findings")


@pytest.fixture(scope="session")
def licenses() -> ModuleType:
    return _load("evaluate-licenses.py", "evaluate_licenses")


@pytest.fixture(scope="session")
def secrets() -> ModuleType:
    return _load("combine-secret-findings.py", "combine_secret_findings")


@pytest.fixture(scope="session")
def osv() -> ModuleType:
    return _load("parse-osv-report.py", "parse_osv_report")


@pytest.fixture(scope="session")
def currency() -> ModuleType:
    return _load("check-tool-currency.py", "check_tool_currency")
