"""Shared fixtures: import the hyphenated helper scripts as modules.

The scripts under ``scripts/`` are named with hyphens (``parse-trivy-report.py``)
so they can't be imported with a plain ``import``. We load them by path via
importlib and expose one module-level fixture per script.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"


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
