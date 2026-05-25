"""Minimal FastAPI service used as a scan target for the example pipeline.

Like the Node.js example, this is intentionally tiny — its only job is to
be a realistic Python app for pipeline-armor's reusable workflows to scan.
"""
from __future__ import annotations

import os

import structlog
from fastapi import FastAPI
from pydantic import BaseModel

log = structlog.get_logger("pipeline-armor-example")

app = FastAPI(title="pipeline-armor-example", version=os.environ.get("APP_VERSION", "dev"))


class HealthResponse(BaseModel):
    status: str


class VersionResponse(BaseModel):
    version: str
    python: str


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get("/version", response_model=VersionResponse)
def version() -> VersionResponse:
    import sys

    return VersionResponse(
        version=os.environ.get("APP_VERSION", "dev"),
        python=sys.version.split()[0],
    )
