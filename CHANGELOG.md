# Changelog

All notable changes to pipeline-armor are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `parse-dependency-report.py` and `evaluate-deploy-gate.py` helper
  scripts, plus pytest coverage for both, to standardize dependency-scan
  artifacts and make deploy-gate evaluation independently testable.
- Repo-level Python and YAML lint configuration via `pyproject.toml` and
  `.yamllint.yml`.

### Changed

- Migrate all bundled actions off the deprecated Node 20 runtime ahead of
  GitHub forcing Node 24 on 2026-06-16: `actions/checkout@v5`,
  `actions/setup-python@v6`, `actions/upload-artifact@v7`,
  `actions/download-artifact@v8`, `actions/github-script@v8`,
  `github/codeql-action/upload-sarif@v4`. No input or behavior changes for
  consumers.
- Make `reusable-deploy-gate.yml` fail closed when required artifacts are
  missing or unreadable, and include that evidence state in the final
  score/report.
- Standardize dependency-review outputs into a machine-readable summary,
  treat denied licenses / failed dependency-review diffs as critical gate
  breaches, and add `working_directory` support for monorepos.
- Make reusable workflows that depend on helper scripts check out their
  own workflow source repository, so consumers in other repositories do
  not need to vendor `scripts/` manually.
- Model verified secrets as critical deploy-gate breaches and expand
  `ci-self-test.yml` to lint Python with Ruff and exercise the dependency
  and container helper paths directly.

## [1.0.1] — 2026-06-03

### Security

- Verify every third-party binary downloaded at runtime against a pinned
  SHA256 instead of trusting the transport: Gitleaks, Trufflehog, and the
  Snyk CLI now `sha256sum -c` the downloaded artifact and fail closed on a
  mismatch.
- Pin the Snyk CLI to a fixed release (`v1.1294.0`) rather than the
  mutable `latest` channel, in both the SAST and dependency-review
  workflows.
- Pin the Trivy bootstrap installer to its release tag (instead of the
  mutable `main` branch) so the script can't drift; it continues to
  sha256-verify the trivy binary itself.
- Escape Markdown table cells in `parse-trivy-report.py` and
  `parse-checkov-report.py` so scanner-supplied strings (package names,
  CVE titles, resource paths) can't break — or inject content into — the
  rendered PR comments and job summaries.

### Added

- `tests/` — a pytest unit suite for the three helper scripts, run in
  `ci-self-test.yml` alongside the existing smoke tests.

### Changed

- Harden the affected install steps with `set -euo pipefail`.
- Bump action pins to current majors: `actions/setup-node@v6`,
  `actions/setup-go@v6`, `actions/setup-java@v5`,
  `actions/dependency-review-action@v5`, `docker/setup-buildx-action@v4`.
- Example apps refreshed against Dependabot suggestions:
  Node.js (`express@^5.2.1`, `pino@^10.3.1`), Python
  (`fastapi==0.136.3`, `pydantic==2.13.4`, `structlog==25.5.0`),
  Terraform (`hashicorp/aws ~> 6.46`).

## [1.0.0] — 2026-05-25

Initial public release.

### Added

- Six reusable workflows covering SAST (Snyk Code + Semgrep), container
  scanning (Trivy), IaC scanning (Checkov), secret detection (Gitleaks +
  Trufflehog), dependency review (GitHub native + Snyk OSS + SPDX license
  enforcement), and a unified deploy gate with per-environment policy.
- `ci-self-test.yml` exercising every reusable workflow against the
  bundled example apps on each PR.
- Helper scripts: `parse-trivy-report.py`, `parse-checkov-report.py`,
  `generate-sbom-summary.py`.
- Example pipelines for Node.js (Express + distroless), Python (FastAPI +
  slim-bookworm), and Terraform (S3 + KMS, CIS-aligned).
- Documentation: getting-started, configuration reference, layered
  security-gate model, troubleshooting.
- Policy templates: `severity-thresholds.yml`, `allowed-licenses.yml`.
- Dependabot configuration covering Actions, npm, pip, and Terraform.
- `CODEOWNERS`, `SECURITY.md`, `CONTRIBUTING.md`.

[Unreleased]: https://github.com/kirilurbonas/pipeline-armor/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/kirilurbonas/pipeline-armor/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/kirilurbonas/pipeline-armor/releases/tag/v1.0.0
