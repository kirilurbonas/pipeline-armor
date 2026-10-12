# Changelog

All notable changes to pipeline-armor are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Theme: **truthful gates.** Several gates could report "pass" without
checking anything. Every fix below fails closed, so **upgrading may turn
previously-green pipelines red**. Each case is a real finding the gate
used to miss. See "IaC scan started failing after upgrading to 1.3" in
docs/troubleshooting.md.

### Fixed — gates that silently passed

- **Semgrep never ran.** `--config=auto` errors out under `--metrics=off`,
  and the exit code was never checked, so SAST without Snyk always reported
  0 findings. Semgrep now runs the `p/default`, `p/secrets` and
  per-language registry packs (override with the new `semgrep_config`
  input). Exit codes other than 0/1 are tool errors that fail the gate.
- **SAST severities collapsed to `low`.** Semgrep puts the SARIF `level`
  on the rule (`defaultConfiguration`), not on each result, so every
  Semgrep finding, injection included, was `low`. Numeric
  `security-severity` scores ("9.8") also mapped to `low`. Both now
  resolve correctly: numeric scores use CVSS buckets (shared with OSV via
  `common.cvss_to_bucket`), with result-then-rule precedence.
- **IaC findings never blocked.** Checkov OSS emits no severities, so every
  failure became `medium`, below the default `high` threshold. Checks are
  now rated from the new `policies/checkov-severity.json` (verified against
  Checkov 3.3.8's check list; caller overrides via `checkov_severity_map`).
  Unrated checks get `iac_default_severity` (default `high`). The map also
  fixes the compliance table's `CKV_K8S_8` entry (a liveness probe check,
  not privileged containers) and drops the removed `CKV_AWS_52`.
- **Secret scanning scanned the wrong thing.** Trufflehog ran
  `filesystem .` (working tree, `.git/` internals and the `.pipeline-armor`
  checkout) instead of git history. Gitleaks used the deprecated
  `detect`/`protect` commands, and `protect --staged` is meaningless in CI.
  Both now scan committed history, over the same commit range. `diff` also
  works on push events (via `github.event.before`); `staged` is a
  deprecated alias for `diff`.
- **Trufflehog Lob false positives** (the "6 verified secrets" on
  Dependabot PR #28). Lob's detector matches any 40-char `test_…` string,
  such as pytest function names, and its API then "verifies" them. Lob is
  now excluded by default via the new `trufflehog_exclude_detectors` input.
- **Unverified secrets never blocked the deploy gate.** They were rated
  `low`. They are now `high`: blocking in staging and prod, a warning in
  dev. Findings both scanners report at the same file:line are merged once
  (verified wins) instead of counted twice.
- **License gate largely ineffective.** Matching was exact-string, so
  `GPL-3.0` missed `GPL-3.0-only`/`-or-later` and every pip trove
  classifier ("GNU General Public License v3 (GPLv3)"). Licenses are now
  normalized to SPDX and matched on base id. `OR`/`AND`/`WITH`
  expressions, npm license arrays and pip `;` joins are understood.
  `UNKNOWN` now fails an allow-list unless `allow_unknown_licenses: true`.
- pip license extraction ran in the runner's own Python and counted the
  tooling as project dependencies. It now uses isolated venvs, and both
  `pip-licenses` (5.5.5) and `license-checker` (25.0.1) are pinned.
- IaC: `setup-python`'s `cache: pip` errored in caller repos without
  Python manifests (e.g. pure Terraform); removed.
- The IaC summary showed "Passed 0" under `--quiet`; totals now come from
  Checkov's own summary block.

### Added

- Scanner tool errors (`tool_errors` in the counts JSON) for SAST, IaC and
  secrets. The deploy gate already failed on them; now they are reported.
- `scanner-canary.yml`: runs SAST and IaC over deliberately vulnerable code
  in `canary/` on every PR and weekly, and fails if expected findings stop
  appearing. A broken scanner can no longer hide behind "0 findings".
- Real captured scanner outputs as test fixtures
  (`tests/fixtures/real/`: Semgrep SARIF, Checkov OSS JSON, pip-licenses
  JSON), alongside the synthetic ones.
- `secrets.sarif` (combined Gitleaks + Trufflehog, never containing secret
  values) in the `secret-scan-reports` artifact. Security-tab upload is
  deferred to v2, because requesting `security-events: write` would break
  existing callers.
- Deploy gate `policy_file` input: callers can supply their own policy,
  including custom environment names. An unreadable caller policy fails
  closed, and an unknown environment is now a clear error, not a traceback.
- IaC `sarif_upload` input.
- OSV gate fixtures; the gate-enforcement job now covers all six scans.

### Security

- Zizmor (second, independent Actions SAST) adopted and all findings
  fixed: every checkout now sets `persist-credentials: false` (except the
  release workflow's, which pushes the floating tag and is annotated as
  intentional), and ci-self-test / gate-negative-e2e drop workflow-level
  write permissions in favor of least-privilege per-job grants. A pinned
  `zizmor --offline` step in the lint job keeps it at zero findings.

### Changed

- New `upsert-pr-comment` composite action replaces the six near-identical
  inline github-script blocks that posted PR comments; reusable workflows
  reference it via the `.pipeline-armor` self-checkout (sparse-checkout now
  includes `.github/actions`). The SAST comment body moved from inline JS
  into `summarize-sast-findings.py --comment-out` (now with Markdown-cell
  escaping) for parity with the other parsers.

## [1.2.1] — 2026-08-06

### Security

- Fix all 16 semgrep `p/github-actions` findings: `${{ inputs.* }}` is no
  longer interpolated directly into `run:` shell or `github-script` JS in
  any reusable workflow — every input now flows through step `env:`
  variables (`"$FAIL_ON"`, `process.env.WORKDIR`, …). Exploitation
  required a caller passing untrusted event data into an input, but a
  security library should not ship the pattern its own SAST flags.
- New lint step runs semgrep `p/github-actions` (same pinned version as
  the SAST workflow) over `.github/workflows/` on every PR so the
  injection pattern cannot regress.
- `check-tool-currency.py` now hard-refuses non-https lookup URLs.

### Changed

- Refactor: new `scripts/common.py` is the single source of truth for the
  severity tables, Markdown-cell escaping, and the tolerant JSON loader
  that were previously copied (and already drifting) across six parser
  scripts. No behavior change; per-call-site defaults preserved.

## [1.2.0] — 2026-08-02

### Security

- Bump all scanner CLI pins to current upstream releases with fresh
  verified checksums: Gitleaks 8.21.2→8.30.1, Trufflehog 3.83.7→3.96.0,
  Trivy 0.71.0→0.72.0, Snyk 1.1294.0→1.1306.2, Semgrep 1.86.0→1.172.0,
  Checkov 3.2.334→3.3.8 (osv-scanner already current). Semgrep output
  flags modernized to `--sarif-output`/`--json-output`.

### Added

- `tool-currency.yml` + `check-tool-currency.py`: weekly staleness check
  for the curl/pip-installed scanner CLIs Dependabot can't see; opens or
  updates a single `tool-currency` tracking issue when pins fall behind
  and closes it when they're current again. A unit test asserts the
  checker's extraction regexes match the real workflow files, so moving a
  pin without updating the checker fails CI.
- Coverage floor in CI: pytest now runs with `--cov=scripts
  --cov-fail-under=80` (currently 87%); `parse-checkov-report.py` gained
  end-to-end tests for breach counting, compliance mapping, SARIF
  severity patching, and suppression filtering (23%→97%).
- `example-dependency-review-pip` self-test job exercising the pip
  license-extraction path against `examples/python-app`, wired into the
  E2E deploy gate.
- IaC framework matrix in the self-test: `example-iac-scan-dockerfile`
  (against the Node.js example's Dockerfile) and `example-iac-scan-k8s`
  against a new hardened `examples/k8s-manifests/` Deployment + Service
  pair — terraform, dockerfile, and kubernetes are now all exercised in
  CI (cloudformation remains supported but not self-tested, noted in
  docs).
- End-to-end `main()` tests for `parse-trivy-report.py` (65%→99%,
  covering misconfig tables, SBOM license distribution, and the
  dual-report misconfig merge) and mocked-network tests for
  `check-tool-currency.py` (51%→99%); a test documenting the Checkov
  SARIF-patch fail-open path. Total script coverage now 94%.

### Changed

- The Checkov PR comment now includes the "Compliance frameworks
  affected" table (top 5), previously visible only in the job summary.
- Docs truth pass: `configuration.md` pin example references a real tag,
  `getting-started.md` covers osv-scan, attest-sbom, and the full caller
  `permissions:` block, and the README quick-start now includes iac-scan
  and osv-scan wired into the deploy gate.

### Fixed

- Removed the `license-checker` devDependency from the Node.js example —
  the workflow fetches it via `npx --yes`, and its ancient dependency
  chain carried an unpatchable `brace-expansion` 1.x advisory
  (GHSA-mh99-v99m-4gvg).

## [1.1.0] — 2026-07-07

### Security

- Pin every third-party action in `.github/workflows/` to a full commit
  SHA (with a version comment), matching the hardening guidance this
  library gives its consumers. Dependabot keeps the pins current.
- Verify the Trivy download against a pinned SHA256 (previously the only
  runtime tool installed without checksum verification, via the upstream
  install.sh).
- Add a `Snyk pin consistency` lint step failing CI if the duplicated
  `SNYK_VERSION`/`SNYK_SHA256` pins in the SAST and dependency-review
  workflows ever drift apart.
- Add an OpenSSF Scorecard workflow (`scorecard.yml`) publishing results
  to the Security tab and scorecard.dev.

### Added

- `reusable-osv-scan.yml` + `parse-osv-report.py`: token-free full-tree
  dependency CVE scanning via OSV-Scanner (pinned, SHA256-verified binary)
  with SARIF upload, PR comment, and deploy-gate integration (`osv` scan
  id).
- Go license extraction (`google/go-licenses`) in the dependency review;
  the license gate now reports an explicit `unsupported` /
  `missing` / `evaluated` status instead of silently passing for
  ecosystems without extraction (maven).
- `fail_on_unverified` input on `reusable-secret-scan.yml`: opt-in
  blocking on unverified (e.g. Gitleaks-only) findings.
- The deploy gate now reads environment thresholds from
  `policies/severity-thresholds.yml` (`--policy-file`, with built-in
  fallback) — the policy file is enforcement, not documentation; a unit
  test fails CI if file and built-ins drift.
- `reusable-attest-sbom.yml`: signed attestation over the container-scan
  SBOM via `actions/attest-sbom`. A standalone opt-in workflow because
  GitHub validates called-workflow permissions at startup even for skipped
  jobs — an input on container-scan would have forced every caller to
  grant `id-token`/`attestations`.
- End-to-end deploy-gate coverage: `example-deploy-gate` in ci-self-test
  consumes the real example-scan artifacts, and `gate-negative-e2e.yml`
  (scheduled/dispatch) proves the reusable workflow blocks on bad
  fixtures at the workflow layer.
- `parse-dependency-report.py` and `evaluate-deploy-gate.py` helper
  scripts, plus pytest coverage for both, to standardize dependency-scan
  artifacts and make deploy-gate evaluation independently testable.
- Extract the remaining inline workflow Python into unit-tested helper
  scripts: `summarize-sast-findings.py` (SARIF summary + severity gate
  counts), `evaluate-licenses.py` (SPDX allow/deny evaluation), and
  `combine-secret-findings.py` (Gitleaks + Trufflehog merge/dedupe with a
  redaction guarantee) — with pytest suites for all three.
- Gate-enforcement fixtures (`tests/fixtures/gate-blocking`,
  `tests/fixtures/gate-passing`) and a `gate-enforcement` CI job that
  positively proves findings block the deploy gate and clean reports
  pass it.
- Release automation (`release.yml`): tagging `vX.Y.Z` creates a GitHub
  Release from the matching CHANGELOG section and force-moves the
  floating major tag.
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1); `SECURITY.md` now
  points to GitHub private vulnerability reporting.
- Repo-level Python and YAML lint configuration via `pyproject.toml` and
  `.yamllint.yml`.

### Changed

- Canonical default deny-list is now `GPL-3.0,AGPL-3.0,SSPL-1.0`,
  aligned across the workflow default, `policies/severity-thresholds.yml`,
  and docs.
- Migrate all bundled actions off the deprecated Node 20 runtime ahead of
  GitHub forcing Node 24 on 2026-06-16: `actions/checkout@v6`,
  `actions/setup-python@v6`, `actions/upload-artifact@v7`,
  `actions/download-artifact@v8`, `actions/github-script@v9`,
  `github/codeql-action/upload-sarif@v4`. No input or behavior changes for
  consumers.
- Document the secret-scan severity model (verified findings block;
  unverified findings — including all Gitleaks findings — are
  informational) as a known limitation in `docs/security-gates.md`, and
  clarify in the README that reusable workflows are consumed by
  reference, not via the GitHub Marketplace.
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

[Unreleased]: https://github.com/kirilurbonas/pipeline-armor/compare/v1.2.1...HEAD
[1.2.1]: https://github.com/kirilurbonas/pipeline-armor/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/kirilurbonas/pipeline-armor/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/kirilurbonas/pipeline-armor/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/kirilurbonas/pipeline-armor/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/kirilurbonas/pipeline-armor/releases/tag/v1.0.0
