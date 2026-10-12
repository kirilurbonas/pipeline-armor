# pipeline-armor

[![CI Self-Test](https://github.com/kirilurbonas/pipeline-armor/actions/workflows/ci-self-test.yml/badge.svg)](https://github.com/kirilurbonas/pipeline-armor/actions/workflows/ci-self-test.yml)
[![Scanner Canary](https://github.com/kirilurbonas/pipeline-armor/actions/workflows/scanner-canary.yml/badge.svg)](https://github.com/kirilurbonas/pipeline-armor/actions/workflows/scanner-canary.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/kirilurbonas/pipeline-armor/badge)](https://scorecard.dev/viewer/?uri=github.com/kirilurbonas/pipeline-armor)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)

**Production-grade reusable GitHub Actions workflows that bake security
gates into every stage of CI/CD — SAST, container scanning, IaC scanning,
secret detection, dependency review, SBOM generation, and a unified
deploy gate.**

Drop one file into your repo, call the workflows you need, and ship
faster *because* security is automated — not despite it.

---

## Why this exists

Most teams reinvent CI/CD security from scratch in every repository.
Each pipeline is slightly different, scanners are inconsistently
configured, and the deploy gate is a coin-flip of bash. `pipeline-armor`
is the opinionated, batteries-included alternative:

- **Reusable workflows** — your repo gets a tiny caller file; the heavy
  lifting lives here, versioned and tested.
- **Shift-left** — secrets, SAST, dependency CVEs, and IaC misconfigs
  all run on the PR, not after merge.
- **One gate** — a single deploy-gate job aggregates every scan, applies
  environment-specific policy, and either passes the build to your
  deploy step or blocks it with a detailed report.
- **Fail closed** — a scanner that crashes, exits oddly, or produces no
  report fails the gate. "0 findings" always means the scan ran and found
  nothing, and a [canary workflow](.github/workflows/scanner-canary.yml)
  proves the scanners still detect planted issues.
- **First-class GitHub integration** — SARIF uploads to the Security
  tab, PR comments via the API, manual approval via Environments.

## What's in the box

| Workflow | Purpose |
| --- | --- |
| [reusable-sast.yml](.github/workflows/reusable-sast.yml) | Snyk Code + Semgrep (`p/default`, `p/secrets`, per-language pack) with SARIF upload. |
| [reusable-container-scan.yml](.github/workflows/reusable-container-scan.yml) | Trivy image + Dockerfile config scan, CycloneDX SBOM. |
| [reusable-iac-scan.yml](.github/workflows/reusable-iac-scan.yml) | Checkov for Terraform/CloudFormation/Kubernetes/Dockerfile, with a [severity map](policies/checkov-severity.json) (Checkov OSS rates nothing) and CIS/SOC2/PCI-DSS mapping. |
| [reusable-secret-scan.yml](.github/workflows/reusable-secret-scan.yml) | Gitleaks + Trufflehog over git history, baseline-aware. Verified secrets are critical; unverified ones are high. |
| [reusable-dependency-review.yml](.github/workflows/reusable-dependency-review.yml) | GitHub native dep review + Snyk OSS + SPDX license enforcement (expressions and pip classifiers understood). |
| [reusable-osv-scan.yml](.github/workflows/reusable-osv-scan.yml) | Token-free full-tree dependency CVE scan via OSV-Scanner / OSV.dev. |
| [reusable-attest-sbom.yml](.github/workflows/reusable-attest-sbom.yml) | Opt-in signed attestation over the container-scan SBOM. |
| [reusable-deploy-gate.yml](.github/workflows/reusable-deploy-gate.yml) | Aggregates every scan, applies env policy, gates the deploy. |
| [ci-self-test.yml](.github/workflows/ci-self-test.yml) | Dogfoods the published helper scripts and core reusable workflows on every PR to this repo. |
| [scanner-canary.yml](.github/workflows/scanner-canary.yml) | Scans deliberately vulnerable code in [canary/](canary/) on every PR and weekly; fails if expected findings disappear. |

Unit-tested, stdlib-only helper scripts under [scripts/](scripts/) do the
parsing and policy work: Trivy, Checkov, Snyk, OSV, and SAST-SARIF report
parsers, secret-finding merge/dedupe (with a redaction guarantee), SPDX
license evaluation, SBOM summaries, the deploy-gate evaluator, and a
scanner-version currency check. Tests include real captured scanner
output. Policy files under [policies/](policies/) hold the environment
thresholds the deploy gate reads at runtime
([severity-thresholds.yml](policies/severity-thresholds.yml), which you can
replace with your own via `policy_file`) and the Checkov severity ratings
([checkov-severity.json](policies/checkov-severity.json)).

## Quick start

```yaml
# .github/workflows/pipeline.yml in your application repo
name: DevSecOps Pipeline
on:
  push:    { branches: [main, develop] }
  pull_request: { branches: [main] }

permissions:
  contents: read
  security-events: write
  pull-requests: write
  actions: read
  deployments: write

jobs:
  secret-scan:
    uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-secret-scan.yml@v1
  sast:
    uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-sast.yml@v1
    with: { language: javascript, fail_on_severity: high }
    secrets: { SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }} }
  dependency-review:
    uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-dependency-review.yml@v1
    secrets: { SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }} }
  osv-scan:
    uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-osv-scan.yml@v1
  iac-scan:
    uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-iac-scan.yml@v1
    with: { iac_directory: infra/, framework: terraform }
  container-scan:
    needs: [secret-scan]
    uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-container-scan.yml@v1
    with: { image_ref: myapp:${{ github.sha }}, enable_sbom: true }
  deploy-gate:
    if: ${{ always() }}
    needs: [sast, container-scan, dependency-review, osv-scan, iac-scan, secret-scan]
    uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-deploy-gate.yml@v1
    with: { environment: staging, required_scans: 'sast,container,iac,secrets,dependencies,osv' }
```

That's it. See [docs/getting-started.md](docs/getting-started.md) for the
full walkthrough.

`deploy-gate` should always be declared with `if: ${{ always() }}` so it
still aggregates artifacts and emits a final decision when an upstream
scan job fails.

Gates fail closed, so expect a few real findings on the first run. See
[what blocks, by default](docs/security-gates.md#what-blocks-by-default)
and the escape hatches in [troubleshooting](docs/troubleshooting.md).

## See it in action

Every scan renders a job-summary table and a single, self-updating PR
comment with severity counts, top findings and license distribution. The
deploy gate writes its decision and 0–100 security score to the job
summary, a `deploy-gate-report` artifact, and (optionally) Slack.

<!-- TODO: screenshot of a job summary + PR comment from a ci-self-test run.
     Capture from https://github.com/kirilurbonas/pipeline-armor/actions -->

## Examples

Example consumers live under [examples/](examples/). The app and
Terraform examples each ship a complete `pipeline.yml`:

- [examples/nodejs-app](examples/nodejs-app) — Express service, Alpine image with npm removed, non-root.
- [examples/python-app](examples/python-app) — FastAPI service, slim-bookworm image.
- [examples/terraform-infra](examples/terraform-infra) — hardened S3 + KMS module.
- [examples/k8s-manifests](examples/k8s-manifests) — hardened Deployment + Service pair for the kubernetes IaC scan.

## Architecture

```
   Developer push / PR
            │
            ├──► secret-scan ──► container-scan ──┐   no image is built from
            ├──► sast ────────────────────────────┤   a tree with a leaked key
            ├──► dependency-review ───────────────┤
            ├──► osv-scan ────────────────────────┤   each uploads counts JSON
            └──► iac-scan ────────────────────────┤   (+ SARIF) as an artifact
                                                  ▼
                                   ┌──────────────────────────────┐
                                   │ deploy-gate  (if: always())  │
                                   │  - aggregates every artifact │
                                   │  - fails closed on missing   │
                                   │    evidence or tool errors   │
                                   │  - applies env policy        │
                                   │  - manual approval via       │
                                   │    GitHub Environments       │
                                   └──────────────────────────────┘
                                                  │ pass
                                                  ▼
                                           your deploy job
```

## Documentation

- [Getting started](docs/getting-started.md) — wire pipeline-armor into a
  repo in under ten minutes.
- [Configuration reference](docs/configuration.md) — every input on
  every workflow.
- [Security gates](docs/security-gates.md) — the layered gate model and
  how to extend it.
- [Troubleshooting](docs/troubleshooting.md) — common issues and fixes.
- [Policies](policies/) — severity thresholds and license allow/deny
  lists.

## Distribution & versioning

Reusable workflows are not listable on the GitHub Marketplace (only
composite/JS/Docker actions are) — you consume this library directly by
reference:

```yaml
uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-sast.yml@v1
```

Releases follow [SemVer](https://semver.org/). Major-version tags
(`v1`, `v2`) are kept up to date with the latest minor — safe for most
teams. For supply-chain-critical workloads, pin to a commit SHA:

```yaml
uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-sast.yml@<commit-sha>  # v1.3.0
```

The library practices what it preaches: every third-party action inside
these workflows is pinned to a full commit SHA, every scanner binary
downloaded at runtime is version-pinned and SHA256-verified, and every
pip/npm-installed tool is version-pinned.

## Contributing

Issues and PRs welcome. The CI self-test (`ci-self-test.yml`) exercises
the published helper scripts and core reusable workflows on every PR, so
changes are caught quickly. See the contribution checklist:

- [ ] Workflow YAML passes `actionlint` and `yamllint`.
- [ ] Any new helper script has a smoke test in `ci-self-test.yml`.
- [ ] Scanner changes keep `scanner-canary.yml` green (planted issues still found).
- [ ] Docs updated alongside any new input or output.
- [ ] Example pipelines still resolve cleanly.

## License

Apache 2.0 — see [LICENSE](LICENSE).
