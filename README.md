# pipeline-armor

[![CI Self-Test](https://github.com/kirilurbonas/pipeline-armor/actions/workflows/ci-self-test.yml/badge.svg)](https://github.com/kirilurbonas/pipeline-armor/actions/workflows/ci-self-test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![SLSA Level 2](https://img.shields.io/badge/SLSA-Level%202-green)](https://slsa.dev/)

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
- **First-class GitHub integration** — SARIF uploads to the Security
  tab, PR comments via the API, manual approval via Environments.

## What's in the box

| Workflow | Purpose |
| --- | --- |
| [reusable-sast.yml](.github/workflows/reusable-sast.yml) | Snyk Code + Semgrep static analysis with SARIF upload. |
| [reusable-container-scan.yml](.github/workflows/reusable-container-scan.yml) | Trivy image + Dockerfile config scan, CycloneDX SBOM. |
| [reusable-iac-scan.yml](.github/workflows/reusable-iac-scan.yml) | Checkov for Terraform/CloudFormation/Kubernetes/Dockerfile, with CIS/SOC2/PCI-DSS mapping. |
| [reusable-secret-scan.yml](.github/workflows/reusable-secret-scan.yml) | Gitleaks + Trufflehog, baseline-aware, verified-only by default. |
| [reusable-dependency-review.yml](.github/workflows/reusable-dependency-review.yml) | GitHub native dep review + Snyk OSS + SPDX license enforcement. |
| [reusable-deploy-gate.yml](.github/workflows/reusable-deploy-gate.yml) | Aggregates every scan, applies env policy, gates the deploy. |
| [ci-self-test.yml](.github/workflows/ci-self-test.yml) | Dogfoods the entire library on every PR to this repo. |

Helper scripts under [scripts/](scripts/) parse Trivy/Checkov output and
summarize SBOMs. Policy files under [policies/](policies/) give your
security team a place to centrally manage severity thresholds and
license rules.

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
  container-scan:
    needs: [secret-scan]
    uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-container-scan.yml@v1
    with: { image_ref: myapp:${{ github.sha }}, enable_sbom: true }
  deploy-gate:
    needs: [sast, container-scan, dependency-review, secret-scan]
    uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-deploy-gate.yml@v1
    with: { environment: staging, required_scans: 'sast,container,secrets,dependencies' }
```

That's it. See [docs/getting-started.md](docs/getting-started.md) for the
full walkthrough.

## Examples

Three runnable example apps live under [examples/](examples/). Each is a
complete, real-world consumer pipeline:

- [examples/nodejs-app](examples/nodejs-app) — Express service, distroless image.
- [examples/python-app](examples/python-app) — FastAPI service, slim-bookworm image.
- [examples/terraform-infra](examples/terraform-infra) — hardened S3 + KMS module.

## Architecture

```
   Developer push / PR
            │
            ▼
   ┌─────────────────────┐
   │   secret-scan       │ ◄── runs first, gates everything else
   └─────────────────────┘
            │
            ├──► sast            ─┐
            ├──► dependency-rev  ─┤
            ├──► iac-scan        ─┤   each writes SARIF + JSON
            └──► container-scan  ─┘   to the Security tab + artifacts
                                  │
                                  ▼
                       ┌──────────────────┐
                       │   deploy-gate    │
                       │  - aggregates    │
                       │  - applies env   │
                       │    policy        │
                       │  - manual approval│
                       │    via GitHub    │
                       │    Environments  │
                       └──────────────────┘
                                  │
                            pass │ fail
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

## Versioning & pinning

Releases follow [SemVer](https://semver.org/). Major-version tags
(`v1`, `v2`) are kept up to date with the latest minor — safe for most
teams. For supply-chain-critical workloads, pin to a commit SHA.

## Contributing

Issues and PRs welcome. The CI self-test (`ci-self-test.yml`) exercises
every reusable workflow on every PR, so changes are caught quickly. See
the contribution checklist:

- [ ] Workflow YAML passes `actionlint` and `yamllint`.
- [ ] Any new helper script has a smoke test in `ci-self-test.yml`.
- [ ] Docs updated alongside any new input or output.
- [ ] Example pipelines still resolve cleanly.

## License

Apache 2.0 — see [LICENSE](LICENSE).
