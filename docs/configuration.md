# Configuration

This document is the reference for every input each reusable workflow
accepts. For a quick start, see [getting-started.md](getting-started.md).

## Pinning

In production, never call pipeline-armor with `@main` — pin to a tag or
commit SHA so a change in this library can't silently alter your gate
behavior.

```yaml
uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-sast.yml@v1.4.0
# or
uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-sast.yml@5c2f4ab1...
```

Tag pinning lets you adopt patch releases by retagging; SHA pinning is
the supply-chain-safe option and what we recommend for `prod` pipelines.

## reusable-sast.yml

| Input | Default | Description |
| --- | --- | --- |
| `language` | _required_ | `python` &#124; `javascript` &#124; `java` &#124; `go` |
| `fail_on_severity` | `high` | `low` &#124; `medium` &#124; `high` &#124; `critical` |
| `snyk_enable` | `true` | If false, Semgrep runs alone. |
| `sarif_upload` | `true` | Upload SARIF to Security tab. |
| `working_directory` | `.` | Subdirectory to scan. |

Required secrets: `SNYK_TOKEN` (only when `snyk_enable: true`).

## reusable-container-scan.yml

| Input | Default | Description |
| --- | --- | --- |
| `image_ref` | _required_ | Image reference (e.g. `myapp:${{ github.sha }}`). |
| `dockerfile_path` | `Dockerfile` | Dockerfile path, relative to `build_context`. |
| `build_context` | `.` | Docker build context directory. |
| `fail_on_severity` | `HIGH` | `LOW` &#124; `MEDIUM` &#124; `HIGH` &#124; `CRITICAL` — note Trivy's uppercase convention. |
| `skip_files` | `""` | Comma-separated in-image paths to skip. |
| `enable_sbom` | `true` | Emit a CycloneDX SBOM as an artifact. |
| `ignore_unfixed` | `true` | Ignore CVEs without an upstream fix available. |

## reusable-iac-scan.yml

| Input | Default | Description |
| --- | --- | --- |
| `iac_directory` | `.` | Path to scan. |
| `framework` | `terraform` | `terraform` &#124; `cloudformation` &#124; `kubernetes` &#124; `dockerfile` &#124; `all` |
| `fail_on_severity` | `high` | Severity gate. |
| `soft_fail` | `false` | If true, never fails the pipeline. |
| `checkov_skip_checks` | `""` | Comma-separated check IDs to suppress. |
| `checkov_external_checks` | `""` | Path to a directory of custom Checkov policies. |

## reusable-secret-scan.yml

| Input | Default | Description |
| --- | --- | --- |
| `scan_depth` | `all` | `staged` &#124; `all` &#124; `diff` |
| `fail_on_detection` | `true` | Fail when verified secrets are found. |
| `baseline_file` | `.gitleaks.baseline.json` | Accepted-findings baseline. |
| `base_ref` | `""` | Base ref for `diff` scans. |

## reusable-dependency-review.yml

| Input | Default | Description |
| --- | --- | --- |
| `fail_on_severity` | `high` | Severity gate. |
| `allow_licenses` | `""` | Comma-separated allowed SPDX IDs. Empty = allow anything not denied. |
| `deny_licenses` | `GPL-3.0,AGPL-3.0` | Comma-separated denied SPDX IDs. |
| `snyk_enable` | `true` | Run Snyk Open Source. |
| `ecosystem` | `auto` | `auto` &#124; `npm` &#124; `pip` &#124; `maven` &#124; `go` |

## reusable-deploy-gate.yml

| Input | Default | Description |
| --- | --- | --- |
| `environment` | _required_ | `dev` &#124; `staging` &#124; `prod` |
| `required_scans` | `sast,container,iac,secrets` | Scans that must have produced artifacts. |
| `bypass_approvers` | `""` | Informational; actual approval enforced via Environments. |
| `notify_slack` | `false` | Post status to Slack. |
| `artifact_run_id` | _current_ | Override which run's artifacts are evaluated. |

Outputs: `decision` (`pass`/`fail`), `score` (0-100).

## Centralized policy

Larger orgs typically don't want each repo picking its own
`fail_on_severity` values. Two ways to centralize:

1. **YAML manifest + composition job.** Maintain
   [policies/severity-thresholds.yml](../policies/severity-thresholds.yml)
   in this repo (or in your own fork). In each consumer pipeline, add a
   tiny job that reads the manifest with `yq` and exposes the values as
   outputs, then reference those outputs in subsequent `with:` blocks.

2. **Wrapper workflow.** Create an org-private `pipeline-armor-wrapper`
   repository containing a single reusable workflow per app archetype.
   Have application repos call the wrapper, and have the wrapper call
   `pipeline-armor`. Policy lives in the wrapper.

Option 2 is the supported pattern for teams with 50+ repositories.
