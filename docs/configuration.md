# Configuration

This document is the reference for every input each reusable workflow
accepts. For a quick start, see [getting-started.md](getting-started.md).

## Pinning

In production, never call pipeline-armor with `@main` — pin to a tag or
commit SHA so a change in this library can't silently alter your gate
behavior.

```yaml
uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-sast.yml@v1.3.0
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

To sign the generated SBOM, chain
[reusable-attest-sbom.yml](../.github/workflows/reusable-attest-sbom.yml)
after this workflow (see below).

## reusable-attest-sbom.yml

Signed attestation over the SBOM artifact produced by the container scan,
verifiable with `gh attestation verify`. Standalone (rather than an input
on container-scan) so the elevated `id-token: write` +
`attestations: write` permissions are only ever requested by callers that
opt in — GitHub validates called-workflow permissions at startup even for
skipped jobs.

| Input | Default | Description |
| --- | --- | --- |
| `artifact_name` | `container-scan-reports` | Uploaded artifact containing the SBOM. |
| `sbom_file` | `sbom.json` | SBOM filename within the artifact. |

The caller job must set `needs:` on the container-scan job and grant
`contents: read`, `actions: read`, `id-token: write`, `attestations: write`.

## reusable-iac-scan.yml

| Input | Default | Description |
| --- | --- | --- |
| `iac_directory` | `.` | Path to scan. |
| `framework` | `terraform` | `terraform` &#124; `cloudformation` &#124; `kubernetes` &#124; `dockerfile` &#124; `all`. The terraform, kubernetes, and dockerfile paths are exercised by this repo's self-test; cloudformation is supported (passed straight to Checkov) but not self-tested. |
| `fail_on_severity` | `high` | Severity gate. |
| `soft_fail` | `false` | If true, never fails the pipeline. |
| `checkov_skip_checks` | `""` | Comma-separated check IDs to suppress. |
| `checkov_external_checks` | `""` | Path to a directory of custom Checkov policies. |
| `iac_default_severity` | `high` | Severity for checks with no rating (Checkov OSS rates none). |
| `checkov_severity_map` | `""` | Path in your repo to a JSON file shaped like [`policies/checkov-severity.json`](../policies/checkov-severity.json); overrides built-in ratings. |
| `sarif_upload` | `true` | Upload SARIF to the Security tab. |

## reusable-secret-scan.yml

| Input | Default | Description |
| --- | --- | --- |
| `scan_depth` | `all` | `all` (full git history) &#124; `diff` (since `base_ref`, or since the previous push). `staged` is a deprecated alias for `diff`. |
| `fail_on_detection` | `true` | Fail when verified secrets are found, or a scanner errors. |
| `fail_on_unverified` | `false` | Also fail this job on unverified findings (e.g. Gitleaks regex hits). The deploy gate rates them `high` either way; see [security-gates.md](security-gates.md). |
| `baseline_file` | `.gitleaks.baseline.json` | Accepted-findings baseline. |
| `base_ref` | `""` | Base ref for `diff` scans. |
| `trufflehog_exclude_detectors` | `Lob` | Trufflehog detectors to skip. Lob's pattern matches 40-char `test_…` identifiers (e.g. pytest names) and "verifies" them; set `''` to re-enable. |

Both scanners read committed history only. The combined findings are also
written as `secrets.sarif` in the `secret-scan-reports` artifact.

## reusable-dependency-review.yml

| Input | Default | Description |
| --- | --- | --- |
| `fail_on_severity` | `high` | Severity gate. |
| `allow_licenses` | `""` | Comma-separated allowed SPDX IDs. Empty = allow anything not denied. |
| `deny_licenses` | `GPL-3.0,AGPL-3.0,SSPL-1.0` | Comma-separated denied SPDX IDs. |
| `allow_unknown_licenses` | `false` | With an allow-list, accept `UNKNOWN` licenses (otherwise they fail). |
| `snyk_enable` | `true` | Run Snyk Open Source. |
| `ecosystem` | `auto` | `auto` &#124; `npm` &#124; `pip` &#124; `maven` &#124; `go` |
| `working_directory` | `.` | Subdirectory to review, useful for monorepos and example apps. |

Licenses are normalized to SPDX, including pip trove classifiers such as
"GNU General Public License v3 (GPLv3)". They are matched by base id, so
`GPL-3.0` also covers `GPL-3.0-only`, `GPL-3.0-or-later` and `GPL-3.0+`.
Expressions are understood: a package passes if any `OR` alternative is
acceptable, and every `AND` term must be. npm license arrays and pip's
`A; B` joins count as `OR`. pip licenses are read from an isolated venv,
so the scanner's own tooling is never counted.

License extraction supports **npm, pip, and go**. For `maven` (and any
other ecosystem) the license gate reports `unsupported` in the job summary
and does not evaluate — it is never silently treated as clean. The
vulnerability scan is unaffected.

## reusable-osv-scan.yml

Token-free dependency vulnerability scanning against the public
[OSV.dev](https://osv.dev) database. Complements dependency-review:
GitHub's native action only sees the PR diff and Snyk requires a token,
while OSV-Scanner reads lockfiles for full-tree coverage with no
credentials.

| Input | Default | Description |
| --- | --- | --- |
| `fail_on_severity` | `high` | `low` &#124; `medium` &#124; `high` &#124; `critical` |
| `working_directory` | `.` | Subdirectory to scan (lockfiles are discovered recursively). |
| `sarif_upload` | `true` | Upload SARIF to Security tab. |

Register it in the deploy gate with the `osv` scan id
(`required_scans: 'sast,container,osv,…'`).

## reusable-deploy-gate.yml

| Input | Default | Description |
| --- | --- | --- |
| `environment` | _required_ | `dev` &#124; `staging` &#124; `prod`, or any environment defined in `policy_file`. |
| `policy_file` | `""` | Path in your repo to a policy shaped like [`policies/severity-thresholds.yml`](../policies/severity-thresholds.yml). Its `environments` replace the built-ins. If unreadable, the gate fails closed. |
| `required_scans` | `sast,container,iac,secrets` | Scans that must have produced artifacts (`sast`, `container`, `iac`, `secrets`, `dependencies`, `osv`). Match these to the caller job's `needs:` list and run the gate job with `if: ${{ always() }}`. |
| `bypass_approvers` | `""` | Informational; actual approval enforced via Environments. |
| `notify_slack` | `false` | Post status to Slack. |
| `artifact_run_id` | _current_ | Override which run's artifacts are evaluated. |

Outputs: `decision` (`pass`/`fail`), `score` (0-100).

## How helper scripts reach your runner

Several reusable workflows depend on Python helpers under `scripts/` in
*this* repository. Each such workflow performs a second, sparse checkout of
its own source (`repository: ${{ job.workflow_repository }}` at
`ref: ${{ job.workflow_sha }}`) into `.pipeline-armor/` on the runner — the
exact commit of the workflow you pinned, not a floating branch. Consumers
never vendor `scripts/` and cannot end up with a script/workflow version
mismatch. The deploy gate additionally checks out `policies/` and reads
environment thresholds from `policies/severity-thresholds.yml`.

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
