# Policies

This directory holds policy documents that govern pipeline-armor's behavior.
The policies are intentionally plain YAML so they can be reviewed by
security teams without GitHub Actions expertise.

## Files

| File | Purpose |
| --- | --- |
| [severity-thresholds.yml](severity-thresholds.yml) | Per-environment and per-scanner severity thresholds. Drives the deploy gate. |
| [allowed-licenses.yml](allowed-licenses.yml) | SPDX allow / deny / review-required license lists for dependency review. |

## How callers consume these

The reusable workflows do not read these files at runtime — they accept
inputs only, which keeps them stateless and easy to test. Consumers wire
the policies in one of two ways:

1. **Inline inputs**: hand-pick values from `severity-thresholds.yml` and
   pass them via `with:` blocks in your caller workflow. Best for small
   teams with one or two pipelines.

2. **Composition workflow**: in larger orgs, write a tiny org-internal
   "policy" workflow that reads this file (e.g. with `yq`) and re-exports
   values as outputs, then chain it before pipeline-armor's reusable jobs.
   This is the supported pattern for centralized policy management.

See [docs/configuration.md](../docs/configuration.md) for full examples of
both approaches.

## Editing policy

Policy changes are intentionally heavyweight:

- Tightening (e.g., adding a license to `denied`) requires a PR review
  from at least one CODEOWNER on the security team.
- Loosening (e.g., moving a license from `denied` to `allowed`) additionally
  requires sign-off from legal — record the approver in the PR description.

The CI self-test exercises these files via `yamllint`. Schema validation
beyond that is the responsibility of the consuming workflow.
