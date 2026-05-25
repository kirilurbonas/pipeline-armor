# Getting started

This guide walks you through wiring `pipeline-armor` into a new repository in
under ten minutes.

## Prerequisites

- A GitHub repository (any language).
- Permission to add workflow files to that repository (`Contents: write`).
- Optional but recommended:
  - A Snyk API token stored as `SNYK_TOKEN` in repository secrets.
  - A Slack webhook URL stored as `SLACK_WEBHOOK_URL` if you want Slack
    notifications from the deploy gate.

You do **not** need to fork pipeline-armor. The workflows are called via
`uses: kirilurbonas/pipeline-armor/.github/workflows/<file>@<ref>` from your
own pipeline file.

## 1. Pick the closest example

| Stack | Reference |
| --- | --- |
| Node.js / TypeScript | [examples/nodejs-app](../examples/nodejs-app) |
| Python | [examples/python-app](../examples/python-app) |
| Terraform / OpenTofu | [examples/terraform-infra](../examples/terraform-infra) |

Copy the example's `.github/workflows/pipeline.yml` into your repo at the
same path.

## 2. (Optional) Replace the org reference if you're forking

The bundled examples call `kirilurbonas/pipeline-armor` directly — you
can leave that as-is to consume this library upstream. If you've forked
this repo for internal hardening, search-and-replace
`kirilurbonas/pipeline-armor` with `<your-org>/pipeline-armor`.

In production, pin to a release tag or commit SHA instead of `@main` —
see [configuration.md](configuration.md#pinning) for details.

## 3. Add secrets

Open *Settings → Secrets and variables → Actions* in your repo and add:

- `SNYK_TOKEN` (optional; required if you keep `snyk_enable: true`).
- `SLACK_WEBHOOK_URL` (optional; required if `notify_slack: true`).

## 4. Create environments

Open *Settings → Environments* and create one per deploy target —
typically `dev`, `staging`, `prod`. The deploy gate consults these
environments by name and respects any **required reviewers** or
**deployment branch rules** you configure on them. This is how
manual-approval-for-prod is enforced — see [security-gates.md](security-gates.md).

## 5. Push and watch

Open a PR against `main`. You should see, in this order:

1. `secret-scan` runs first and gates everything else.
2. `sast`, `dependency-review`, and (if applicable) `iac-scan` run in
   parallel.
3. `container-scan` runs after `secret-scan` succeeds.
4. `deploy-gate` runs last, aggregates the results, and either passes
   (allowing your downstream deploy job to proceed) or fails with a
   detailed report in the job summary.

Every workflow uploads a SARIF file to the **Security** tab of your
repository. Findings appear in *Security → Code scanning alerts*.

## Troubleshooting

If something doesn't run, check [troubleshooting.md](troubleshooting.md)
first. The most common issues are missing secrets, missing workflow
permissions, and pinning a tag/SHA that no longer exists.
