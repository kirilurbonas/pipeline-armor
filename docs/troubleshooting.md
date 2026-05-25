# Troubleshooting

A grab-bag of issues we've seen in real deployments and how to fix them.

## The workflow never runs

**Symptom:** opening a PR doesn't trigger the pipeline at all.

Check, in order:

1. The caller workflow lives at `.github/workflows/<name>.yml` (not
   `.github/workflow/`, not anywhere else).
2. The `on:` block lists `pull_request` and the right branches.
3. *Settings → Actions → General* has "Allow all actions and reusable
   workflows" enabled. Workflows from external repositories are blocked
   under the strictest setting.
4. If your caller is in a private repo and `pipeline-armor` is in a
   different private repo, ensure *Settings → Actions → General →
   Access* permits cross-repository reuse on **both** repos.

## "Reusable workflow not found"

The `uses:` path must be exact:

```
uses: <owner>/<repo>/.github/workflows/<file>.yml@<ref>
```

The most common mistake is putting `.yaml` instead of `.yml`. Pinning to
a tag that doesn't exist will also produce this error — verify with
`git ls-remote --tags`.

## SARIF upload says "Path does not exist"

This means a scanner failed to produce its SARIF file before the upload
step ran. Open the failing scanner's step and look for a fatal error.
Common causes:

- Snyk: invalid `SNYK_TOKEN`. The CLI prints "Authentication failed"
  and exits 2.
- Trivy: image not found locally. Verify the previous `docker build`
  step actually loaded the image (`--load`, not `--push`).
- Checkov: `--directory` doesn't contain any files of the configured
  `framework`. Set `framework: all` to confirm.

Every workflow uses `if: hashFiles(...) != ''` on its upload step
specifically to prevent the upload from being the *first* visible
failure — but the underlying scanner failure still needs fixing.

## "Resource not accessible by integration"

The reusable workflow needs permissions the caller didn't grant. Add
this to the caller workflow's top-level `permissions:` block:

```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write
  actions: read
  deployments: write
```

Granular `permissions:` on individual jobs *overrides* the top-level
block — make sure you're not narrowing in a job that needs SARIF upload.

## Deploy gate says "missing" for every scan

The gate downloads artifacts from the same run. If the upstream scans
were `skipped` (e.g., because a `needs:` condition wasn't met), they
won't have produced artifacts.

Verify the topology:

```
secret-scan ────┐
sast            ├──► deploy-gate
container-scan ─┤
iac-scan       ─┘
```

All of these must be in the gate's `needs:` list and must run to
completion (success or failure — failures still produce artifacts).

## Snyk is too noisy

Snyk's default Code rule set surfaces a lot of `medium` findings that
are non-exploitable in many contexts (e.g. format-string sinks where
the input is a literal). Three options:

1. Set `fail_on_severity: high` and treat mediums as informational.
2. Configure exclusion rules in your Snyk org (Snyk web UI → Settings →
   Code).
3. Disable Snyk in the SAST job (`snyk_enable: false`) and rely on
   Semgrep alone.

## Gitleaks flags my test fixtures

This is expected — test data often looks exactly like real credentials.
Add the finding to `.gitleaks.baseline.json` (regenerate with
`gitleaks detect --report-path .gitleaks.baseline.json`) and the
scanner will skip it going forward.

For per-file suppression, add a `gitleaks:allow` comment on the
offending line. Document *why* the value is safe in a code comment next
to the suppression.

## Container scan takes 8+ minutes

Trivy downloads its CVE database on every cold cache. Two ways to fix:

- Pin the Trivy version in the workflow file and rely on GitHub's
  runner cache — same version = same database location.
- Use the Trivy DB OCI image: set `TRIVY_DB_REPOSITORY` to a mirror
  hosted in your own registry to avoid hitting GHCR rate limits.

## "License check fails on UNKNOWN"

Some npm packages don't declare a license in their `package.json`.
`license-checker` reports these as `UNKNOWN`. Two options:

- Treat UNKNOWN as denied: explicitly add it to `deny_licenses`.
- Bisect with `npx license-checker --summary` to find the offender,
  then either replace the dependency or add a per-package override in
  `package.json` (`license.overrides`).

The Snyk dependency review will also catch this, with the additional
benefit of vulnerability data.

## I need to add a finding to the baseline, but the file doesn't exist

The first run won't have one. Generate it locally:

```bash
gitleaks detect --report-path .gitleaks.baseline.json
git add .gitleaks.baseline.json
git commit -m "chore(security): add gitleaks baseline"
```

The baseline is committed to the repo. Future scans subtract it from
new findings, so genuine *new* leaks still cause a failure.
