# Security gates

This document explains *how* pipeline-armor decides whether to let a
deploy proceed, and how to extend the policy for your environment.

## Layered model

Gates are applied in layers. A finding has to clear every layer that
applies to it; failing any one blocks the deploy.

```
   ┌──────────────────────────────────────────────────────────┐
   │  Layer 4: GitHub Environment protection (manual approval) │
   ├──────────────────────────────────────────────────────────┤
   │  Layer 3: Deploy gate environment policy (env override)   │
   ├──────────────────────────────────────────────────────────┤
   │  Layer 2: Per-scan severity threshold (caller-configured) │
   ├──────────────────────────────────────────────────────────┤
   │  Layer 1: Scanner default rule packs                      │
   └──────────────────────────────────────────────────────────┘
```

The bottom three layers can each *fail* a build; only the top layer can
*block* a passing build pending manual approval.

### Layer 1 — Scanner defaults

Each scanner ships with its own rule packs:

- **Semgrep** loads the `auto` config, which selects rule packs by
  detected language.
- **Snyk Code** uses the rule set associated with the configured Snyk
  organization.
- **Trivy** uses the vulnerability database current at scan time.
- **Checkov** loads its built-in policies (1000+) plus any custom
  policies supplied via `checkov_external_checks`.
- **Gitleaks** uses its built-in regex set plus any rules in
  `.gitleaks.toml` at the repo root.

These are tuned upstream and are out of scope for pipeline-armor; the
library only orchestrates the scanners.

### Layer 2 — Per-scan severity threshold

Every reusable workflow accepts a `fail_on_severity` input. The convention
across the library is the same set of values:

| `fail_on_severity` | What it means |
| --- | --- |
| `low` | Block on any finding. Useful for security-critical libraries. |
| `medium` | Block on medium and above. Default for prod. |
| `high` | Block on high and above. Default for staging. |
| `critical` | Block on critical only. Default for dev. |

The scanner produces all findings regardless of the threshold — the gate
only filters which ones *fail* the build.

### Layer 3 — Deploy-gate environment policy

`reusable-deploy-gate.yml` applies an **additional** severity policy on
top of layer 2, based on the `environment` input:

| Environment | Policy |
| --- | --- |
| `dev` | Fail only on `critical`. |
| `staging` | Fail on `high` + `critical`. |
| `prod` | Fail on `medium` + `high` + `critical`, and require manual approval. |

Layer 3 can only **tighten** layer 2. If a per-scan threshold is `low`
but the environment is `dev`, the gate still applies the dev policy on
top — but the scan has already produced the full finding set, so
nothing is lost.

Two non-severity signals are also treated as hard gate breaches:

- **Verified secrets** are counted as `critical`.
- **Dependency policy failures** (for example denied licenses or a
  failing dependency-review diff) are counted as `critical`.

If a required scan artifact is missing or unreadable, the deploy gate
fails closed instead of assuming success.

#### Known limitation: unverified secrets are informational

The secret-scan severity model is deliberately coarse:

- **Verified** findings (Trufflehog confirmed the credential live against
  the provider) are counted as `critical` and block the gate.
- **Unverified** findings — which includes *every* Gitleaks finding, since
  Gitleaks does not verify — are counted as `low` and are informational
  only.

This trades sensitivity for signal: hard-failing on regex hits creates
alert fatigue. The cost is that a real leaked credential that cannot be
verified (provider offline, detector without a verifier, revoked-but-
reused key material) will **not** block a deploy on its own. If your
threat model requires blocking on any detection, set
`fail_on_unverified: true` on `reusable-secret-scan.yml` — the job then
fails on any unverified finding as well (pair it with a curated
`baseline_file` to keep accepted false positives from blocking).

## Provenance and attestation

`reusable-container-scan.yml` builds images locally for scanning and
never pushes them, so it deliberately does **not** sign or attest images —
an attestation over an image that only ever existed in an ephemeral
runner daemon proves nothing a consumer can verify. What it can attest is
the **SBOM file** it generates: set `attest_sbom: true` (and grant the
caller `id-token: write` + `attestations: write`) to produce a signed
attestation over `sbom.json` via `actions/attest-sbom`, verifiable with
`gh attestation verify`.

Image provenance and signing belong in the workflow that pushes the image
to a registry. In that workflow, after the push:

```yaml
permissions:
  id-token: write
  attestations: write
steps:
  - uses: actions/attest-build-provenance@<pin-to-sha>
    with:
      subject-name: ghcr.io/you/app
      subject-digest: ${{ steps.push.outputs.digest }}
      push-to-registry: true
```

### Layer 4 — GitHub Environment protection

The `prod` policy sets `environment: prod` on the gate job. That
instructs GitHub to consult the **Environment protection rules** you've
configured in *Settings → Environments → prod*:

- **Required reviewers**: at least one of the listed reviewers must
  approve the job before it runs.
- **Wait timer**: optional cooldown between approval and run.
- **Deployment branch rules**: limits which branches can deploy.

This is the *only* layer that pauses an otherwise-passing build for a
human. Don't reinvent it in workflow logic — use Environments.

## Bypassing a gate

Sometimes you need to ship despite a known finding (e.g. a high-severity
CVE in a transitive dependency with no upstream fix). Three options, in
order of preference:

1. **Suppress at the scanner.** Add a `// nosemgrep`, `# checkov:skip=…`,
   `.snyk` ignore entry, or `.gitleaks.baseline.json` entry. This is the
   most auditable: the suppression lives in the code review history.

2. **Tighten the input.** Raise `fail_on_severity` for the affected scan
   (e.g., `critical` for a single PR) and revert in a follow-up. Document
   the reason in the PR description.

3. **Skip via `required_scans`.** Remove the scan from the deploy gate's
   `required_scans` list. This is the loudest option — it removes the
   scan from the gate's report entirely — and should be temporary.

Whichever path you choose, link the suppression to a Jira / Linear ticket
with an expiration date. pipeline-armor does not enforce expirations;
your governance does.

## Scoring

The deploy gate computes a 0-100 **security score** that goes into the
PR comment and is surfaced as a workflow output. The formula is:

```
score = max(0, 100 − ( 10·critical + 4·high + 1·medium + 0.25·low ) − 20·missing_evidence )
```

This is intentionally simple. It's a trend indicator, not a risk model.
If you need a defensible risk score for compliance reporting, integrate
with Dependency-Track or DefectDojo using the SBOM and SARIF artifacts
that this library uploads on every run.
