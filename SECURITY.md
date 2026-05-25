# Security Policy

## Supported versions

| Version | Status |
| --- | --- |
| `main`   | ✅ Active development. Receives all security fixes. |
| `v1.x`   | ✅ Security fixes for 12 months after release. |
| `< v1.0` | ❌ Pre-1.0 releases are not supported. |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Email the maintainer with a clear description of:

- The affected workflow / script / policy.
- The impact (what an attacker can do).
- A minimal reproduction.

You can expect an initial response within **5 business days**. Confirmed
vulnerabilities are patched on a private branch and disclosed via a
GitHub Security Advisory once the fix lands on `main`.

## Coordinated disclosure

We follow a 90-day coordinated-disclosure timeline by default, shortened
or extended by mutual agreement when the situation requires it
(actively-exploited issues are patched and disclosed faster; deeper
architectural issues may take longer).

## Scope

In scope:

- The reusable workflows under `.github/workflows/`.
- Helper scripts under `scripts/`.
- Policy templates under `policies/`.

Out of scope (report directly to the upstream project):

- Findings in Trivy, Snyk, Semgrep, Checkov, Gitleaks, or Trufflehog
  themselves.
- Findings in actions from `actions/`, `github/codeql-action/`, etc.

## Hardening recommendations for consumers

- Pin every `uses:` to a commit SHA in production environments.
- Store all secrets (`SNYK_TOKEN`, `SLACK_WEBHOOK_URL`, registry creds)
  as GitHub Encrypted Secrets — never inline.
- Use GitHub Environments with required reviewers to enforce manual
  approval for production deploys.
- Review the [policies/](policies/) defaults and tighten them for your
  threat model.
