# Kubernetes manifests example

A minimal, reasonably-hardened Deployment + Service pair used to exercise
`reusable-iac-scan.yml` with `framework: kubernetes` in the self-test.

Wire it in a consumer pipeline like this:

```yaml
jobs:
  iac-scan-k8s:
    uses: kirilurbonas/pipeline-armor/.github/workflows/reusable-iac-scan.yml@v1
    with:
      iac_directory: k8s/
      framework: kubernetes
      fail_on_severity: high
```

The manifests demonstrate the posture Checkov's `CKV_K8S_*` policies check
for: `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation:
false`, dropped capabilities, seccomp `RuntimeDefault`, disabled service
account token automount, resource requests/limits, and liveness/readiness
probes.
