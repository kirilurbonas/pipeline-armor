# Contributing

Thanks for your interest in improving pipeline-armor. This project is a
public template library; contributions that make it more useful to more
teams are very welcome.

## Ground rules

1. **Security first.** This library exists to enforce security policy.
   Changes that loosen a default, suppress a check, or weaken a gate
   need explicit justification in the PR description.
2. **Backwards compatibility.** Consumers pin against tags and SHAs. Do
   not rename inputs, remove inputs, or change default semantics in a
   patch or minor release.
3. **Tested in CI.** Every reusable workflow is exercised by
   [`ci-self-test.yml`](.github/workflows/ci-self-test.yml). If you add a
   new workflow or input, extend the self-test.

## Development loop

```bash
git clone https://github.com/kirilurbonas/pipeline-armor
cd pipeline-armor

# Lint workflows + policy YAML
pip install yamllint
yamllint .github/ policies/

# actionlint is a Go binary; CI uses raven-actions/actionlint. Locally:
brew install actionlint   # or: go install github.com/rhysd/actionlint/cmd/actionlint@latest
# (pip fallback: `pip install actionlint-py` — recent versions ship an
#  `actionlint` wrapper, but the native binary matches CI exactly.)
actionlint .github/workflows/*.yml

# Unit-test and lint the helper scripts
pip install pytest ruff
pytest tests/ -q
ruff check scripts tests

# Smoke-test the helper scripts
python3 scripts/parse-trivy-report.py --help
python3 scripts/parse-checkov-report.py --help
python3 scripts/generate-sbom-summary.py --help
```

To trigger the full self-test, open a PR — the suite runs automatically.

## Pull-request checklist

- [ ] YAML lints clean (`yamllint`, `actionlint`).
- [ ] `pytest tests/` passes; new script logic comes with a unit test.
- [ ] Any new helper script accepts `--help` and handles empty input.
- [ ] Runtime binary downloads are pinned to a version and verified
      against a SHA256 checksum.
- [ ] Docs updated alongside any new input or output.
- [ ] Example pipelines still resolve cleanly.
- [ ] `CHANGELOG.md` updated under `## Unreleased`.
- [ ] PR description explains *why* the change is safe for downstream
      consumers.

## Release process

1. Update `CHANGELOG.md` — move `## Unreleased` entries under a new
   version heading with today's date.
2. Tag the merge commit: `git tag -s vX.Y.Z -m 'Release vX.Y.Z'`.
3. Push the tag: `git push origin vX.Y.Z`.
4. Move the major-version tag forward: `git tag -f vX && git push -f origin vX`.
5. Create a GitHub Release from the tag with the changelog excerpt.

## Code of conduct

Be kind. We follow the [Contributor Covenant](CODE_OF_CONDUCT.md).
