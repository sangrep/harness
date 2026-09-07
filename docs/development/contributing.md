# Development workflow

Read the repository's contributor, security and governance policies first. New
API and security behavior starts with a repository-local Issue and scope approval.
Use synthetic data and public-safe names throughout code, tests, commit messages,
PRs, workflow output and artifacts.

Run `./scripts/bootstrap`, activate `.venv`, and use the smallest relevant pytest
selection while iterating. Safety regressions require observed RED then GREEN.
Run `./scripts/check` once at the frozen head before push and review. Test output is checked for public-boundary
violations before it can appear in CI logs; unsafe diagnostics are suppressed. The check is
fail-closed when source, fixtures, tools or required acceptance evidence is absent.

`requirements-dev.in` pins development tools. Regenerate the full hash lock with:

```bash
uv pip compile requirements-dev.in --generate-hashes --output-file requirements-dev.txt
```

The contracts dependency has a separate immutable artifact lock in
`provenance/contracts-v1.json`. Never replace it with a branch or editable install.

## Review and integration

Record the exact head, checks, result, artifact digests, limitations and untested
scope in the PR. Resolve independent review before integration. Preserve the
required `check` status and squash merge policy; draft work must not substitute a
skipped implementation check for acceptance. CI cancels superseded work.

Documentation is built locally and as a CI artifact before any GitHub Pages
publication. Preview it locally with `python -m mkdocs serve`. Deployment and
publication need their own accepted gate; this implementation does not activate
hosting or release automation.
