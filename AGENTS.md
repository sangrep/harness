# Contributor and agent guide

## Purpose

This repository owns the Harness component: Backend-only evidence review harness, deterministic adapters, and headless CLI.

## Public information boundary

Assume every branch, commit, Issue, pull request, review, workflow log, artifact, document, and
agent instruction can become permanently public. Work only from repository-local public context.
Do not mention private repositories, parents, roadmaps, task identifiers, worktrees, local paths,
provider records, customer material, credentials, or unreleased product composition.

## Working agreement

1. Read README.md, CONTRIBUTING.md, SECURITY.md, and the assigned public Issue.
2. Keep changes focused and repository-local; consume other components only as released artifacts.
3. Do not add source copied from another repository without reviewed public provenance.
4. Do not add generated files unless their generator and drift check are included.
5. Run `./scripts/check` before pushing or requesting review.
6. Record exact tested and untested scope. Do not claim support or release from a passing build.
7. Use a private security report for vulnerabilities.

## Repository map

- `.github/` — contribution forms, review ownership, and scoped CI.
- `scripts/` — the preliminary check and public-boundary audit.
- `src/sangrep_harness/` — engine, reference adapters and CLI.
- `tests/`, `corpus/`, `examples/` — deterministic tests and synthetic examples.
- `docs/`, `mkdocs.yml` — developer guides, reference and local preview.
- `provenance/` — immutable dependency and technical source inventory.

## Dependency direction

No editable installs, submodules, source-tree imports, or hidden cross-repository credentials. Use
versioned artifacts with digests and compatibility declarations.

## Documentation

Implementation facts stay beside this component. User-facing product behavior belongs in its
canonical product documentation. Internal decision history does not enter this repository.
