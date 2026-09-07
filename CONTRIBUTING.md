# Contributing

Thank you for helping improve this component.

## Before you start

Small fixes, tests, examples, documentation, and accessibility improvements may go directly to a
pull request. New API, protocol, security, licensing, or architecture behavior starts with a
self-contained public Issue and maintainer approval. Never include private project context,
credentials, customer material, or unreleased product details.

## Local check

1. Create a focused branch with a public-safe name and run `./scripts/bootstrap`.
   Activate `.venv`; development dependencies are hash-locked.
2. Make one bounded change.
3. Use focused tests while iterating and run `./scripts/check` at the frozen head.
   Observe a failing probe before fixing a safety regression.
   Preview docs with `python -m mkdocs serve`.
4. Open a pull request using the repository template.

Commits use `type(scope): summary`. Explain the public problem, verification, limitations, and
security effects. Security findings follow [SECURITY.md](SECURITY.md).

## Licensing

Contributions are accepted only under the repository's reviewed contribution and licensing terms.
Those terms must be finalized before public source publication. Do not add third-party material
without its exact provenance and license classification.
