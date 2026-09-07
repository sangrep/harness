# Backend implementation plan

The acceptance contract is [Issue #1](https://github.com/sangrep/harness/issues/1).
Implementation preserves the existing generic engine supplied through a sanitized,
reviewed one-time import. It does not substitute a smaller engine implementation.

## Architecture

The distribution is `sangrep-harness`, with Python imports under `sangrep_harness`.
An immutable artifact supplies `sangrep-contracts==0.1.0.dev0`. The generic engine
owns grants, task authority, budgets, admission, containment, repair and outcomes.
An evidence adapter presents immutable Markdown/TXT snapshots through the engine's
existing interface. A headless JSON/JSONL boundary composes these pieces. Providers
are deterministic fake or replay implementations; integrations use explicit
interfaces and receive no implicit filesystem, credential or execution authority.

## Delivery sequence

- [x] Establish packaging, immutable dependency verification, repository checks,
  documentation navigation, contributor guidance and licensing classifications.
- [x] Validate the sanitized import inventory and provenance, integrate generic
  source and tests, and record preserved interfaces and capabilities.
- [x] Add immutable Markdown/TXT snapshots, the library facade, bounded JSON/JSONL
  CLI, and cited review, adapter, replay, gap and failure examples.
- [x] Observe failing safety/regression probes before fixes; use the smallest
  relevant tests during construction.
- [ ] Freeze the implementation and run one focused/impacted acceptance batch:
  engine, adversarial, replay, provider-contract, privacy, Ruff, format, mypy,
  wheel/CLI, docs, license/provenance, secret and public-boundary checks.
- [ ] Build a local and CI documentation artifact preview, record exact artifact
  identities and tested/untested scope, and request independent PR review.

## Scope and effects

Evidence remains read-only. Models may propose review output, use only granted
engine tools, and must cite admitted evidence or return an explicit gap. A passing
build establishes neither real-provider quality nor product behavior, rich-document
support, a release, public availability, legal acceptance or a support commitment.

The implementation task does not merge, publish, deploy, sign, release, change
hosting or change repository protections.
