# Bounded evidence review components

Development source for a backend library that preserves immutable evidence grants,
closed tools, citations, bounded tasks, context precedence and ordered receipts.
Synthetic tests exercise the reusable algorithms without network access.

## Contents

- `src/sangrep_harness/`: executable generic value types, grants, tool admission,
  citation validation, task scheduling/reconciliation, context assembly, egress,
  deterministic fake model, event replay and inspection receipts.
- `adaptation/`: Python source excerpts for the structural model loop, durable task
  coordination, terminal recovery and provider exchange. These are implementation
  inputs with explicit unresolved adapter dependencies. They are not importable
  package modules or a working CLI.
- `tests/`: synthetic context, egress, event, replay and bounded-task tests.
- `ADAPTERS.md`: required adapter behavior and integration checks.
- `BUNDLE.json`: exact file hashes and canonical inventory digest.

## Local verification

Use Python 3.11 or later, pytest and Pydantic 2.12.5. Install the accepted
`sangrep-contracts==0.1.0.dev0` wheel non-editably. Its SHA-256 is
`8b6e52f4fb6db1ee021c7111cd17021577d9deb20ba7167622456a1bd329423c`.
This is an accepted development artifact; it is not available from a package
registry. Public source authority is contracts commit
`28f6d9ada5b2da9fb432aead11462104207750c0`.

Run from this directory:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m pytest -c /dev/null -p no:cacheprovider tests --confcutdir=. -q
```

The suite contains 51 inherited tests and 13 focused evidence-adapter cases.
The adapter cases cover the complete declared shape, typed refusals and a synthetic
grant/tool/citation flow. The 26 runtime modules import in a clean environment.
These checks do not establish complete adapter-excerpt integration, CLI, packaging,
documentation site, rich-document support, live providers or persistent recovery.

`wire.py` and `review.py` contain component-local review values using the development
identifier `sangrep.harness.review.v1`. They are not an extension to the accepted
contracts release. The public integration must reconcile identity/citation values
with that dependency and explicitly test wire compatibility. No earlier internal
wire identity or digest compatibility is claimed.

The bundle is a one-time construction input. Publish and consume the resulting
independently versioned package after its own acceptance. Do not use this directory
as a permanent copied implementation dependency.

No parser, database, source vault, credential implementation, product UI or network
transport is included. Evidence adapters and provider ports remain trusted code;
document text cannot supply them. Protocol conformance is not evidence validation.
