# Sangrep Harness

A Python backend library and headless JSON/JSONL CLI for bounded, cited evidence
review. Use immutable Markdown/TXT snapshots, deterministic fake or replay
providers, and explicit evidence/provider interfaces to build review into another
application. No API key is needed for the reference examples.

The engine constrains tool use, resource budgets, citation admission, containment
and repair. Claims must cite admitted evidence or be represented as an explicit
gap. Consequential output remains a proposal for the caller to inspect.

## Start in five minutes

Python 3.11 and [uv](https://docs.astral.sh/uv/getting-started/installation/) are
required for the development workflow:

```bash
git clone https://github.com/sangrep/harness.git
cd harness
./scripts/bootstrap
source .venv/bin/activate
sangrep-harness review corpus/operations.md --question "Quote the operating rules."
./scripts/check
```

The bootstrap builds the contracts dependency from a pinned source archive and
verifies exact wheel equality before installing it. A supplied wheel can be passed
with `./scripts/bootstrap --wheel path/to/sangrep_contracts-0.1.0.dev0-py3-none-any.whl`.
No mutable source dependency or package-registry release is assumed.

Read the [quickstart](docs/guides/quickstart.md), [authority model](docs/concepts/authority.md),
[evidence and citations](docs/concepts/evidence.md), [replay](docs/concepts/replay.md),
[compatibility](docs/compatibility.md), [threat model](docs/threat-model.md), and
[evaluation limits](docs/evaluation.md). The [synthetic corpus](corpus/README.md)
contains inspectable evidence for examples and tests.

## Developer documentation

```bash
python -m mkdocs serve --dev-addr 127.0.0.1:8000
```

MkDocs Material and mkdocstrings produce the concepts, guides and API reference.
`./scripts/check-docs` creates a scanned local preview in `work/docs-site`. CI
uploads this preview and the checked wheel as short-lived artifacts. GitHub Pages
is the intended documentation destination; this repository does not deploy it as
part of a PR check.

## Integration boundary

The harness uses `sangrep-contracts==0.1.0.dev0` from the exact artifact recorded in
[provenance/contracts-v1.json](provenance/contracts-v1.json). Evidence is read-only;
models have no arbitrary filesystem or tool authority. Python adapters are trusted
host code and need their own integration review.

This component does not implement a frontend, rich-document parser, workspace or
credential storage, product authentication or licensing service. Deterministic
mechanical checks do not establish semantic correctness, live-provider
qualification, product behavior, release or public-support commitment.

## Contribute and report

Read [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md) and
[AGENTS.md](AGENTS.md). Run focused tests while iterating and `./scripts/check` at
the frozen head. Report vulnerabilities through [SECURITY.md](SECURITY.md), not a
public Issue. Public questions and support boundaries are in [SUPPORT.md](SUPPORT.md).

## License and origin

Approved intent: `AGPL-3.0-or-later OR LicenseRef-Sangrep-Commercial`, where the
commercial alternative requires a separate Sangrep agreement. The current
[LICENSE](LICENSE) retains its publication gate. Package metadata and technical
checks do not claim specialist legal review or contributor-rights acceptance.
See [ORIGIN.md](ORIGIN.md), [NOTICE](NOTICE), and the
[licensing guide](docs/development/licensing.md).
