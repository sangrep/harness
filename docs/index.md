# Sangrep Harness

Build evidence review into a Python application, or run it as a headless JSON/JSONL
process. The harness uses bounded tools and immutable evidence identities to keep
review output tied to admitted source text. Its reference adapters handle Markdown
and UTF-8 plain text; fake and replay providers make behavior reproducible without
network calls.

Start with the [quickstart](guides/quickstart.md), then read about
[authority](concepts/authority.md), [evidence and citations](concepts/evidence.md),
and [deterministic replay](concepts/replay.md).

The [threat model](threat-model.md) describes what the engine checks and what an
integrator must enforce. The [evaluation guide](evaluation.md) distinguishes
mechanical citation validity from semantic correctness. The [compatibility
contract](compatibility.md) records the accepted dependency artifact.

This development package produces proposals. It is not a rich-document parser,
credential store, autonomous shell or product runtime. A successful check does not
establish release, provider qualification or supported product behavior.
