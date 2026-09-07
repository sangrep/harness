# Five-minute quickstart

You need Python 3.11, Git and [uv](https://docs.astral.sh/uv/getting-started/installation/).
The reference examples use synthetic evidence and deterministic providers. No API
key or live model call is required.

## Install from the checkout

```bash
git clone https://github.com/sangrep/harness.git
cd harness
./scripts/bootstrap
source .venv/bin/activate
```

Bootstrap installs hash-locked tools, downloads contracts at the accepted commit,
verifies its archive digest, rebuilds and verifies its exact wheel, and installs a
wheel of this checkout. To supply an already accepted contracts wheel, use
`./scripts/bootstrap --wheel path/to/sangrep_contracts-0.1.0.dev0-py3-none-any.whl`.
The same digest check applies. This is development installation from versioned
artifacts; no package-registry release is assumed.

## Run a cited review

```bash
sangrep-harness review corpus/operations.md --question "Quote the operating rules."
sangrep-harness run < examples/request.json
sangrep-harness run --jsonl < examples/batch.jsonl
```

The first result contains `outcome: supported_answer`, quoted evidence with
`[id:...]` labels, public citation addresses, a terminal result, an event chain and a
receipt. It also sets `proposalOnly: true`. The fake provider demonstrates mechanics
by quoting up to three paragraph nodes; it does not perform semantic inference.

## Use the library

```python
from sangrep_harness import (
    ExtractiveFakeProviderV1,
    review_snapshot_v1,
    snapshot_text_v1,
)

snapshot = snapshot_text_v1(
    b"Only observers may enter.\n",
    relative_path="rules.txt",
)
result = review_snapshot_v1(
    snapshot,
    question="Quote the access rule.",
    provider=ExtractiveFakeProviderV1(),
)
print(result.to_json_obj()["outcome"])
```

Run `python examples/replay.py` to compare exact results, or try the
[adapter](adapters.md), [gap and failure](outcomes.md), and [CLI](cli.md) guides.

## Verify and preview

```bash
./scripts/check
python -m mkdocs serve --dev-addr 127.0.0.1:8000
```

The docs server is local. CI uploads an inspectable static artifact for a future
GitHub Pages deployment; it does not deploy. Read the [threat model](../threat-model.md)
before supplying your own material.
