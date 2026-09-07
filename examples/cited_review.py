"""Quote actual source text through the bounded engine and public citations."""

import json
from pathlib import Path

from sangrep_harness import ExtractiveFakeProviderV1, review_snapshot_v1, snapshot_file_v1

snapshot = snapshot_file_v1(Path(__file__).resolve().parents[1] / "corpus/operations.md")
result = review_snapshot_v1(
    snapshot, question="Quote the operating rules.", provider=ExtractiveFakeProviderV1()
)
assert result.draft.outcome.value == "supported_answer"
print(
    json.dumps(
        {
            "outcome": result.draft.outcome.value,
            "answer": result.draft.answer,
            "receiptSha256": result.terminal.receipt.digest,
        }
    )
)
