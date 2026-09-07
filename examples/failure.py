"""A provider failure produces a typed outcome without exception payloads."""

import json

from sangrep_harness import ExtractiveFakeProviderV1, review_snapshot_v1, snapshot_text_v1

snapshot = snapshot_text_v1(b"Synthetic evidence.\n", relative_path="notes.txt")
result = review_snapshot_v1(
    snapshot, question="Review the note.", provider=ExtractiveFakeProviderV1("failure")
)
assert result.draft.outcome.value == "provider_failed"
assert "synthetic-provider-failure" not in json.dumps(result.to_json_obj())
print(json.dumps({"outcome": result.draft.outcome.value, "proposalOnly": True}))
