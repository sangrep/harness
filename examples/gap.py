"""An unanswered question becomes a gap; missing records do not prove absence."""

import json

from sangrep_harness import ExtractiveFakeProviderV1, review_snapshot_v1, snapshot_text_v1

snapshot = snapshot_text_v1(
    b"No repair completion date is recorded here.\n", relative_path="notes.txt"
)
result = review_snapshot_v1(
    snapshot, question="When was the repair completed?", provider=ExtractiveFakeProviderV1("gap")
)
assert result.draft.outcome.value == "evidence_gap"
assert result.draft.answer is None
print(json.dumps({"outcome": result.draft.outcome.value, "gaps": result.draft.evidence_gap_codes}))
