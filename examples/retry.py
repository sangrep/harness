"""A completed same-process run returns its exact receipt with no repeated provider call."""

import json

from sangrep_harness import (
    ExtractiveFakeProviderV1,
    InMemoryRunRepositoryV1,
    review_snapshot_v1,
    snapshot_text_v1,
)

snapshot = snapshot_text_v1(b"Synthetic evidence.\n", relative_path="notes.txt")
repository = InMemoryRunRepositoryV1()
first = review_snapshot_v1(
    snapshot,
    question="Quote the note.",
    provider=ExtractiveFakeProviderV1(),
    run_repository=repository,
)
second = review_snapshot_v1(
    snapshot,
    question="Quote the note.",
    provider=ExtractiveFakeProviderV1("failure"),
    run_repository=repository,
)
assert first.to_json_obj() == second.to_json_obj()
print(json.dumps({"retryEqual": True, "durableRestartQualified": False}))
