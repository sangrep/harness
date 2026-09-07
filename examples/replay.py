"""Replay request commitments and compare the complete public result."""

import json

from sangrep_harness import (
    ExtractiveFakeProviderV1,
    ReplayProviderV1,
    review_snapshot_v1,
    snapshot_text_v1,
)

snapshot = snapshot_text_v1(
    b"The filter is inspected every fourteen days.\n", relative_path="rules.txt"
)
first = review_snapshot_v1(
    snapshot, question="Quote the rule.", provider=ExtractiveFakeProviderV1()
)
provider = ReplayProviderV1(first.transcript)
second = review_snapshot_v1(snapshot, question="Quote the rule.", provider=provider)
provider.require_exhausted()
assert first.to_json_obj() == second.to_json_obj()
print(json.dumps({"replayEqual": True, "receiptSha256": first.terminal.receipt.digest}))
