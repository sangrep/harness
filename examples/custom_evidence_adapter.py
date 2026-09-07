"""A caller-controlled text catalog adapts to immutable snapshots without ambient I/O."""

import json
from dataclasses import dataclass

from sangrep_harness import (
    ExtractiveFakeProviderV1,
    TextSnapshotV1,
    review_snapshot_v1,
    snapshot_text_v1,
)


@dataclass(frozen=True)
class CatalogAdapter:
    records: tuple[tuple[str, bytes], ...]

    def snapshot(self, identifier: str) -> TextSnapshotV1:
        matches = [raw for key, raw in self.records if key == identifier]
        if len(matches) != 1:
            raise ValueError("catalog-selection-missing-or-ambiguous")
        return snapshot_text_v1(matches[0], relative_path="catalog-note.txt")


adapter = CatalogAdapter((("observatory-note", b"The gallery remains open.\n"),))
result = review_snapshot_v1(
    adapter.snapshot("observatory-note"),
    question="Quote the note.",
    provider=ExtractiveFakeProviderV1(),
)
assert result.draft.outcome.value == "supported_answer"
print(json.dumps({"outcome": result.draft.outcome.value, "citations": len(result.draft.citations)}))
