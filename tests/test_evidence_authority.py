"""A Python adapter object is insufficient authority; immutable bytes must agree."""

from dataclasses import replace

import pytest

from sangrep_harness.text_snapshot import snapshot_text_v1


def _head(snapshot):
    from sangrep_harness import evidence_head

    factory = getattr(evidence_head, "text_evidence_head_v1", None)
    assert factory is not None, "validated evidence-head constructor is absent"
    return factory(snapshot)


def test_accepted_snapshot_creates_exact_head():
    snapshot = snapshot_text_v1(b"# Scope\nOnly observers enter.\n", relative_path="a.md")
    head = _head(snapshot)
    assert head.evidence_binding.evidence_version_id == snapshot.evidence.evidence_version_id


@pytest.mark.parametrize("field", ["text", "source_bytes", "nodes", "projections"])
def test_forged_snapshot_cannot_become_authority(field):
    snapshot = snapshot_text_v1(b"# Scope\nOnly observers enter.\n", relative_path="a.md")
    values = {
        "text": "Forged",
        "source_bytes": b"Forged",
        "nodes": snapshot.nodes[::-1],
        "projections": snapshot.projections[::-1],
    }
    with pytest.raises(ValueError, match="snapshot-authority"):
        _head(replace(snapshot, **{field: values[field]}))
