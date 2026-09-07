"""Immutable reference evidence ingestion and hierarchy boundaries."""

import dataclasses
import hashlib
import importlib

import pytest


def _snapshot_module():
    try:
        return importlib.import_module("sangrep_harness.text_snapshot")
    except ModuleNotFoundError:
        pytest.fail("immutable text snapshot adapter is absent")


def test_snapshot_is_deterministic_and_uses_public_contracts():
    module = _snapshot_module()
    from sangrep_contracts import EvidenceNodeV1, ProjectedNodeV1

    raw = b"# Access\n\nOnly observers may enter.\n"
    first = module.snapshot_text_v1(raw, relative_path="access.md")
    second = module.snapshot_text_v1(raw, relative_path="access.md")
    assert first == second
    assert first.source.content_sha256 == hashlib.sha256(raw).hexdigest()
    assert all(isinstance(node, EvidenceNodeV1) for node in first.nodes)
    assert all(isinstance(node, ProjectedNodeV1) for node in first.projections)
    assert any(node.node_kind.value == "heading" for node in first.nodes)
    with pytest.raises(dataclasses.FrozenInstanceError):
        first.text = "changed"


def test_file_change_does_not_change_admitted_snapshot(tmp_path):
    module = _snapshot_module()
    source = tmp_path / "source.txt"
    source.write_bytes(b"Original evidence.\n")
    before = module.snapshot_file_v1(source)
    source.write_bytes(b"Replacement evidence.\n")
    after = module.snapshot_file_v1(source)
    assert before.text == "Original evidence.\n"
    assert before.evidence.evidence_version_id != after.evidence.evidence_version_id
    assert source.read_bytes() == b"Replacement evidence.\n"


def test_fenced_headings_are_text_not_structure():
    module = _snapshot_module()
    snapshot = module.snapshot_text_v1(
        b"# Heading\n```text\n# Example\n```\n", relative_path="a.md"
    )
    headings = [node for node in snapshot.nodes if node.node_kind.value == "heading"]
    assert len(headings) == 1


@pytest.mark.parametrize("label", ["../a.md", "/a.md", "a.pdf"])
def test_rejects_unsafe_or_unsupported_labels(label):
    module = _snapshot_module()
    with pytest.raises(ValueError):
        module.snapshot_text_v1(b"Synthetic evidence", relative_path=label)


@pytest.mark.parametrize(
    "raw",
    [b"\xff", b"binary\x00content", b"x" * (1024 * 1024 + 1)],
    ids=["invalid-utf8", "nul", "oversized"],
)
def test_rejects_invalid_or_oversized_text(raw):
    module = _snapshot_module()
    with pytest.raises(ValueError):
        module.snapshot_text_v1(raw, relative_path="a.txt")


def test_does_not_follow_source_symlinks(tmp_path):
    module = _snapshot_module()
    source = tmp_path / "source.txt"
    source.write_text("Synthetic evidence")
    link = tmp_path / "link.txt"
    link.symlink_to(source)
    with pytest.raises(ValueError):
        module.snapshot_file_v1(link)
