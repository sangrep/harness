"""Synthetic adapter shape, citation compatibility and typed refusal checks."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from synthetic_helpers import _grant

from sangrep_harness.citations import admit_citation, resolve_citation
from sangrep_harness.grants import ToolEvidenceSupportV1, create_structural_grant_v1
from sangrep_harness.ports import ReviewEvidenceHeadV1
from sangrep_harness.tools import AdmittedToolRegistryV1, HarnessToolResult
from sangrep_harness.wire import CitationResolutionStateV1


def head_fixture():
    grant = _grant()
    node = SimpleNamespace(
        stable_id="section-a",
        occurrence_id="occ-1",
        parent_stable_id=None,
        parent_occurrence_id=None,
        kind=SimpleNamespace(value="paragraph"),
        ordinal=0,
        title_or_none=None,
        text_or_none="Synthetic evidence",
        coverage=SimpleNamespace(value="complete"),
        limitation_code_or_none=None,
    )
    projected = SimpleNamespace(
        anchor_id=node.stable_id,
        occurrence_id=node.occurrence_id,
        projection_revision_id=grant.evidence_binding.projection_revision_id,
        structure_revision_id=grant.evidence_binding.structure_revision_id,
        payload_kind="markdown",
        payload="Synthetic evidence",
        inclusion_state="included",
        citable_state="citable",
        projected_payload_sha256="9" * 64,
        limitation_codes=(),
    )
    canonical = SimpleNamespace(
        evidence_version_id=grant.evidence_binding.evidence_version_id,
        structure_revision_id=grant.evidence_binding.structure_revision_id,
        source_sha256=grant.evidence_binding.source_content_sha256,
        semantic_ir_sha256=grant.evidence_binding.evidence_canonical_output_sha256,
        canonicalization_profile_id="synthetic",
        canonicalization_profile_sha256="4" * 64,
        root_stable_id=node.stable_id,
        nodes=(node,),
        digest=grant.evidence_binding.structure_graph_sha256,
        to_structure_revision_json=lambda: {},
    )
    projection = SimpleNamespace(
        projection_revision_id=grant.evidence_binding.projection_revision_id,
        structure_revision_id=grant.evidence_binding.structure_revision_id,
        projection_kind="model_text",
        projection_profile_id="model-text-v1",
        projection_profile_version="1",
        projection_profile_sha256="7" * 64,
        payload_sha256=grant.evidence_binding.projection_payload_sha256,
        nodes=(projected,),
        to_projection_revision_json=lambda: {},
    )
    return SimpleNamespace(
        source_format="txt",
        evidence_binding=grant.evidence_binding,
        digest="a" * 64,
        canonical_revision=canonical,
        projection_revision=projection,
        require_grant=lambda g: None,
        canonical_node=lambda a, o: node,
        projected_node=lambda a, o: projected,
        root_for_anchor=lambda g, a, o: node.stable_id,
        require_stable_ids_in_grant=lambda g, ids: None,
        _unique_node_for_stable_id=lambda a: node,
        _is_descendant_or_self=lambda n, r: n is r,
        granted_nodes=lambda g: (node,),
        descendants_or_self=lambda g, a: (node,),
        depth_from=lambda n, r: 0,
    )


def mint(head):
    original = _grant()
    return create_structural_grant_v1(
        grant_id="synthetic-grant",
        reviewer_selected_roots=original.evidence_roots,
        evidence_head=head,
        tool_names=original.tool_names,
        media_ids=(),
        limits=original.limits,
    )


@pytest.mark.parametrize(
    "member",
    [
        "projection_revision",
        "canonical_revision",
        "granted_nodes",
        "descendants_or_self",
        "depth_from",
    ],
)
def test_missing_consumed_head_members_cannot_satisfy_port_or_mint_grant(member):
    head = head_fixture()
    delattr(head, member)
    assert not isinstance(head, ReviewEvidenceHeadV1)
    with pytest.raises(ValueError) as refusal:
        mint(head)
    assert refusal.value.code == "invalid_evidence_adapter"


@pytest.mark.parametrize(
    "change",
    [
        lambda h: setattr(h, "projection_revision", None),
        lambda h: setattr(h, "granted_nodes", "not callable"),
        lambda h: setattr(h.projection_revision, "nodes", [h.projection_revision.nodes[0]]),
        lambda h: delattr(h.projection_revision, "projection_profile_id"),
        lambda h: setattr(h.canonical_revision.nodes[0], "kind", None),
        lambda h: setattr(h.projection_revision.nodes[0], "payload", None),
    ],
)
def test_invalid_nested_adapter_shapes_refuse_before_mint(change):
    head = head_fixture()
    change(head)
    with pytest.raises(ValueError) as refusal:
        mint(head)
    assert refusal.value.code == "invalid_evidence_adapter"


def successful_tool(head, grant):
    registry = AdmittedToolRegistryV1()
    call = registry.authorize(
        "read_nodes",
        {"stableIds": ["section-a"]},
        call_id="call-1",
        grant=grant,
        evidence_head=head,
    )
    result = HarnessToolResult(
        call_id="call-1",
        name="read_nodes",
        status="succeeded",
        payload={},
        projection_digest=head.projection_revision.payload_sha256,
        citable_stable_ids=("section-a",),
        citable_evidence=(
            ToolEvidenceSupportV1("section-a", "section-a", "occ-1", "9" * 64, "9" * 64),
        ),
    )
    return registry.record_success(call, result, grant=grant, evidence_head=head)


def test_complete_synthetic_adapter_mints_tool_support_and_resolves_citation():
    head = head_fixture()
    assert isinstance(head, ReviewEvidenceHeadV1)
    grant = mint(head)
    support = successful_tool(head, grant)
    address = {
        "schemaVersion": 1,
        "kind": "citationAddress",
        "evidenceVersionId": grant.evidence_binding.evidence_version_id,
        "structureRevisionId": grant.evidence_binding.structure_revision_id,
        "projectionRevisionId": grant.evidence_binding.projection_revision_id,
        "rootAnchorId": "section-a",
        "anchorId": "section-a",
        "occurrenceId": "occ-1",
        "selector": {"kind": "node", "anchorId": "section-a"},
        "exactQuoteSha256": "9" * 64,
        "projectionProfileId": "model-text-v1",
        "projectionProfileVersion": "1",
        "projectionPayloadSha256": head.projection_revision.payload_sha256,
        "admittedByToolCallId": "call-1",
    }
    citation = admit_citation(
        address, grant=grant, evidence_head=head, successful_tool_calls=(support,)
    )
    resolved = resolve_citation(
        citation, grant=grant, evidence_head=head, successful_tool_calls=(support,)
    )
    assert resolved.state is CitationResolutionStateV1.RESOLVED


def test_bad_projection_method_result_is_typed_refusal_not_attribute_error():
    head = head_fixture()
    grant = mint(head)
    head.projected_node = lambda a, o: object()
    with pytest.raises(ValueError) as refusal:
        successful_tool(head, grant)
    assert refusal.value.code == "invalid_evidence_adapter"
