from __future__ import annotations

from sangrep_harness.review import (
    EvidenceBindingV1,
    EvidenceIdentityDraftsV1,
    EvidenceRootRefV1,
    ReviewLimitsV1,
    StructuralGrantV1,
)
from sangrep_harness.wire import canonical_json_sha256_v1, freeze_json_object_v1


def _limits(*, max_total_tokens: int = 16_000) -> ReviewLimitsV1:
    return ReviewLimitsV1(
        max_iterations=6,
        max_tool_calls=8,
        max_total_tokens=max_total_tokens,
        deadline_ms=60_000,
        max_child_tasks=0,
        max_concurrency=0,
    )


def _grant(*, suffix: str = "01", media_ids: tuple[str, ...] = ()) -> StructuralGrantV1:
    evidence = {
        "schemaVersion": 1,
        "kind": "evidenceVersion",
        "evidenceVersionId": f"evidence_{suffix}",
        "sourceVersionIds": [f"source_{suffix}"],
        "adapterProfileId": "text-reference",
        "adapterProfileSha256": "1" * 64,
        "coverageState": "complete",
        "warningCodes": [],
        "blockerCodes": [],
        "canonicalOutputSha256": "2" * 64,
    }
    structure = {
        "schemaVersion": 1,
        "kind": "structureRevision",
        "structureRevisionId": f"structure_{suffix}",
        "evidenceVersionId": f"evidence_{suffix}",
        "structureProfileId": "canonical-v1",
        "structureProfileSha256": "4" * 64,
        "graphSha256": "5" * 64,
    }
    projection = {
        "schemaVersion": 1,
        "kind": "projectionRevision",
        "projectionRevisionId": f"projection_{suffix}",
        "structureRevisionId": f"structure_{suffix}",
        "projectionProfileId": "model-text-v1",
        "projectionProfileVersion": "1",
        "projectionProfileSha256": "7" * 64,
        "payloadSha256": "8" * 64,
    }
    drafts = EvidenceIdentityDraftsV1(
        evidence_version=freeze_json_object_v1(evidence),
        structure_revision=freeze_json_object_v1(structure),
        projection_revision=freeze_json_object_v1(projection),
    )
    binding = EvidenceBindingV1.from_json_obj(
        {
            "schemaVersion": 1,
            "kind": "evidenceBinding",
            "contractId": "sangrep.harness.review.v1",
            "sourceVersionId": f"source_{suffix}",
            "sourceContentSha256": "1" * 64,
            "evidenceVersionId": f"evidence_{suffix}",
            "evidenceRecordSha256": canonical_json_sha256_v1(drafts.evidence_version.to_json_obj()),
            "evidenceCanonicalOutputSha256": "2" * 64,
            "structureRevisionId": f"structure_{suffix}",
            "structureRecordSha256": canonical_json_sha256_v1(
                drafts.structure_revision.to_json_obj()
            ),
            "structureGraphSha256": "5" * 64,
            "projectionRevisionId": f"projection_{suffix}",
            "projectionRecordSha256": canonical_json_sha256_v1(
                drafts.projection_revision.to_json_obj()
            ),
            "projectionPayloadSha256": "8" * 64,
        },
        draft_identities=drafts,
    )
    return StructuralGrantV1(
        grant_id=f"grant_{suffix}",
        evidence_binding=binding,
        evidence_roots=(EvidenceRootRefV1(f"evidence_{suffix}", "section-a"),),
        tool_names=("read_nodes", "search"),
        media_ids=media_ids,
        limits=_limits(),
    )
