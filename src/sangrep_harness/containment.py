from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sangrep_harness.citations import extract_stable_id_citations
from sangrep_harness.grants import ReviewEvidenceHeadV1, SuccessfulToolCallV1
from sangrep_harness.ports import evidence_port_boundary
from sangrep_harness.review import StructuralGrantV1


class CitationContainmentError(RuntimeError):
    """Raised when citation containment validation cannot be performed safely."""


@dataclass(frozen=True)
class CitationContainmentViolation:
    """A citation that references a stable ID outside the rendered scope."""

    citation_label: str
    stable_id: str
    output_span_start: int
    output_span_end: int


def validate_citations_within_scope(
    output: str,
    allowed_stable_ids: Iterable[str],
) -> tuple[CitationContainmentViolation, ...]:
    """Return citations whose stable IDs are absent from the rendered scope manifest."""

    allowed = set(allowed_stable_ids)
    return tuple(
        CitationContainmentViolation(
            citation_label=citation.citation_label,
            stable_id=citation.stable_id,
            output_span_start=citation.output_span_start,
            output_span_end=citation.output_span_end,
        )
        for citation in extract_stable_id_citations(output)
        if citation.stable_id not in allowed
    )


@evidence_port_boundary
def validate_citations_within_structural_grant(
    output: str,
    *,
    grant: StructuralGrantV1,
    evidence_head: ReviewEvidenceHeadV1,
    successful_tool_calls: tuple[SuccessfulToolCallV1, ...],
) -> tuple[CitationContainmentViolation, ...]:
    """Validate legacy inline labels against exact successful-tool grant evidence."""

    evidence_head.require_grant(grant)
    allowed: set[str] = set()
    seen_calls: set[str] = set()
    for call in successful_tool_calls:
        if (
            type(call) is not SuccessfulToolCallV1
            or call.call_id in seen_calls
            or call.authorization.grant_id != grant.grant_id
            or call.authorization.grant_sha256 != grant.digest
            or call.authorization.evidence_head_sha256 != evidence_head.digest
        ):
            raise CitationContainmentError(
                "Successful-tool evidence does not match the structural grant."
            )
        seen_calls.add(call.call_id)
        for support in call.supports:
            projected = evidence_head.projected_node(
                support.anchor_id,
                support.occurrence_id,
            )
            if (
                projected is not None
                and projected.citable_state == "citable"
                and projected.projected_payload_sha256 == support.projected_payload_sha256
                and evidence_head.root_for_anchor(
                    grant,
                    support.anchor_id,
                    support.occurrence_id,
                )
                == support.root_anchor_id
            ):
                allowed.add(support.anchor_id)
    return validate_citations_within_scope(output, allowed)
