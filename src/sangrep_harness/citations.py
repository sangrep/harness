from __future__ import annotations

import re
from dataclasses import dataclass
from typing import cast

from sangrep_harness.grants import (
    GrantViolation,
    GrantViolationCodeV1,
    ReviewEvidenceHeadV1,
    SuccessfulToolCallV1,
)
from sangrep_harness.ports import evidence_port_boundary
from sangrep_harness.review import (
    CitationAdmissionV1,
    CitationResolutionV1,
    ReviewSemanticError,
    ReviewSemanticErrorCodeV1,
    StructuralGrantV1,
)
from sangrep_harness.wire import CitationResolutionStateV1, JsonValue

_STABLE_ID_CITATION_RE = re.compile(r"\[id:([A-Za-z0-9._:/-]+)\]")


@dataclass(frozen=True)
class ExtractedCitation:
    """A citation label parsed from agent output."""

    citation_label: str
    stable_id: str
    output_span_start: int
    output_span_end: int


def extract_stable_id_citations(output: str) -> tuple[ExtractedCitation, ...]:
    """Return exact inline ``[id:<stable_id>]`` citations in first-seen order."""

    return tuple(
        ExtractedCitation(
            citation_label=match.group(0),
            stable_id=match.group(1),
            output_span_start=match.start(),
            output_span_end=match.end(),
        )
        for match in _STABLE_ID_CITATION_RE.finditer(output)
    )


@evidence_port_boundary
def admit_citation(
    address: object,
    *,
    grant: StructuralGrantV1,
    evidence_head: ReviewEvidenceHeadV1,
    successful_tool_calls: tuple[SuccessfulToolCallV1, ...],
) -> CitationAdmissionV1:
    """Admit only a resolvable in-grant address from exact successful-tool support."""

    evidence_head.require_grant(grant)
    call_ids = _successful_call_ids(successful_tool_calls, grant=grant, evidence_head=evidence_head)
    try:
        citation = CitationAdmissionV1.create(
            address=address,
            grant=grant,
            admitted_tool_call_ids=call_ids,
        )
    except ReviewSemanticError as error:
        code = (
            GrantViolationCodeV1.OUT_OF_SCOPE
            if error.code
            in {
                ReviewSemanticErrorCodeV1.CROSS_GRANT,
                ReviewSemanticErrorCodeV1.MIXED_VERSION,
            }
            else GrantViolationCodeV1.UNADMITTED_CITATION
        )
        raise GrantViolation(code, "Citation is not admitted by this review run.") from error
    state, reason = _resolution_state(
        citation,
        grant=grant,
        evidence_head=evidence_head,
        successful_tool_calls=successful_tool_calls,
    )
    if state is not CitationResolutionStateV1.RESOLVED:
        code = {
            CitationResolutionStateV1.OUT_OF_SCOPE: GrantViolationCodeV1.OUT_OF_SCOPE,
            CitationResolutionStateV1.UNSUPPORTED: GrantViolationCodeV1.UNSUPPORTED,
            CitationResolutionStateV1.INVALID: GrantViolationCodeV1.UNADMITTED_CITATION,
        }[state]
        raise GrantViolation(code, f"Citation cannot be admitted: {reason}.")
    return citation


@evidence_port_boundary
def resolve_citation(
    citation: CitationAdmissionV1,
    *,
    grant: StructuralGrantV1,
    evidence_head: ReviewEvidenceHeadV1,
    successful_tool_calls: tuple[SuccessfulToolCallV1, ...],
) -> CitationResolutionV1:
    """Resolve an exact durable address or return one typed refusal without redirection."""

    if type(citation) is not CitationAdmissionV1 or type(grant) is not StructuralGrantV1:
        raise TypeError("citation and grant must use frozen review contracts")
    if citation.grant_id != grant.grant_id or citation.grant_sha256 != grant.digest:
        raise GrantViolation(
            GrantViolationCodeV1.OUT_OF_SCOPE,
            "Citation belongs to another immutable structural grant.",
        )
    try:
        evidence_head.require_grant(grant)
    except GrantViolation as error:
        if error.code is not GrantViolationCodeV1.STALE_EVIDENCE:
            raise
        return CitationResolutionV1.create(
            citation=citation,
            grant=grant,
            state=CitationResolutionStateV1.INVALID,
            reason_code="stale_evidence",
        )
    state, reason = _resolution_state(
        citation,
        grant=grant,
        evidence_head=evidence_head,
        successful_tool_calls=successful_tool_calls,
    )
    return CitationResolutionV1.create(
        citation=citation,
        grant=grant,
        state=state,
        reason_code=reason,
    )


def _resolution_state(
    citation: CitationAdmissionV1,
    *,
    grant: StructuralGrantV1,
    evidence_head: ReviewEvidenceHeadV1,
    successful_tool_calls: tuple[SuccessfulToolCallV1, ...],
) -> tuple[CitationResolutionStateV1, str | None]:
    address = citation.address.to_json_obj()
    binding = grant.evidence_binding
    if (
        address["evidenceVersionId"] != binding.evidence_version_id
        or address["structureRevisionId"] != binding.structure_revision_id
        or address["projectionRevisionId"] != binding.projection_revision_id
        or address["projectionPayloadSha256"] != binding.projection_payload_sha256
    ):
        return CitationResolutionStateV1.OUT_OF_SCOPE, "outside_run_grant"
    root_id = cast(str, address["rootAnchorId"])
    if root_id not in {root.stable_id for root in grant.evidence_roots}:
        return CitationResolutionStateV1.OUT_OF_SCOPE, "outside_run_grant"
    anchor_id = cast(str, address["anchorId"])
    occurrence_id = address["occurrenceId"]
    if type(occurrence_id) is not str:
        return CitationResolutionStateV1.INVALID, "missing_occurrence"
    canonical = evidence_head.canonical_node(anchor_id, occurrence_id)
    projected = evidence_head.projected_node(anchor_id, occurrence_id)
    if canonical is None or projected is None:
        return CitationResolutionStateV1.INVALID, "missing_occurrence"
    if evidence_head.root_for_anchor(grant, anchor_id, occurrence_id) != root_id:
        return CitationResolutionStateV1.OUT_OF_SCOPE, "outside_run_grant"
    selector = cast(dict[str, JsonValue], address["selector"])
    if selector.get("kind") != "node" or selector.get("anchorId") != anchor_id:
        return CitationResolutionStateV1.UNSUPPORTED, "unsupported_selector"
    if projected.citable_state != "citable":
        return CitationResolutionStateV1.UNSUPPORTED, "limited_evidence"
    projection = evidence_head.projection_revision
    if (
        address["projectionProfileId"] != projection.projection_profile_id
        or address["projectionProfileVersion"] != projection.projection_profile_version
    ):
        return CitationResolutionStateV1.INVALID, "projection_profile_mismatch"
    admitted_call_id = cast(str, address["admittedByToolCallId"])
    exact_quote_sha256 = address["exactQuoteSha256"]
    support = next(
        (
            item
            for call in successful_tool_calls
            if call.call_id == admitted_call_id
            for item in call.supports
            if (
                item.root_anchor_id,
                item.anchor_id,
                item.occurrence_id,
                item.projected_payload_sha256,
            )
            == (
                root_id,
                anchor_id,
                occurrence_id,
                projected.projected_payload_sha256,
            )
        ),
        None,
    )
    if support is None or (
        exact_quote_sha256 is not None and exact_quote_sha256 != support.exact_quote_sha256
    ):
        return CitationResolutionStateV1.INVALID, "missing_tool_support"
    return CitationResolutionStateV1.RESOLVED, None


def _successful_call_ids(
    calls: tuple[SuccessfulToolCallV1, ...],
    *,
    grant: StructuralGrantV1,
    evidence_head: ReviewEvidenceHeadV1,
) -> tuple[str, ...]:
    if type(calls) is not tuple:
        raise GrantViolation(
            GrantViolationCodeV1.INVALID_ARGUMENT,
            "Successful-tool ledger must be immutable.",
        )
    call_ids: list[str] = []
    for call in calls:
        if (
            type(call) is not SuccessfulToolCallV1
            or call.authorization.grant_id != grant.grant_id
            or call.authorization.grant_sha256 != grant.digest
            or call.authorization.evidence_head_sha256 != evidence_head.digest
            or call.call_id in call_ids
        ):
            raise GrantViolation(
                GrantViolationCodeV1.UNADMITTED_CITATION,
                "Successful-tool ledger crosses grant or evidence authority.",
            )
        call_ids.append(call.call_id)
    return tuple(call_ids)
