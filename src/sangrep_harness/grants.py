from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from sangrep_harness.ports import EvidenceNodeV1, evidence_port_boundary
from sangrep_harness.ports import ReviewEvidenceHeadV1 as ReviewEvidenceHeadV1
from sangrep_harness.review import EvidenceRootRefV1, ReviewLimitsV1, StructuralGrantV1
from sangrep_harness.wire import FrozenJsonObjectV1, JsonValue, canonical_json_sha256_v1

REVIEW_TOOL_NAMES = (
    "list_scope",
    "outline",
    "read_nodes",
    "search",
    "query_blocks",
)


MAX_GRANT_ROOTS = 256


_RUNTIME_AUTHORITY = object()


class GrantViolationCodeV1(StrEnum):
    """Closed runtime refusal classes before evidence or tool execution."""

    INVALID_ARGUMENT = "invalid_argument"
    MIXED_VERSION = "mixed_version"
    STALE_EVIDENCE = "stale_evidence"
    OVERLAPPING_ROOTS = "overlapping_roots"
    OUT_OF_SCOPE = "out_of_scope"
    UNADMITTED_TOOL = "unadmitted_tool"
    UNADMITTED_CITATION = "unadmitted_citation"
    UNSUPPORTED = "unsupported"
    BUDGET_EXHAUSTED = "budget_exhausted"
    DUPLICATE_CALL = "duplicate_call"


class GrantViolation(RuntimeError):
    """One typed fail-closed runtime authority refusal."""

    def __init__(self, code: GrantViolationCodeV1, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class AuthorizedToolCallV1:
    """One call admitted before execution against an exact grant and head."""

    call_id: str
    name: str
    arguments: FrozenJsonObjectV1
    grant_id: str
    grant_sha256: str
    evidence_head_sha256: str
    ordinal: int
    _authority: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._authority is not _RUNTIME_AUTHORITY:
            raise GrantViolation(
                GrantViolationCodeV1.UNADMITTED_TOOL,
                "Tool authorization requires trusted registry authority.",
            )

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(
            {
                "callId": self.call_id,
                "name": self.name,
                "arguments": self.arguments.to_json_obj(),
                "grantId": self.grant_id,
                "grantSha256": self.grant_sha256,
                "evidenceHeadSha256": self.evidence_head_sha256,
                "ordinal": self.ordinal,
            }
        )


@dataclass(frozen=True, slots=True)
class ToolEvidenceSupportV1:
    """Exact citable projection payload emitted by one successful tool call."""

    root_anchor_id: str
    anchor_id: str
    occurrence_id: str
    projected_payload_sha256: str
    exact_quote_sha256: str

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "rootAnchorId": self.root_anchor_id,
            "anchorId": self.anchor_id,
            "occurrenceId": self.occurrence_id,
            "projectedPayloadSha256": self.projected_payload_sha256,
            "exactQuoteSha256": self.exact_quote_sha256,
        }


@dataclass(frozen=True, slots=True)
class SuccessfulToolCallV1:
    """Immutable provenance for citable evidence from a successful tool result."""

    authorization: AuthorizedToolCallV1
    result_sha256: str
    supports: tuple[ToolEvidenceSupportV1, ...]
    _authority: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._authority is not _RUNTIME_AUTHORITY:
            raise GrantViolation(
                GrantViolationCodeV1.UNADMITTED_CITATION,
                "Successful-tool provenance requires trusted registry authority.",
            )

    @property
    def call_id(self) -> str:
        return self.authorization.call_id

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(
            {
                "authorizationSha256": self.authorization.digest,
                "resultSha256": self.result_sha256,
                "supports": [support.to_json_obj() for support in self.supports],
            }
        )


@evidence_port_boundary
def create_structural_grant_v1(
    *,
    grant_id: str,
    reviewer_selected_roots: tuple[EvidenceRootRefV1, ...],
    evidence_head: ReviewEvidenceHeadV1,
    tool_names: tuple[str, ...],
    media_ids: tuple[str, ...],
    limits: ReviewLimitsV1,
) -> StructuralGrantV1:
    """Mint one grant solely from trusted selections and the current immutable head."""

    if not isinstance(evidence_head, ReviewEvidenceHeadV1):
        raise GrantViolation(
            GrantViolationCodeV1.INVALID_ARGUMENT,
            "Structural grant requires one trusted evidence head.",
        )
    if type(reviewer_selected_roots) is not tuple or not reviewer_selected_roots:
        raise GrantViolation(
            GrantViolationCodeV1.INVALID_ARGUMENT,
            "Reviewer selection must contain at least one immutable root.",
        )
    if len(reviewer_selected_roots) > MAX_GRANT_ROOTS:
        raise GrantViolation(
            GrantViolationCodeV1.BUDGET_EXHAUSTED,
            f"Reviewer selection exceeds the {MAX_GRANT_ROOTS}-root grant budget.",
        )
    if type(tool_names) is not tuple or not tool_names:
        raise GrantViolation(
            GrantViolationCodeV1.INVALID_ARGUMENT,
            "Structural grant must admit at least one bounded review tool.",
        )
    if any(name not in REVIEW_TOOL_NAMES for name in tool_names):
        raise GrantViolation(
            GrantViolationCodeV1.UNADMITTED_TOOL,
            "Structural grant contains a tool outside the closed review registry.",
        )
    canonical_roots: list[EvidenceNodeV1] = []
    for root in reviewer_selected_roots:
        if type(root) is not EvidenceRootRefV1:
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "Reviewer selection contains an invalid root.",
            )
        if root.evidence_version_id != evidence_head.evidence_binding.evidence_version_id:
            raise GrantViolation(
                GrantViolationCodeV1.MIXED_VERSION,
                "Reviewer selection mixes evidence versions.",
            )
        canonical_roots.append(evidence_head._unique_node_for_stable_id(root.stable_id))
    for index, first in enumerate(canonical_roots):
        for second in canonical_roots[index + 1 :]:
            if evidence_head._is_descendant_or_self(
                first, second
            ) or evidence_head._is_descendant_or_self(second, first):
                raise GrantViolation(
                    GrantViolationCodeV1.OVERLAPPING_ROOTS,
                    "Reviewer-selected structural roots must not overlap.",
                )
    try:
        return StructuralGrantV1(
            grant_id=grant_id,
            evidence_binding=evidence_head.evidence_binding,
            evidence_roots=reviewer_selected_roots,
            tool_names=tool_names,
            media_ids=media_ids,
            limits=limits,
        )
    except (TypeError, ValueError) as error:
        raise GrantViolation(
            GrantViolationCodeV1.INVALID_ARGUMENT,
            "Structural grant input is invalid.",
        ) from error


def _mint_authorized_tool_call_v1(
    *,
    call_id: str,
    name: str,
    arguments: FrozenJsonObjectV1,
    grant_id: str,
    grant_sha256: str,
    evidence_head_sha256: str,
    ordinal: int,
) -> AuthorizedToolCallV1:
    return AuthorizedToolCallV1(
        call_id=call_id,
        name=name,
        arguments=arguments,
        grant_id=grant_id,
        grant_sha256=grant_sha256,
        evidence_head_sha256=evidence_head_sha256,
        ordinal=ordinal,
        _authority=_RUNTIME_AUTHORITY,
    )


def _mint_successful_tool_call_v1(
    *,
    authorization: AuthorizedToolCallV1,
    result_sha256: str,
    supports: tuple[ToolEvidenceSupportV1, ...],
) -> SuccessfulToolCallV1:
    if authorization._authority is not _RUNTIME_AUTHORITY:
        raise GrantViolation(
            GrantViolationCodeV1.UNADMITTED_TOOL,
            "Successful result requires a trusted tool authorization.",
        )
    return SuccessfulToolCallV1(
        authorization=authorization,
        result_sha256=result_sha256,
        supports=supports,
        _authority=_RUNTIME_AUTHORITY,
    )
