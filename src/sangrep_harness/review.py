from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeAlias, TypeVar, cast

import sangrep_contracts as public_contracts

from sangrep_harness.diagnostics import ProviderFailureDiagnosticV1
from sangrep_harness.providers.base import (
    OpenAIProtocolIdV1,
    ProviderReasoningEffortV1,
    ProviderResponseFailureCodeV1,
)
from sangrep_harness.wire import (
    HARNESS_REVIEW_CONTRACT_ID,
    CitationResolutionStateV1,
    FrozenJsonObjectV1,
    JsonValue,
    ReviewCommandV1,
    ReviewMethodV1,
    TerminalOutcomeV1,
    canonical_json_sha256_v1,
    freeze_json_object_v1,
)

MAX_SAFE_INTEGER = 2**53 - 1


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


_CODE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")


_TOOL_NAME = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")


EnumV1 = TypeVar("EnumV1", bound=StrEnum)


class ReviewSemanticErrorCodeV1(StrEnum):
    """Closed refusal codes for evidence/review semantic contracts."""

    INVALID_VALUE = "invalid_value"
    MIXED_VERSION = "mixed_version"
    CROSS_GRANT = "cross_grant"
    UNADMITTED_TOOL = "unadmitted_tool"
    UNADMITTED_MEDIA = "unadmitted_media"
    UNADMITTED_CITATION = "unadmitted_citation"
    UNKNOWN_OUTCOME = "unknown_outcome"
    FALSE_COMPLETENESS = "false_completeness"
    UNSUPPORTED_EGRESS = "unsupported_egress"
    ANSWER_KEY_MATERIAL = "answer_key_material"
    HUMAN_AUTHORITY = "human_authority"


class ReviewSemanticError(ValueError):
    """Raised when a valid wire value violates review authority."""

    def __init__(
        self,
        message: str,
        *,
        code: ReviewSemanticErrorCodeV1 = ReviewSemanticErrorCodeV1.INVALID_VALUE,
    ) -> None:
        super().__init__(message)
        self.code = code


class CoverageStateV1(StrEnum):
    """Coverage claim carried separately from answer correctness."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    NOT_ASSESSED = "not_assessed"


class ContextLayerV1(StrEnum):
    """The three persistent instruction-context authorities."""

    APPLICATION = "application"
    USER = "user"
    WORKSPACE = "workspace"


class ClarificationModeV1(StrEnum):
    """Session-pinned clarification behavior."""

    AUTONOMOUS = "autonomous"
    ASK_WHEN_MATERIAL = "ask_when_material"
    COLLABORATIVE = "collaborative"


class EgressDataClassV1(StrEnum):
    """Data classes a standing egress policy may admit."""

    MODEL_PROJECTION = "model_projection"
    ADMITTED_MEDIA = "admitted_media"
    TOOL_RESULT = "tool_result"


class ProviderCallStateV1(StrEnum):
    """Receipt state for a provider boundary without implying result correctness."""

    NOT_REQUESTED = "not_requested"
    BLOCKED_PREFLIGHT = "blocked_preflight"
    SENT = "sent"
    COMPLETED = "completed"
    OUTCOME_UNKNOWN = "outcome_unknown"


@dataclass(frozen=True, slots=True)
class EvidenceRootRefV1:
    """One version-qualified structural root."""

    evidence_version_id: str
    stable_id: str

    def __post_init__(self) -> None:
        _require_identifier(self.evidence_version_id, field_name="evidence_version_id")
        _require_identifier(self.stable_id, field_name="stable_id")

    @classmethod
    def from_json_obj(cls, value: object) -> EvidenceRootRefV1:
        payload = _require_exact_object(
            value,
            expected=frozenset({"evidenceVersionId", "stableId"}),
            field_name="evidenceRoot",
        )
        return cls(
            evidence_version_id=_require_identifier(
                payload["evidenceVersionId"],
                field_name="evidenceVersionId",
            ),
            stable_id=_require_identifier(payload["stableId"], field_name="stableId"),
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "evidenceVersionId": self.evidence_version_id,
            "stableId": self.stable_id,
        }


@dataclass(frozen=True, slots=True)
class EvidenceIdentityDraftsV1:
    """Frozen reusable draft records used to validate one identity binding."""

    evidence_version: FrozenJsonObjectV1
    structure_revision: FrozenJsonObjectV1
    projection_revision: FrozenJsonObjectV1

    _FIELDS = frozenset({"evidenceVersion", "structureRevision", "projectionRevision"})

    def __post_init__(self) -> None:
        for field_name, value in (
            ("evidence_version", self.evidence_version),
            ("structure_revision", self.structure_revision),
            ("projection_revision", self.projection_revision),
        ):
            if type(value) is not FrozenJsonObjectV1:
                raise ReviewSemanticError(f"{field_name} must be a frozen draft identity record.")
        evidence = _validate_evidence_version_draft(self.evidence_version.to_json_obj())
        structure = _validate_structure_revision_draft(self.structure_revision.to_json_obj())
        projection = _validate_projection_revision_draft(self.projection_revision.to_json_obj())
        if structure["evidenceVersionId"] != evidence["evidenceVersionId"]:
            raise ReviewSemanticError(
                "Structure draft references a different evidence version.",
                code=ReviewSemanticErrorCodeV1.MIXED_VERSION,
            )
        if projection["structureRevisionId"] != structure["structureRevisionId"]:
            raise ReviewSemanticError(
                "Projection draft references a different structure revision.",
                code=ReviewSemanticErrorCodeV1.MIXED_VERSION,
            )

    @classmethod
    def from_json_obj(cls, value: object) -> EvidenceIdentityDraftsV1:
        payload = _require_exact_object(
            value,
            expected=cls._FIELDS,
            field_name="draftIdentities",
        )
        return cls(
            evidence_version=freeze_json_object_v1(payload["evidenceVersion"]),
            structure_revision=freeze_json_object_v1(payload["structureRevision"]),
            projection_revision=freeze_json_object_v1(payload["projectionRevision"]),
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "evidenceVersion": self.evidence_version.to_json_obj(),
            "structureRevision": self.structure_revision.to_json_obj(),
            "projectionRevision": self.projection_revision.to_json_obj(),
        }

    def require_binding(self, binding: EvidenceBindingV1) -> None:
        """Require exact IDs plus record and payload digests for the draft chain."""

        evidence = self.evidence_version.to_json_obj()
        structure = self.structure_revision.to_json_obj()
        projection = self.projection_revision.to_json_obj()
        source_version_ids = cast(list[JsonValue], evidence["sourceVersionIds"])
        if (
            binding.source_version_id not in source_version_ids
            or binding.evidence_version_id != evidence["evidenceVersionId"]
            or binding.evidence_record_sha256 != canonical_json_sha256_v1(evidence)
            or binding.evidence_canonical_output_sha256 != evidence["canonicalOutputSha256"]
            or binding.structure_revision_id != structure["structureRevisionId"]
            or binding.structure_record_sha256 != canonical_json_sha256_v1(structure)
            or binding.structure_graph_sha256 != structure["graphSha256"]
            or binding.projection_revision_id != projection["projectionRevisionId"]
            or binding.projection_record_sha256 != canonical_json_sha256_v1(projection)
            or binding.projection_payload_sha256 != projection["payloadSha256"]
        ):
            raise ReviewSemanticError(
                "Evidence binding does not match its draft identity context.",
                code=ReviewSemanticErrorCodeV1.MIXED_VERSION,
            )


@dataclass(frozen=True, slots=True)
class EvidenceBindingV1:
    """Explicit draft-compatible record and payload identity chain."""

    source_version_id: str
    source_content_sha256: str
    evidence_version_id: str
    evidence_record_sha256: str
    evidence_canonical_output_sha256: str
    structure_revision_id: str
    structure_record_sha256: str
    structure_graph_sha256: str
    projection_revision_id: str
    projection_record_sha256: str
    projection_payload_sha256: str
    _draft_identities: EvidenceIdentityDraftsV1 | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    _FIELDS = frozenset(
        {
            "schemaVersion",
            "kind",
            "contractId",
            "sourceVersionId",
            "sourceContentSha256",
            "evidenceVersionId",
            "evidenceRecordSha256",
            "evidenceCanonicalOutputSha256",
            "structureRevisionId",
            "structureRecordSha256",
            "structureGraphSha256",
            "projectionRevisionId",
            "projectionRecordSha256",
            "projectionPayloadSha256",
        }
    )

    def __post_init__(self) -> None:
        for field_name, value in (
            ("source_version_id", self.source_version_id),
            ("evidence_version_id", self.evidence_version_id),
            ("structure_revision_id", self.structure_revision_id),
            ("projection_revision_id", self.projection_revision_id),
        ):
            _require_identifier(value, field_name=field_name)
        for field_name, value in (
            ("source_content_sha256", self.source_content_sha256),
            ("evidence_record_sha256", self.evidence_record_sha256),
            (
                "evidence_canonical_output_sha256",
                self.evidence_canonical_output_sha256,
            ),
            ("structure_record_sha256", self.structure_record_sha256),
            ("structure_graph_sha256", self.structure_graph_sha256),
            ("projection_record_sha256", self.projection_record_sha256),
            ("projection_payload_sha256", self.projection_payload_sha256),
        ):
            _require_sha256(value, field_name=field_name)
        if self._draft_identities is None:
            raise ReviewSemanticError(
                "Evidence binding requires draft identity context.",
                code=ReviewSemanticErrorCodeV1.MIXED_VERSION,
            )
        if type(self._draft_identities) is not EvidenceIdentityDraftsV1:
            raise ReviewSemanticError("Evidence draft identity context is malformed.")
        self._draft_identities.require_binding(self)

    @classmethod
    def from_json_obj(
        cls,
        value: object,
        *,
        draft_identities: EvidenceIdentityDraftsV1 | None = None,
    ) -> EvidenceBindingV1:
        payload = _require_exact_object(
            value,
            expected=cls._FIELDS,
            field_name="evidenceBinding",
        )
        _require_header(payload, kind="evidenceBinding")
        return cls(
            source_version_id=_require_identifier(
                payload["sourceVersionId"],
                field_name="sourceVersionId",
            ),
            source_content_sha256=_require_sha256(
                payload["sourceContentSha256"],
                field_name="sourceContentSha256",
            ),
            evidence_version_id=_require_identifier(
                payload["evidenceVersionId"],
                field_name="evidenceVersionId",
            ),
            evidence_record_sha256=_require_sha256(
                payload["evidenceRecordSha256"],
                field_name="evidenceRecordSha256",
            ),
            evidence_canonical_output_sha256=_require_sha256(
                payload["evidenceCanonicalOutputSha256"],
                field_name="evidenceCanonicalOutputSha256",
            ),
            structure_revision_id=_require_identifier(
                payload["structureRevisionId"],
                field_name="structureRevisionId",
            ),
            structure_record_sha256=_require_sha256(
                payload["structureRecordSha256"],
                field_name="structureRecordSha256",
            ),
            structure_graph_sha256=_require_sha256(
                payload["structureGraphSha256"],
                field_name="structureGraphSha256",
            ),
            projection_revision_id=_require_identifier(
                payload["projectionRevisionId"],
                field_name="projectionRevisionId",
            ),
            projection_record_sha256=_require_sha256(
                payload["projectionRecordSha256"],
                field_name="projectionRecordSha256",
            ),
            projection_payload_sha256=_require_sha256(
                payload["projectionPayloadSha256"],
                field_name="projectionPayloadSha256",
            ),
            _draft_identities=draft_identities,
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": "evidenceBinding",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "sourceVersionId": self.source_version_id,
            "sourceContentSha256": self.source_content_sha256,
            "evidenceVersionId": self.evidence_version_id,
            "evidenceRecordSha256": self.evidence_record_sha256,
            "evidenceCanonicalOutputSha256": self.evidence_canonical_output_sha256,
            "structureRevisionId": self.structure_revision_id,
            "structureRecordSha256": self.structure_record_sha256,
            "structureGraphSha256": self.structure_graph_sha256,
            "projectionRevisionId": self.projection_revision_id,
            "projectionRecordSha256": self.projection_record_sha256,
            "projectionPayloadSha256": self.projection_payload_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class ReviewLimitsV1:
    """Finite review/worker limits frozen before execution."""

    max_iterations: int
    max_tool_calls: int
    max_total_tokens: int
    deadline_ms: int
    max_child_tasks: int
    max_concurrency: int

    _FIELDS = frozenset(
        {
            "schemaVersion",
            "kind",
            "contractId",
            "maxIterations",
            "maxToolCalls",
            "maxTotalTokens",
            "deadlineMs",
            "maxChildTasks",
            "maxConcurrency",
        }
    )

    def __post_init__(self) -> None:
        for field_name, value in (
            ("max_iterations", self.max_iterations),
            ("max_tool_calls", self.max_tool_calls),
            ("max_total_tokens", self.max_total_tokens),
            ("deadline_ms", self.deadline_ms),
        ):
            _require_positive_int(value, field_name=field_name)
        _require_non_negative_int(self.max_child_tasks, field_name="max_child_tasks")
        _require_non_negative_int(self.max_concurrency, field_name="max_concurrency")
        if self.max_concurrency > self.max_child_tasks:
            raise ReviewSemanticError("max_concurrency cannot exceed max_child_tasks.")
        if self.max_child_tasks == 0 and self.max_concurrency != 0:
            raise ReviewSemanticError("max_concurrency must be zero without child tasks.")

    @classmethod
    def from_json_obj(cls, value: object) -> ReviewLimitsV1:
        payload = _require_exact_object(value, expected=cls._FIELDS, field_name="reviewLimits")
        _require_header(payload, kind="reviewLimits")
        return cls(
            max_iterations=_require_positive_int(
                payload["maxIterations"],
                field_name="maxIterations",
            ),
            max_tool_calls=_require_positive_int(
                payload["maxToolCalls"],
                field_name="maxToolCalls",
            ),
            max_total_tokens=_require_positive_int(
                payload["maxTotalTokens"],
                field_name="maxTotalTokens",
            ),
            deadline_ms=_require_positive_int(payload["deadlineMs"], field_name="deadlineMs"),
            max_child_tasks=_require_non_negative_int(
                payload["maxChildTasks"],
                field_name="maxChildTasks",
            ),
            max_concurrency=_require_non_negative_int(
                payload["maxConcurrency"],
                field_name="maxConcurrency",
            ),
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": "reviewLimits",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "maxIterations": self.max_iterations,
            "maxToolCalls": self.max_tool_calls,
            "maxTotalTokens": self.max_total_tokens,
            "deadlineMs": self.deadline_ms,
            "maxChildTasks": self.max_child_tasks,
            "maxConcurrency": self.max_concurrency,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class StructuralGrantV1:
    """Immutable evidence/tool/media authority created by the trusted service."""

    grant_id: str
    evidence_binding: EvidenceBindingV1
    evidence_roots: tuple[EvidenceRootRefV1, ...]
    tool_names: tuple[str, ...]
    media_ids: tuple[str, ...]
    limits: ReviewLimitsV1

    _FIELDS = frozenset(
        {
            "schemaVersion",
            "kind",
            "contractId",
            "grantId",
            "evidenceBinding",
            "evidenceRoots",
            "toolNames",
            "mediaIds",
            "limits",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.grant_id, field_name="grant_id")
        if type(self.evidence_binding) is not EvidenceBindingV1:
            raise ReviewSemanticError("evidence_binding must be an EvidenceBindingV1.")
        if type(self.evidence_roots) is not tuple or not self.evidence_roots:
            raise ReviewSemanticError("evidence_roots must be a non-empty immutable tuple.")
        for root in self.evidence_roots:
            if type(root) is not EvidenceRootRefV1:
                raise ReviewSemanticError("evidence_roots contains an invalid root.")
            if root.evidence_version_id != self.evidence_binding.evidence_version_id:
                raise ReviewSemanticError(
                    "Grant root uses a different evidence version.",
                    code=ReviewSemanticErrorCodeV1.MIXED_VERSION,
                )
        if len(set(self.evidence_roots)) != len(self.evidence_roots):
            raise ReviewSemanticError("evidence_roots contains a duplicate root.")
        _require_unique_names(self.tool_names, field_name="tool_names", pattern=_TOOL_NAME)
        _require_unique_identifiers(self.media_ids, field_name="media_ids")
        if type(self.limits) is not ReviewLimitsV1:
            raise ReviewSemanticError("limits must be a ReviewLimitsV1.")

    @classmethod
    def from_json_obj(
        cls,
        value: object,
        *,
        draft_identities: EvidenceIdentityDraftsV1 | None = None,
    ) -> StructuralGrantV1:
        payload = _require_exact_object(value, expected=cls._FIELDS, field_name="structuralGrant")
        _require_header(payload, kind="structuralGrant")
        raw_roots = _require_list(payload["evidenceRoots"], field_name="evidenceRoots")
        return cls(
            grant_id=_require_identifier(payload["grantId"], field_name="grantId"),
            evidence_binding=EvidenceBindingV1.from_json_obj(
                payload["evidenceBinding"],
                draft_identities=draft_identities,
            ),
            evidence_roots=tuple(EvidenceRootRefV1.from_json_obj(root) for root in raw_roots),
            tool_names=_parse_string_tuple(payload["toolNames"], field_name="toolNames"),
            media_ids=_parse_string_tuple(payload["mediaIds"], field_name="mediaIds"),
            limits=ReviewLimitsV1.from_json_obj(payload["limits"]),
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": "structuralGrant",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "grantId": self.grant_id,
            "evidenceBinding": self.evidence_binding.to_json_obj(),
            "evidenceRoots": [root.to_json_obj() for root in self.evidence_roots],
            "toolNames": list(self.tool_names),
            "mediaIds": list(self.media_ids),
            "limits": self.limits.to_json_obj(),
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())

    def authorize_tool(
        self,
        *,
        name: str,
        evidence_version_id: str,
        stable_ids: tuple[str, ...],
    ) -> None:
        """Fail closed before execution if one tool request exceeds this grant vector."""

        if name not in self.tool_names:
            raise ReviewSemanticError(
                "Tool is not admitted by the structural grant.",
                code=ReviewSemanticErrorCodeV1.UNADMITTED_TOOL,
            )
        if evidence_version_id != self.evidence_binding.evidence_version_id:
            raise ReviewSemanticError(
                "Tool request uses a different evidence version.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )
        admitted = {root.stable_id for root in self.evidence_roots}
        if type(stable_ids) is not tuple or any(
            stable_id not in admitted for stable_id in stable_ids
        ):
            raise ReviewSemanticError(
                "Tool request is outside the structural grant roots.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )

    def authorize_media(self, media_id: str) -> None:
        """Fail closed if media was not admitted when the grant was created."""

        if media_id not in self.media_ids:
            raise ReviewSemanticError(
                "Media is not admitted by the structural grant.",
                code=ReviewSemanticErrorCodeV1.UNADMITTED_MEDIA,
            )


@dataclass(frozen=True, slots=True)
class CitationAdmissionV1:
    """One package-compatible citation address bound to its grant and tool ledger."""

    address: FrozenJsonObjectV1
    address_sha256: str
    grant_id: str
    grant_sha256: str
    _authority_grant: StructuralGrantV1 | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    _admitted_tool_call_ids: tuple[str, ...] = field(
        default=(),
        repr=False,
        compare=False,
    )

    _FIELDS = frozenset(
        {
            "schemaVersion",
            "kind",
            "contractId",
            "address",
            "addressSha256",
            "grantId",
            "grantSha256",
        }
    )

    def __post_init__(self) -> None:
        if type(self.address) is not FrozenJsonObjectV1:
            raise ReviewSemanticError("address must be a frozen JSON object.")
        _require_sha256(self.address_sha256, field_name="address_sha256")
        if canonical_json_sha256_v1(self.address.to_json_obj()) != self.address_sha256:
            raise ReviewSemanticError("Citation address digest does not match its payload.")
        _require_identifier(self.grant_id, field_name="grant_id")
        _require_sha256(self.grant_sha256, field_name="grant_sha256")
        _validate_citation_address_shape(self.address.to_json_obj())
        if self._authority_grant is None:
            raise ReviewSemanticError(
                "Citation admission requires grant and tool ledger authority context.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )
        if type(self._authority_grant) is not StructuralGrantV1:
            raise ReviewSemanticError("Citation authority grant is malformed.")
        _require_unique_identifiers(
            self._admitted_tool_call_ids,
            field_name="admitted_tool_call_ids",
        )
        if (
            self.grant_id != self._authority_grant.grant_id
            or self.grant_sha256 != self._authority_grant.digest
        ):
            raise ReviewSemanticError(
                "Citation admission does not match the trusted structural grant.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )
        _validate_citation_against_grant(
            self.address.to_json_obj(),
            grant=self._authority_grant,
            admitted_tool_call_ids=self._admitted_tool_call_ids,
        )

    @classmethod
    def create(
        cls,
        *,
        address: object,
        grant: StructuralGrantV1,
        admitted_tool_call_ids: tuple[str, ...],
    ) -> CitationAdmissionV1:
        _require_unique_identifiers(
            admitted_tool_call_ids,
            field_name="admitted_tool_call_ids",
        )
        frozen = freeze_json_object_v1(address)
        address_payload = frozen.to_json_obj()
        _validate_citation_against_grant(
            address_payload,
            grant=grant,
            admitted_tool_call_ids=admitted_tool_call_ids,
        )
        return cls(
            address=frozen,
            address_sha256=canonical_json_sha256_v1(address_payload),
            grant_id=grant.grant_id,
            grant_sha256=grant.digest,
            _authority_grant=grant,
            _admitted_tool_call_ids=admitted_tool_call_ids,
        )

    @classmethod
    def from_json_obj(
        cls,
        value: object,
        *,
        grant: StructuralGrantV1 | None = None,
        admitted_tool_call_ids: tuple[str, ...] = (),
    ) -> CitationAdmissionV1:
        if grant is None:
            raise ReviewSemanticError(
                "Citation admission requires grant and tool ledger authority context.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )
        payload = _require_exact_object(value, expected=cls._FIELDS, field_name="citationAdmission")
        _require_header(payload, kind="citationAdmission")
        admission = cls(
            address=freeze_json_object_v1(payload["address"]),
            address_sha256=_require_sha256(
                payload["addressSha256"],
                field_name="addressSha256",
            ),
            grant_id=_require_identifier(payload["grantId"], field_name="grantId"),
            grant_sha256=_require_sha256(payload["grantSha256"], field_name="grantSha256"),
            _authority_grant=grant,
            _admitted_tool_call_ids=admitted_tool_call_ids,
        )
        admission.require_authority(
            grant=grant,
            admitted_tool_call_ids=admitted_tool_call_ids,
        )
        return admission

    def require_authority(
        self,
        *,
        grant: StructuralGrantV1,
        admitted_tool_call_ids: tuple[str, ...],
    ) -> None:
        """Validate claimed provenance against the trusted run grant and tool ledger."""

        if self.grant_id != grant.grant_id or self.grant_sha256 != grant.digest:
            raise ReviewSemanticError(
                "Citation admission does not match the trusted structural grant.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )
        _require_unique_identifiers(
            admitted_tool_call_ids,
            field_name="admitted_tool_call_ids",
        )
        _validate_citation_against_grant(
            self.address.to_json_obj(),
            grant=grant,
            admitted_tool_call_ids=admitted_tool_call_ids,
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": "citationAdmission",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "address": self.address.to_json_obj(),
            "addressSha256": self.address_sha256,
            "grantId": self.grant_id,
            "grantSha256": self.grant_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class CitationResolutionV1:
    """Typed click-back result that never redirects a citation to similar evidence."""

    citation_sha256: str
    address_sha256: str
    grant_id: str
    grant_sha256: str
    state: CitationResolutionStateV1
    resolved_address_sha256: str | None
    reason_code: str | None

    _FIELDS = frozenset(
        {
            "schemaVersion",
            "kind",
            "contractId",
            "citationSha256",
            "addressSha256",
            "grantId",
            "grantSha256",
            "state",
            "resolvedAddressSha256",
            "reasonCode",
        }
    )

    def __post_init__(self) -> None:
        _require_sha256(self.citation_sha256, field_name="citation_sha256")
        _require_sha256(self.address_sha256, field_name="address_sha256")
        _require_identifier(self.grant_id, field_name="grant_id")
        _require_sha256(self.grant_sha256, field_name="grant_sha256")
        if not isinstance(self.state, CitationResolutionStateV1):
            raise ReviewSemanticError("state contains an unknown citation resolution value.")
        if self.state is CitationResolutionStateV1.RESOLVED:
            if self.resolved_address_sha256 != self.address_sha256:
                raise ReviewSemanticError(
                    "A resolved citation cannot redirect to a different address digest."
                )
            if self.reason_code is not None:
                raise ReviewSemanticError("A resolved citation cannot carry a refusal reason.")
        else:
            if self.resolved_address_sha256 is not None:
                raise ReviewSemanticError(
                    "An unresolved citation cannot carry a resolved address digest."
                )
            if type(self.reason_code) is not str or _CODE.fullmatch(self.reason_code) is None:
                raise ReviewSemanticError("An unresolved citation requires a bounded reason code.")

    @classmethod
    def create(
        cls,
        *,
        citation: CitationAdmissionV1,
        grant: StructuralGrantV1,
        state: CitationResolutionStateV1,
        reason_code: str | None,
    ) -> CitationResolutionV1:
        if type(citation) is not CitationAdmissionV1:
            raise ReviewSemanticError("citation must be an admitted citation contract.")
        if citation.grant_id != grant.grant_id or citation.grant_sha256 != grant.digest:
            raise ReviewSemanticError(
                "Citation resolution is outside the trusted structural grant.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )
        return cls(
            citation_sha256=citation.digest,
            address_sha256=citation.address_sha256,
            grant_id=grant.grant_id,
            grant_sha256=grant.digest,
            state=state,
            resolved_address_sha256=(
                citation.address_sha256 if state is CitationResolutionStateV1.RESOLVED else None
            ),
            reason_code=reason_code,
        )

    @classmethod
    def from_json_obj(
        cls,
        value: object,
        *,
        citation: CitationAdmissionV1 | None = None,
        grant: StructuralGrantV1 | None = None,
    ) -> CitationResolutionV1:
        if citation is None or grant is None:
            raise ReviewSemanticError(
                "Citation resolution requires admitted citation and grant context.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )
        payload = _require_exact_object(
            value,
            expected=cls._FIELDS,
            field_name="citationResolution",
        )
        _require_header(payload, kind="citationResolution")
        result = cls(
            citation_sha256=_require_sha256(payload["citationSha256"], field_name="citationSha256"),
            address_sha256=_require_sha256(payload["addressSha256"], field_name="addressSha256"),
            grant_id=_require_identifier(payload["grantId"], field_name="grantId"),
            grant_sha256=_require_sha256(payload["grantSha256"], field_name="grantSha256"),
            state=_require_enum(
                CitationResolutionStateV1,
                payload["state"],
                field_name="state",
                unknown_code=ReviewSemanticErrorCodeV1.INVALID_VALUE,
            ),
            resolved_address_sha256=_require_optional_sha256(
                payload["resolvedAddressSha256"],
                field_name="resolvedAddressSha256",
            ),
            reason_code=_require_optional_code(
                payload["reasonCode"],
                field_name="reasonCode",
            ),
        )
        result.require_context(citation=citation, grant=grant)
        return result

    def require_context(
        self,
        *,
        citation: CitationAdmissionV1,
        grant: StructuralGrantV1,
    ) -> None:
        """Bind the result to the exact admitted citation and trusted grant."""

        if (
            citation.grant_id != grant.grant_id
            or citation.grant_sha256 != grant.digest
            or self.grant_id != grant.grant_id
            or self.grant_sha256 != grant.digest
            or self.citation_sha256 != citation.digest
            or self.address_sha256 != citation.address_sha256
        ):
            raise ReviewSemanticError(
                "Citation resolution does not match the admitted citation and grant.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": "citationResolution",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "citationSha256": self.citation_sha256,
            "addressSha256": self.address_sha256,
            "grantId": self.grant_id,
            "grantSha256": self.grant_sha256,
            "state": self.state.value,
            "resolvedAddressSha256": self.resolved_address_sha256,
            "reasonCode": self.reason_code,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class TerminalReviewResultV1:
    """Exactly one typed terminal review result with an honest coverage claim."""

    run_id: str
    outcome: TerminalOutcomeV1
    answer: str | None
    citations: tuple[CitationAdmissionV1, ...]
    grant_id: str
    grant_sha256: str
    evidence_gap_codes: tuple[str, ...]
    inspected_count: int
    unreviewed_count: int
    coverage_state: CoverageStateV1
    clarification_question_id: str | None
    pre_terminal_event_head_sha256: str
    receipt_id: str
    provider_failure_diagnostic: ProviderFailureDiagnosticV1 | None = None

    _FIELDS = frozenset(
        {
            "schemaVersion",
            "kind",
            "contractId",
            "runId",
            "outcome",
            "answer",
            "citations",
            "grantId",
            "grantSha256",
            "evidenceGapCodes",
            "inspectedCount",
            "unreviewedCount",
            "coverageState",
            "clarificationQuestionId",
            "preTerminalEventHeadSha256",
            "receiptId",
        }
    )
    _DIAGNOSTIC_FIELDS = _FIELDS | frozenset({"providerFailureDiagnostic"})

    def __post_init__(self) -> None:
        _require_identifier(self.run_id, field_name="run_id")
        if not isinstance(self.outcome, TerminalOutcomeV1):
            raise ReviewSemanticError(
                "outcome contains an unknown terminal value.",
                code=ReviewSemanticErrorCodeV1.UNKNOWN_OUTCOME,
            )
        if self.answer is not None:
            _require_non_empty_text(self.answer, field_name="answer")
        if type(self.citations) is not tuple or any(
            type(citation) is not CitationAdmissionV1 for citation in self.citations
        ):
            raise ReviewSemanticError("citations must be an immutable citation tuple.")
        _require_identifier(self.grant_id, field_name="grant_id")
        _require_sha256(self.grant_sha256, field_name="grant_sha256")
        if any(
            citation.grant_id != self.grant_id or citation.grant_sha256 != self.grant_sha256
            for citation in self.citations
        ):
            raise ReviewSemanticError(
                "Terminal citations must share the terminal result grant.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )
        _require_unique_names(
            self.evidence_gap_codes,
            field_name="evidence_gap_codes",
            pattern=_CODE,
        )
        _require_non_negative_int(self.inspected_count, field_name="inspected_count")
        _require_non_negative_int(self.unreviewed_count, field_name="unreviewed_count")
        if not isinstance(self.coverage_state, CoverageStateV1):
            raise ReviewSemanticError("coverage_state contains an unknown value.")
        if self.coverage_state is CoverageStateV1.COMPLETE and self.unreviewed_count != 0:
            raise ReviewSemanticError(
                "A terminal result cannot claim complete coverage with unreviewed evidence.",
                code=ReviewSemanticErrorCodeV1.FALSE_COMPLETENESS,
            )
        if self.outcome is TerminalOutcomeV1.SUPPORTED_ANSWER:
            if self.answer is None or not self.citations:
                raise ReviewSemanticError("A supported answer requires text and citations.")
        elif self.answer is not None:
            raise ReviewSemanticError("Only supported_answer may carry answer text.")
        if self.outcome is TerminalOutcomeV1.CLARIFICATION_REQUIRED:
            if self.clarification_question_id is None:
                raise ReviewSemanticError("clarification_required must carry a question ID.")
        elif self.clarification_question_id is not None:
            raise ReviewSemanticError("Only clarification_required may carry a question ID.")
        if self.clarification_question_id is not None:
            _require_identifier(
                self.clarification_question_id,
                field_name="clarification_question_id",
            )
        if self.outcome is TerminalOutcomeV1.EVIDENCE_GAP and not self.evidence_gap_codes:
            raise ReviewSemanticError("evidence_gap must enumerate at least one gap code.")
        _require_sha256(
            self.pre_terminal_event_head_sha256,
            field_name="pre_terminal_event_head_sha256",
        )
        _require_identifier(self.receipt_id, field_name="receipt_id")
        if self.provider_failure_diagnostic is not None:
            if type(self.provider_failure_diagnostic) is not ProviderFailureDiagnosticV1:
                raise ReviewSemanticError("Provider failure diagnostic type is invalid.")
            if self.outcome is not TerminalOutcomeV1.PROVIDER_FAILED:
                raise ReviewSemanticError(
                    "Only provider_failed may carry a provider failure diagnostic."
                )

    @classmethod
    def from_json_obj(
        cls,
        value: object,
        *,
        grant: StructuralGrantV1 | None = None,
        admitted_tool_call_ids: tuple[str, ...] = (),
    ) -> TerminalReviewResultV1:
        if grant is None:
            raise ReviewSemanticError(
                "Terminal result requires grant and tool ledger authority context.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )
        raw = cast(dict[str, JsonValue], value) if type(value) is dict else {}
        has_diagnostic = frozenset(raw) == cls._DIAGNOSTIC_FIELDS
        payload = _require_exact_object(
            value,
            expected=cls._DIAGNOSTIC_FIELDS if has_diagnostic else cls._FIELDS,
            field_name="terminalReview",
        )
        _require_header(payload, kind="terminalReviewResult")
        raw_citations = _require_list(payload["citations"], field_name="citations")
        grant_id = _require_identifier(payload["grantId"], field_name="grantId")
        grant_sha256 = _require_sha256(payload["grantSha256"], field_name="grantSha256")
        if grant_id != grant.grant_id or grant_sha256 != grant.digest:
            raise ReviewSemanticError(
                "Terminal result does not match the trusted structural grant.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )
        return cls(
            run_id=_require_identifier(payload["runId"], field_name="runId"),
            outcome=_require_enum(
                TerminalOutcomeV1,
                payload["outcome"],
                field_name="outcome",
                unknown_code=ReviewSemanticErrorCodeV1.UNKNOWN_OUTCOME,
            ),
            answer=_require_optional_text(payload["answer"], field_name="answer"),
            citations=tuple(
                CitationAdmissionV1.from_json_obj(
                    item,
                    grant=grant,
                    admitted_tool_call_ids=admitted_tool_call_ids,
                )
                for item in raw_citations
            ),
            grant_id=grant_id,
            grant_sha256=grant_sha256,
            evidence_gap_codes=_parse_string_tuple(
                payload["evidenceGapCodes"],
                field_name="evidenceGapCodes",
            ),
            inspected_count=_require_non_negative_int(
                payload["inspectedCount"],
                field_name="inspectedCount",
            ),
            unreviewed_count=_require_non_negative_int(
                payload["unreviewedCount"],
                field_name="unreviewedCount",
            ),
            coverage_state=_require_enum(
                CoverageStateV1,
                payload["coverageState"],
                field_name="coverageState",
                unknown_code=ReviewSemanticErrorCodeV1.INVALID_VALUE,
            ),
            clarification_question_id=_require_optional_identifier(
                payload["clarificationQuestionId"],
                field_name="clarificationQuestionId",
            ),
            pre_terminal_event_head_sha256=_require_sha256(
                payload["preTerminalEventHeadSha256"],
                field_name="preTerminalEventHeadSha256",
            ),
            receipt_id=_require_identifier(payload["receiptId"], field_name="receiptId"),
            provider_failure_diagnostic=(
                _provider_failure_diagnostic_v1(payload["providerFailureDiagnostic"])
                if has_diagnostic
                else None
            ),
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        payload: dict[str, JsonValue] = {
            "schemaVersion": 1,
            "kind": "terminalReviewResult",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "runId": self.run_id,
            "outcome": self.outcome.value,
            "answer": self.answer,
            "citations": [citation.to_json_obj() for citation in self.citations],
            "grantId": self.grant_id,
            "grantSha256": self.grant_sha256,
            "evidenceGapCodes": list(self.evidence_gap_codes),
            "inspectedCount": self.inspected_count,
            "unreviewedCount": self.unreviewed_count,
            "coverageState": self.coverage_state.value,
            "clarificationQuestionId": self.clarification_question_id,
            "preTerminalEventHeadSha256": self.pre_terminal_event_head_sha256,
            "receiptId": self.receipt_id,
        }
        if self.provider_failure_diagnostic is not None:
            payload["providerFailureDiagnostic"] = cast(
                JsonValue,
                self.provider_failure_diagnostic.to_json_obj(),
            )
        return payload

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class ContextRevisionRefV1:
    """One persistent context revision identity without its instruction text."""

    layer: ContextLayerV1 | str
    revision_id: str
    sha256: str

    def __post_init__(self) -> None:
        layer = (
            self.layer
            if isinstance(self.layer, ContextLayerV1)
            else _require_enum(
                ContextLayerV1,
                self.layer,
                field_name="layer",
                unknown_code=ReviewSemanticErrorCodeV1.INVALID_VALUE,
            )
        )
        object.__setattr__(self, "layer", layer)
        _require_identifier(self.revision_id, field_name="revision_id")
        _require_sha256(self.sha256, field_name="sha256")

    @classmethod
    def from_json_obj(cls, value: object) -> ContextRevisionRefV1:
        payload = _require_exact_object(
            value,
            expected=frozenset({"layer", "revisionId", "sha256"}),
            field_name="contextRevision",
        )
        return cls(
            layer=_require_enum(
                ContextLayerV1,
                payload["layer"],
                field_name="layer",
                unknown_code=ReviewSemanticErrorCodeV1.INVALID_VALUE,
            ),
            revision_id=_require_identifier(payload["revisionId"], field_name="revisionId"),
            sha256=_require_sha256(payload["sha256"], field_name="sha256"),
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        layer = cast(ContextLayerV1, self.layer)
        return {"layer": layer.value, "revisionId": self.revision_id, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class ContextBindingV1:
    """Resolved context identities plus transient selected evidence."""

    application: ContextRevisionRefV1
    user: ContextRevisionRefV1 | None
    workspace: ContextRevisionRefV1 | None
    selected_roots: tuple[EvidenceRootRefV1, ...]
    session_sha256: str
    knowledge_revision_ids: tuple[str, ...]
    knowledge_head_sha256: str
    resolved_sha256: str
    clarification_mode: ClarificationModeV1
    policy_version: str

    _FIELDS = frozenset(
        {
            "schemaVersion",
            "kind",
            "contractId",
            "application",
            "user",
            "workspace",
            "selectedRoots",
            "sessionSha256",
            "knowledgeRevisionIds",
            "knowledgeHeadSha256",
            "resolvedSha256",
            "clarificationMode",
            "policyVersion",
        }
    )

    def __post_init__(self) -> None:
        _require_context_layer(self.application, ContextLayerV1.APPLICATION)
        if self.user is not None:
            _require_context_layer(self.user, ContextLayerV1.USER)
        if self.workspace is not None:
            _require_context_layer(self.workspace, ContextLayerV1.WORKSPACE)
        if type(self.selected_roots) is not tuple or not self.selected_roots:
            raise ReviewSemanticError("selected_roots must be a non-empty immutable tuple.")
        if any(type(root) is not EvidenceRootRefV1 for root in self.selected_roots):
            raise ReviewSemanticError("selected_roots contains an invalid evidence root.")
        if len(self.selected_roots) != len(set(self.selected_roots)):
            raise ReviewSemanticError("selected_roots contains a duplicate root.")
        _require_sha256(self.session_sha256, field_name="session_sha256")
        _require_unique_identifiers(
            self.knowledge_revision_ids,
            field_name="knowledge_revision_ids",
        )
        _require_sha256(self.knowledge_head_sha256, field_name="knowledge_head_sha256")
        _require_sha256(self.resolved_sha256, field_name="resolved_sha256")
        if not isinstance(self.clarification_mode, ClarificationModeV1):
            raise ReviewSemanticError("clarification_mode contains an unknown value.")
        _require_identifier(self.policy_version, field_name="policy_version")

    @classmethod
    def from_json_obj(cls, value: object) -> ContextBindingV1:
        payload = _require_exact_object(value, expected=cls._FIELDS, field_name="contextBinding")
        _require_header(payload, kind="contextBinding")
        raw_user = payload["user"]
        raw_workspace = payload["workspace"]
        raw_roots = _require_list(payload["selectedRoots"], field_name="selectedRoots")
        return cls(
            application=ContextRevisionRefV1.from_json_obj(payload["application"]),
            user=None if raw_user is None else ContextRevisionRefV1.from_json_obj(raw_user),
            workspace=(
                None if raw_workspace is None else ContextRevisionRefV1.from_json_obj(raw_workspace)
            ),
            selected_roots=tuple(EvidenceRootRefV1.from_json_obj(root) for root in raw_roots),
            session_sha256=_require_sha256(
                payload["sessionSha256"],
                field_name="sessionSha256",
            ),
            knowledge_revision_ids=_parse_string_tuple(
                payload["knowledgeRevisionIds"],
                field_name="knowledgeRevisionIds",
            ),
            knowledge_head_sha256=_require_sha256(
                payload["knowledgeHeadSha256"],
                field_name="knowledgeHeadSha256",
            ),
            resolved_sha256=_require_sha256(
                payload["resolvedSha256"],
                field_name="resolvedSha256",
            ),
            clarification_mode=_require_enum(
                ClarificationModeV1,
                payload["clarificationMode"],
                field_name="clarificationMode",
                unknown_code=ReviewSemanticErrorCodeV1.INVALID_VALUE,
            ),
            policy_version=_require_identifier(
                payload["policyVersion"],
                field_name="policyVersion",
            ),
        )

    @property
    def layers(self) -> tuple[ContextLayerV1, ...]:
        revisions = tuple(
            revision
            for revision in (self.application, self.user, self.workspace)
            if revision is not None
        )
        return tuple(cast(ContextLayerV1, revision.layer) for revision in revisions)

    def require_grant(self, grant: StructuralGrantV1) -> None:
        """Reject session selections that are not exactly within the structural grant."""

        if type(grant) is not StructuralGrantV1:
            raise ReviewSemanticError("grant must be a StructuralGrantV1.")
        granted = set(grant.evidence_roots)
        if any(root not in granted for root in self.selected_roots):
            raise ReviewSemanticError(
                "Context selected roots cross the structural grant.",
                code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
            )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": "contextBinding",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "application": self.application.to_json_obj(),
            "user": None if self.user is None else self.user.to_json_obj(),
            "workspace": None if self.workspace is None else self.workspace.to_json_obj(),
            "selectedRoots": [root.to_json_obj() for root in self.selected_roots],
            "sessionSha256": self.session_sha256,
            "knowledgeRevisionIds": list(self.knowledge_revision_ids),
            "knowledgeHeadSha256": self.knowledge_head_sha256,
            "resolvedSha256": self.resolved_sha256,
            "clarificationMode": self.clarification_mode.value,
            "policyVersion": self.policy_version,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class EgressPolicyV1:
    """Standing provider destination and data-class authority."""

    policy_id: str
    provider_id: str
    model_id: str
    network_destination: str
    allowed_data_classes: tuple[EgressDataClassV1, ...]
    evidence_version_ids: tuple[str, ...]
    media_ids: tuple[str, ...]
    max_total_bytes: int
    route_decision_sha256: str | None = None
    route_policy_sha256: str | None = None
    pricing_authority_sha256: str | None = None

    _FIELDS = frozenset(
        {
            "schemaVersion",
            "kind",
            "contractId",
            "policyId",
            "providerId",
            "modelId",
            "networkDestination",
            "allowedDataClasses",
            "evidenceVersionIds",
            "mediaIds",
            "maxTotalBytes",
        }
    )
    _ROUTED_FIELDS = _FIELDS | frozenset(
        {
            "routeDecisionSha256",
            "routePolicySha256",
            "pricingAuthoritySha256",
        }
    )

    def __post_init__(self) -> None:
        for field_name, value in (
            ("policy_id", self.policy_id),
            ("provider_id", self.provider_id),
            ("model_id", self.model_id),
        ):
            _require_identifier(value, field_name=field_name)
        _require_network_destination(self.network_destination)
        if type(self.allowed_data_classes) is not tuple or not self.allowed_data_classes:
            raise ReviewSemanticError("allowed_data_classes must be a non-empty tuple.")
        if any(
            not isinstance(data_class, EgressDataClassV1)
            for data_class in self.allowed_data_classes
        ):
            raise ReviewSemanticError("allowed_data_classes contains an unknown value.")
        if len(self.allowed_data_classes) != len(set(self.allowed_data_classes)):
            raise ReviewSemanticError("allowed_data_classes contains a duplicate value.")
        _require_unique_identifiers(
            self.evidence_version_ids,
            field_name="evidence_version_ids",
        )
        if not self.evidence_version_ids:
            raise ReviewSemanticError("evidence_version_ids must not be empty.")
        _require_unique_identifiers(self.media_ids, field_name="media_ids")
        _require_positive_int(self.max_total_bytes, field_name="max_total_bytes")
        routed = (
            self.route_decision_sha256,
            self.route_policy_sha256,
            self.pricing_authority_sha256,
        )
        if any(value is not None for value in routed):
            if any(value is None for value in routed):
                raise ReviewSemanticError("Routed egress authority must be complete.")
            for field_name, route_value in (
                ("route_decision_sha256", self.route_decision_sha256),
                ("route_policy_sha256", self.route_policy_sha256),
                ("pricing_authority_sha256", self.pricing_authority_sha256),
            ):
                assert route_value is not None
                _require_sha256(route_value, field_name=field_name)

    @classmethod
    def from_json_obj(cls, value: object) -> EgressPolicyV1:
        if type(value) is not dict:
            raise ReviewSemanticError("egressPolicy must be an object.")
        raw = cast(dict[str, JsonValue], value)
        expected = cls._ROUTED_FIELDS if frozenset(raw) == cls._ROUTED_FIELDS else cls._FIELDS
        payload = _require_exact_object(value, expected=expected, field_name="egressPolicy")
        _require_header(payload, kind="egressPolicy")
        raw_data_classes = _require_list(
            payload["allowedDataClasses"],
            field_name="allowedDataClasses",
        )
        return cls(
            policy_id=_require_identifier(payload["policyId"], field_name="policyId"),
            provider_id=_require_identifier(payload["providerId"], field_name="providerId"),
            model_id=_require_identifier(payload["modelId"], field_name="modelId"),
            network_destination=_require_network_destination(payload["networkDestination"]),
            allowed_data_classes=tuple(
                _require_enum(
                    EgressDataClassV1,
                    item,
                    field_name="allowedDataClasses",
                    unknown_code=ReviewSemanticErrorCodeV1.UNSUPPORTED_EGRESS,
                )
                for item in raw_data_classes
            ),
            evidence_version_ids=_parse_string_tuple(
                payload["evidenceVersionIds"],
                field_name="evidenceVersionIds",
            ),
            media_ids=_parse_string_tuple(payload["mediaIds"], field_name="mediaIds"),
            max_total_bytes=_require_positive_int(
                payload["maxTotalBytes"],
                field_name="maxTotalBytes",
            ),
            route_decision_sha256=(
                None
                if expected is cls._FIELDS
                else _require_sha256(
                    payload["routeDecisionSha256"], field_name="routeDecisionSha256"
                )
            ),
            route_policy_sha256=(
                None
                if expected is cls._FIELDS
                else _require_sha256(payload["routePolicySha256"], field_name="routePolicySha256")
            ),
            pricing_authority_sha256=(
                None
                if expected is cls._FIELDS
                else _require_sha256(
                    payload["pricingAuthoritySha256"],
                    field_name="pricingAuthoritySha256",
                )
            ),
        )

    def authorize(
        self,
        *,
        data_class: EgressDataClassV1 | str,
        network_destination: str,
        evidence_version_id: str,
        media_id: str | None,
        byte_count: int,
    ) -> None:
        """Fail before network access when the exact request is outside policy."""

        try:
            normalized_class = EgressDataClassV1(data_class)
        except ValueError:
            raise ReviewSemanticError(
                "Egress data class is unsupported.",
                code=ReviewSemanticErrorCodeV1.UNSUPPORTED_EGRESS,
            ) from None
        if (
            normalized_class not in self.allowed_data_classes
            or network_destination != self.network_destination
            or evidence_version_id not in self.evidence_version_ids
            or byte_count < 0
            or byte_count > self.max_total_bytes
        ):
            raise ReviewSemanticError(
                "Egress request is outside the standing policy.",
                code=ReviewSemanticErrorCodeV1.UNSUPPORTED_EGRESS,
            )
        if normalized_class is EgressDataClassV1.ADMITTED_MEDIA:
            if media_id is None or media_id not in self.media_ids:
                raise ReviewSemanticError(
                    "Egress media is not admitted by policy.",
                    code=ReviewSemanticErrorCodeV1.UNSUPPORTED_EGRESS,
                )
        elif media_id is not None:
            raise ReviewSemanticError(
                "Only admitted_media egress may carry a media ID.",
                code=ReviewSemanticErrorCodeV1.UNSUPPORTED_EGRESS,
            )

    def to_json_obj(self) -> dict[str, JsonValue]:
        payload: dict[str, JsonValue] = {
            "schemaVersion": 1,
            "kind": "egressPolicy",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "policyId": self.policy_id,
            "providerId": self.provider_id,
            "modelId": self.model_id,
            "networkDestination": self.network_destination,
            "allowedDataClasses": [item.value for item in self.allowed_data_classes],
            "evidenceVersionIds": list(self.evidence_version_ids),
            "mediaIds": list(self.media_ids),
            "maxTotalBytes": self.max_total_bytes,
        }
        if self.route_decision_sha256 is not None:
            payload.update(
                {
                    "routeDecisionSha256": self.route_decision_sha256,
                    "routePolicySha256": self.route_policy_sha256,
                    "pricingAuthoritySha256": self.pricing_authority_sha256,
                }
            )
        return payload

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class EgressPolicyV2:
    """Responses-only standing egress authority with exact output ceilings."""

    policy_id: str
    provider_id: str
    model_id: str
    provider_protocol_id: OpenAIProtocolIdV1
    reasoning_effort: ProviderReasoningEffortV1
    network_destination: str
    allowed_data_classes: tuple[EgressDataClassV1, ...]
    evidence_version_ids: tuple[str, ...]
    media_ids: tuple[str, ...]
    max_total_bytes: int
    model_max_output_tokens: int
    admitted_max_output_tokens: int
    route_decision_sha256: str
    route_policy_sha256: str
    pricing_authority_sha256: str

    _FIELDS = frozenset(
        {
            "schemaVersion",
            "kind",
            "contractId",
            "policyId",
            "providerId",
            "modelId",
            "providerProtocolId",
            "reasoningEffort",
            "networkDestination",
            "allowedDataClasses",
            "evidenceVersionIds",
            "mediaIds",
            "maxTotalBytes",
            "modelMaxOutputTokens",
            "admittedMaxOutputTokens",
            "routeDecisionSha256",
            "routePolicySha256",
            "pricingAuthoritySha256",
        }
    )

    def __post_init__(self) -> None:
        from sangrep_harness.providers.base import OpenAIProtocolIdV1, ProviderReasoningEffortV1

        for field_name, value in (
            ("policy_id", self.policy_id),
            ("provider_id", self.provider_id),
            ("model_id", self.model_id),
        ):
            _require_identifier(value, field_name=field_name)
        if self.provider_id != "openai" or self.model_id not in {
            "gpt-5.6-sol",
            "gpt-5.6-terra",
            "gpt-5.6-luna",
        }:
            raise ReviewSemanticError("Responses egress provider/model authority is invalid.")
        if self.provider_protocol_id is not OpenAIProtocolIdV1.RESPONSES_V1:
            raise ReviewSemanticError("Responses egress protocol authority is invalid.")
        if self.reasoning_effort is not ProviderReasoningEffortV1.MEDIUM:
            raise ReviewSemanticError("Responses egress reasoning effort is invalid.")
        _require_network_destination(self.network_destination)
        if type(self.allowed_data_classes) is not tuple or not self.allowed_data_classes:
            raise ReviewSemanticError("allowed_data_classes must be a non-empty tuple.")
        if any(
            not isinstance(data_class, EgressDataClassV1)
            for data_class in self.allowed_data_classes
        ) or len(self.allowed_data_classes) != len(set(self.allowed_data_classes)):
            raise ReviewSemanticError("allowed_data_classes contains an invalid value.")
        _require_unique_identifiers(
            self.evidence_version_ids,
            field_name="evidence_version_ids",
        )
        if not self.evidence_version_ids:
            raise ReviewSemanticError("evidence_version_ids must not be empty.")
        _require_unique_identifiers(self.media_ids, field_name="media_ids")
        _require_positive_int(self.max_total_bytes, field_name="max_total_bytes")
        _require_safe_positive_int(
            self.model_max_output_tokens,
            field_name="model_max_output_tokens",
        )
        _require_safe_positive_int(
            self.admitted_max_output_tokens,
            field_name="admitted_max_output_tokens",
        )
        for field_name, value in (
            ("route_decision_sha256", self.route_decision_sha256),
            ("route_policy_sha256", self.route_policy_sha256),
            ("pricing_authority_sha256", self.pricing_authority_sha256),
        ):
            _require_sha256(value, field_name=field_name)

    @classmethod
    def from_json_obj(cls, value: object) -> EgressPolicyV2:
        from sangrep_harness.providers.base import OpenAIProtocolIdV1, ProviderReasoningEffortV1

        payload = _require_exact_object(
            value,
            expected=cls._FIELDS,
            field_name="egressPolicy",
        )
        _require_header_version(payload, kind="egressPolicy", version=2)
        raw_data_classes = _require_list(
            payload["allowedDataClasses"],
            field_name="allowedDataClasses",
        )
        return cls(
            policy_id=_require_identifier(payload["policyId"], field_name="policyId"),
            provider_id=_require_identifier(payload["providerId"], field_name="providerId"),
            model_id=_require_identifier(payload["modelId"], field_name="modelId"),
            provider_protocol_id=_require_enum(
                OpenAIProtocolIdV1,
                payload["providerProtocolId"],
                field_name="providerProtocolId",
                unknown_code=ReviewSemanticErrorCodeV1.INVALID_VALUE,
            ),
            reasoning_effort=_require_enum(
                ProviderReasoningEffortV1,
                payload["reasoningEffort"],
                field_name="reasoningEffort",
                unknown_code=ReviewSemanticErrorCodeV1.INVALID_VALUE,
            ),
            network_destination=_require_network_destination(payload["networkDestination"]),
            allowed_data_classes=tuple(
                _require_enum(
                    EgressDataClassV1,
                    item,
                    field_name="allowedDataClasses",
                    unknown_code=ReviewSemanticErrorCodeV1.UNSUPPORTED_EGRESS,
                )
                for item in raw_data_classes
            ),
            evidence_version_ids=_parse_string_tuple(
                payload["evidenceVersionIds"],
                field_name="evidenceVersionIds",
            ),
            media_ids=_parse_string_tuple(payload["mediaIds"], field_name="mediaIds"),
            max_total_bytes=_require_positive_int(
                payload["maxTotalBytes"],
                field_name="maxTotalBytes",
            ),
            model_max_output_tokens=_require_safe_positive_int(
                payload["modelMaxOutputTokens"],
                field_name="model_max_output_tokens",
            ),
            admitted_max_output_tokens=_require_safe_positive_int(
                payload["admittedMaxOutputTokens"],
                field_name="admitted_max_output_tokens",
            ),
            route_decision_sha256=_require_sha256(
                payload["routeDecisionSha256"],
                field_name="routeDecisionSha256",
            ),
            route_policy_sha256=_require_sha256(
                payload["routePolicySha256"],
                field_name="routePolicySha256",
            ),
            pricing_authority_sha256=_require_sha256(
                payload["pricingAuthoritySha256"],
                field_name="pricingAuthoritySha256",
            ),
        )

    def authorize(
        self,
        *,
        data_class: EgressDataClassV1 | str,
        network_destination: str,
        evidence_version_id: str,
        media_id: str | None,
        byte_count: int,
    ) -> None:
        """Apply the same structural egress containment as V1."""

        try:
            normalized_class = EgressDataClassV1(data_class)
        except ValueError:
            raise ReviewSemanticError(
                "Egress data class is unsupported.",
                code=ReviewSemanticErrorCodeV1.UNSUPPORTED_EGRESS,
            ) from None
        if (
            normalized_class not in self.allowed_data_classes
            or network_destination != self.network_destination
            or evidence_version_id not in self.evidence_version_ids
            or byte_count < 0
            or byte_count > self.max_total_bytes
        ):
            raise ReviewSemanticError(
                "Egress request is outside the standing policy.",
                code=ReviewSemanticErrorCodeV1.UNSUPPORTED_EGRESS,
            )
        if normalized_class is EgressDataClassV1.ADMITTED_MEDIA:
            if media_id is None or media_id not in self.media_ids:
                raise ReviewSemanticError(
                    "Egress media is not admitted by policy.",
                    code=ReviewSemanticErrorCodeV1.UNSUPPORTED_EGRESS,
                )
        elif media_id is not None:
            raise ReviewSemanticError(
                "Only admitted_media egress may carry a media ID.",
                code=ReviewSemanticErrorCodeV1.UNSUPPORTED_EGRESS,
            )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 2,
            "kind": "egressPolicy",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "policyId": self.policy_id,
            "providerId": self.provider_id,
            "modelId": self.model_id,
            "providerProtocolId": self.provider_protocol_id.value,
            "reasoningEffort": self.reasoning_effort.value,
            "networkDestination": self.network_destination,
            "allowedDataClasses": [item.value for item in self.allowed_data_classes],
            "evidenceVersionIds": list(self.evidence_version_ids),
            "mediaIds": list(self.media_ids),
            "maxTotalBytes": self.max_total_bytes,
            "modelMaxOutputTokens": self.model_max_output_tokens,
            "admittedMaxOutputTokens": self.admitted_max_output_tokens,
            "routeDecisionSha256": self.route_decision_sha256,
            "routePolicySha256": self.route_policy_sha256,
            "pricingAuthoritySha256": self.pricing_authority_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class ReviewReceiptV1:
    """Portable identity receipt for what one run attempted and reached."""

    receipt_id: str
    run_id: str
    evidence_binding_sha256: str
    grant_sha256: str
    context_sha256: str
    egress_policy_sha256: str
    limits_sha256: str
    pre_terminal_event_head_sha256: str
    terminal_result_sha256: str
    provider_call_state: ProviderCallStateV1
    route_decision_sha256: str | None = None
    route_policy_sha256: str | None = None
    pricing_authority_sha256: str | None = None
    provider_id: str | None = None
    model_id: str | None = None

    _FIELDS = frozenset(
        {
            "schemaVersion",
            "kind",
            "contractId",
            "receiptId",
            "runId",
            "evidenceBindingSha256",
            "grantSha256",
            "contextSha256",
            "egressPolicySha256",
            "limitsSha256",
            "preTerminalEventHeadSha256",
            "terminalResultSha256",
            "providerCallState",
        }
    )
    _ROUTED_FIELDS = _FIELDS | frozenset(
        {
            "routeDecisionSha256",
            "routePolicySha256",
            "pricingAuthoritySha256",
            "providerId",
            "modelId",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.receipt_id, field_name="receipt_id")
        _require_identifier(self.run_id, field_name="run_id")
        for field_name, value in (
            ("evidence_binding_sha256", self.evidence_binding_sha256),
            ("grant_sha256", self.grant_sha256),
            ("context_sha256", self.context_sha256),
            ("egress_policy_sha256", self.egress_policy_sha256),
            ("limits_sha256", self.limits_sha256),
            (
                "pre_terminal_event_head_sha256",
                self.pre_terminal_event_head_sha256,
            ),
            ("terminal_result_sha256", self.terminal_result_sha256),
        ):
            _require_sha256(value, field_name=field_name)
        if not isinstance(self.provider_call_state, ProviderCallStateV1):
            raise ReviewSemanticError("provider_call_state contains an unknown value.")
        routed = (
            self.route_decision_sha256,
            self.route_policy_sha256,
            self.pricing_authority_sha256,
            self.provider_id,
            self.model_id,
        )
        if any(value is not None for value in routed):
            if any(value is None for value in routed):
                raise ReviewSemanticError("Routed receipt authority must be complete.")
            for field_name, route_value in (
                ("route_decision_sha256", self.route_decision_sha256),
                ("route_policy_sha256", self.route_policy_sha256),
                ("pricing_authority_sha256", self.pricing_authority_sha256),
            ):
                assert route_value is not None
                _require_sha256(route_value, field_name=field_name)
            _require_identifier(self.provider_id, field_name="provider_id")
            _require_identifier(self.model_id, field_name="model_id")

    @classmethod
    def from_json_obj(cls, value: object) -> ReviewReceiptV1:
        if type(value) is not dict:
            raise ReviewSemanticError("reviewReceipt must be an object.")
        raw = cast(dict[str, JsonValue], value)
        routed = frozenset(raw) == cls._ROUTED_FIELDS
        expected = cls._ROUTED_FIELDS if routed else cls._FIELDS
        payload = _require_exact_object(value, expected=expected, field_name="reviewReceipt")
        _require_header(payload, kind="reviewReceipt")
        return cls(
            receipt_id=_require_identifier(payload["receiptId"], field_name="receiptId"),
            run_id=_require_identifier(payload["runId"], field_name="runId"),
            evidence_binding_sha256=_require_sha256(
                payload["evidenceBindingSha256"],
                field_name="evidenceBindingSha256",
            ),
            grant_sha256=_require_sha256(payload["grantSha256"], field_name="grantSha256"),
            context_sha256=_require_sha256(
                payload["contextSha256"],
                field_name="contextSha256",
            ),
            egress_policy_sha256=_require_sha256(
                payload["egressPolicySha256"],
                field_name="egressPolicySha256",
            ),
            limits_sha256=_require_sha256(payload["limitsSha256"], field_name="limitsSha256"),
            pre_terminal_event_head_sha256=_require_sha256(
                payload["preTerminalEventHeadSha256"],
                field_name="preTerminalEventHeadSha256",
            ),
            terminal_result_sha256=_require_sha256(
                payload["terminalResultSha256"],
                field_name="terminalResultSha256",
            ),
            provider_call_state=_require_enum(
                ProviderCallStateV1,
                payload["providerCallState"],
                field_name="providerCallState",
                unknown_code=ReviewSemanticErrorCodeV1.INVALID_VALUE,
            ),
            route_decision_sha256=(
                _require_sha256(payload["routeDecisionSha256"], field_name="routeDecisionSha256")
                if routed
                else None
            ),
            route_policy_sha256=(
                _require_sha256(payload["routePolicySha256"], field_name="routePolicySha256")
                if routed
                else None
            ),
            pricing_authority_sha256=(
                _require_sha256(
                    payload["pricingAuthoritySha256"],
                    field_name="pricingAuthoritySha256",
                )
                if routed
                else None
            ),
            provider_id=(
                _require_identifier(payload["providerId"], field_name="providerId")
                if routed
                else None
            ),
            model_id=(
                _require_identifier(payload["modelId"], field_name="modelId") if routed else None
            ),
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        payload: dict[str, JsonValue] = {
            "schemaVersion": 1,
            "kind": "reviewReceipt",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "receiptId": self.receipt_id,
            "runId": self.run_id,
            "evidenceBindingSha256": self.evidence_binding_sha256,
            "grantSha256": self.grant_sha256,
            "contextSha256": self.context_sha256,
            "egressPolicySha256": self.egress_policy_sha256,
            "limitsSha256": self.limits_sha256,
            "preTerminalEventHeadSha256": self.pre_terminal_event_head_sha256,
            "terminalResultSha256": self.terminal_result_sha256,
            "providerCallState": self.provider_call_state.value,
        }
        if self.route_decision_sha256 is not None:
            payload.update(
                {
                    "routeDecisionSha256": self.route_decision_sha256,
                    "routePolicySha256": self.route_policy_sha256,
                    "pricingAuthoritySha256": self.pricing_authority_sha256,
                    "providerId": self.provider_id,
                    "modelId": self.model_id,
                }
            )
        return payload

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class ReviewReceiptV2:
    """Sanitized Responses receipt bound to its exact durable authority prefix."""

    receipt_id: str
    run_id: str
    evidence_binding_sha256: str
    grant_sha256: str
    context_sha256: str
    egress_policy_sha256: str
    limits_sha256: str
    pre_terminal_event_head_sha256: str
    terminal_result_sha256: str
    provider_call_state: ProviderCallStateV1
    route_decision_sha256: str
    route_policy_sha256: str
    pricing_authority_sha256: str
    provider_id: str
    model_id: str
    provider_protocol_id: OpenAIProtocolIdV1
    reasoning_effort: ProviderReasoningEffortV1
    physical_request_sha256: str | None
    raw_response_sha256: str | None
    continuation_sha256: str | None
    provider_response_failure_code: ProviderResponseFailureCodeV1 | None

    _FIELDS = frozenset(
        {
            "schemaVersion",
            "kind",
            "contractId",
            "receiptId",
            "runId",
            "evidenceBindingSha256",
            "grantSha256",
            "contextSha256",
            "egressPolicySha256",
            "limitsSha256",
            "preTerminalEventHeadSha256",
            "terminalResultSha256",
            "providerCallState",
            "routeDecisionSha256",
            "routePolicySha256",
            "pricingAuthoritySha256",
            "providerId",
            "modelId",
            "providerProtocolId",
            "reasoningEffort",
            "physicalRequestSha256",
            "rawResponseSha256",
            "continuationSha256",
            "providerResponseFailureCode",
        }
    )

    def __post_init__(self) -> None:
        from sangrep_harness.providers.base import (
            OpenAIProtocolIdV1,
            ProviderReasoningEffortV1,
            ProviderResponseFailureCodeV1,
        )

        _require_identifier(self.receipt_id, field_name="receipt_id")
        _require_identifier(self.run_id, field_name="run_id")
        for field_name, value in (
            ("evidence_binding_sha256", self.evidence_binding_sha256),
            ("grant_sha256", self.grant_sha256),
            ("context_sha256", self.context_sha256),
            ("egress_policy_sha256", self.egress_policy_sha256),
            ("limits_sha256", self.limits_sha256),
            ("pre_terminal_event_head_sha256", self.pre_terminal_event_head_sha256),
            ("terminal_result_sha256", self.terminal_result_sha256),
            ("route_decision_sha256", self.route_decision_sha256),
            ("route_policy_sha256", self.route_policy_sha256),
            ("pricing_authority_sha256", self.pricing_authority_sha256),
        ):
            _require_sha256(value, field_name=field_name)
        if type(self.provider_call_state) is not ProviderCallStateV1:
            raise ReviewSemanticError("provider_call_state contains an unknown value.")
        if self.provider_id != "openai" or self.model_id not in {
            "gpt-5.6-sol",
            "gpt-5.6-terra",
            "gpt-5.6-luna",
        }:
            raise ReviewSemanticError("Responses receipt provider/model authority is invalid.")
        if self.provider_protocol_id is not OpenAIProtocolIdV1.RESPONSES_V1:
            raise ReviewSemanticError("Responses receipt protocol authority is invalid.")
        if self.reasoning_effort is not ProviderReasoningEffortV1.MEDIUM:
            raise ReviewSemanticError("Responses receipt reasoning effort is invalid.")
        for field_name, optional_digest in (
            ("physical_request_sha256", self.physical_request_sha256),
            ("raw_response_sha256", self.raw_response_sha256),
            ("continuation_sha256", self.continuation_sha256),
        ):
            if optional_digest is not None:
                _require_sha256(optional_digest, field_name=field_name)
        if (
            self.provider_response_failure_code is not None
            and type(self.provider_response_failure_code) is not ProviderResponseFailureCodeV1
        ):
            raise ReviewSemanticError("Provider response failure code is invalid.")
        if self.provider_call_state in {
            ProviderCallStateV1.NOT_REQUESTED,
            ProviderCallStateV1.BLOCKED_PREFLIGHT,
        }:
            if any(
                value is not None
                for value in (
                    self.physical_request_sha256,
                    self.raw_response_sha256,
                    self.continuation_sha256,
                    self.provider_response_failure_code,
                )
            ):
                raise ReviewSemanticError(
                    "not_requested or blocked_preflight receipt cannot carry physical authority."
                )
            return
        if self.physical_request_sha256 is None:
            raise ReviewSemanticError("Sent Responses receipt requires physical request authority.")
        if self.provider_call_state in {
            ProviderCallStateV1.SENT,
            ProviderCallStateV1.OUTCOME_UNKNOWN,
        }:
            if any(
                value is not None
                for value in (
                    self.raw_response_sha256,
                    self.continuation_sha256,
                    self.provider_response_failure_code,
                )
            ):
                raise ReviewSemanticError(
                    "Ambiguous Responses receipt cannot fabricate response authority."
                )
            return
        if self.provider_call_state is not ProviderCallStateV1.COMPLETED:
            raise ReviewSemanticError("Responses receipt provider-call state is invalid.")
        if self.provider_response_failure_code is None:
            if self.raw_response_sha256 is None or self.continuation_sha256 is None:
                raise ReviewSemanticError(
                    "Completed Responses receipt requires raw and continuation authority."
                )
        elif self.continuation_sha256 is not None and self.raw_response_sha256 is None:
            raise ReviewSemanticError(
                "Responses continuation authority requires raw response authority."
            )

    @classmethod
    def from_json_obj(cls, value: object) -> ReviewReceiptV2:
        from sangrep_harness.providers.base import (
            OpenAIProtocolIdV1,
            ProviderReasoningEffortV1,
            ProviderResponseFailureCodeV1,
        )

        payload = _require_exact_object(
            value,
            expected=cls._FIELDS,
            field_name="reviewReceipt",
        )
        _require_header_version(payload, kind="reviewReceipt", version=2)
        raw_failure = payload["providerResponseFailureCode"]
        return cls(
            receipt_id=_require_identifier(payload["receiptId"], field_name="receiptId"),
            run_id=_require_identifier(payload["runId"], field_name="runId"),
            evidence_binding_sha256=_require_sha256(
                payload["evidenceBindingSha256"],
                field_name="evidenceBindingSha256",
            ),
            grant_sha256=_require_sha256(payload["grantSha256"], field_name="grantSha256"),
            context_sha256=_require_sha256(payload["contextSha256"], field_name="contextSha256"),
            egress_policy_sha256=_require_sha256(
                payload["egressPolicySha256"],
                field_name="egressPolicySha256",
            ),
            limits_sha256=_require_sha256(payload["limitsSha256"], field_name="limitsSha256"),
            pre_terminal_event_head_sha256=_require_sha256(
                payload["preTerminalEventHeadSha256"],
                field_name="preTerminalEventHeadSha256",
            ),
            terminal_result_sha256=_require_sha256(
                payload["terminalResultSha256"],
                field_name="terminalResultSha256",
            ),
            provider_call_state=_require_enum(
                ProviderCallStateV1,
                payload["providerCallState"],
                field_name="providerCallState",
                unknown_code=ReviewSemanticErrorCodeV1.INVALID_VALUE,
            ),
            route_decision_sha256=_require_sha256(
                payload["routeDecisionSha256"],
                field_name="routeDecisionSha256",
            ),
            route_policy_sha256=_require_sha256(
                payload["routePolicySha256"],
                field_name="routePolicySha256",
            ),
            pricing_authority_sha256=_require_sha256(
                payload["pricingAuthoritySha256"],
                field_name="pricingAuthoritySha256",
            ),
            provider_id=_require_identifier(payload["providerId"], field_name="providerId"),
            model_id=_require_identifier(payload["modelId"], field_name="modelId"),
            provider_protocol_id=_require_enum(
                OpenAIProtocolIdV1,
                payload["providerProtocolId"],
                field_name="providerProtocolId",
                unknown_code=ReviewSemanticErrorCodeV1.INVALID_VALUE,
            ),
            reasoning_effort=_require_enum(
                ProviderReasoningEffortV1,
                payload["reasoningEffort"],
                field_name="reasoningEffort",
                unknown_code=ReviewSemanticErrorCodeV1.INVALID_VALUE,
            ),
            physical_request_sha256=_require_optional_sha256(
                payload["physicalRequestSha256"],
                field_name="physicalRequestSha256",
            ),
            raw_response_sha256=_require_optional_sha256(
                payload["rawResponseSha256"],
                field_name="rawResponseSha256",
            ),
            continuation_sha256=_require_optional_sha256(
                payload["continuationSha256"],
                field_name="continuationSha256",
            ),
            provider_response_failure_code=(
                None
                if raw_failure is None
                else _require_enum(
                    ProviderResponseFailureCodeV1,
                    raw_failure,
                    field_name="providerResponseFailureCode",
                    unknown_code=ReviewSemanticErrorCodeV1.INVALID_VALUE,
                )
            ),
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 2,
            "kind": "reviewReceipt",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "receiptId": self.receipt_id,
            "runId": self.run_id,
            "evidenceBindingSha256": self.evidence_binding_sha256,
            "grantSha256": self.grant_sha256,
            "contextSha256": self.context_sha256,
            "egressPolicySha256": self.egress_policy_sha256,
            "limitsSha256": self.limits_sha256,
            "preTerminalEventHeadSha256": self.pre_terminal_event_head_sha256,
            "terminalResultSha256": self.terminal_result_sha256,
            "providerCallState": self.provider_call_state.value,
            "routeDecisionSha256": self.route_decision_sha256,
            "routePolicySha256": self.route_policy_sha256,
            "pricingAuthoritySha256": self.pricing_authority_sha256,
            "providerId": self.provider_id,
            "modelId": self.model_id,
            "providerProtocolId": self.provider_protocol_id.value,
            "reasoningEffort": self.reasoning_effort.value,
            "physicalRequestSha256": self.physical_request_sha256,
            "rawResponseSha256": self.raw_response_sha256,
            "continuationSha256": self.continuation_sha256,
            "providerResponseFailureCode": (
                None
                if self.provider_response_failure_code is None
                else self.provider_response_failure_code.value
            ),
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class EvaluationRequestV1:
    """Evaluator-to-engine projection that cannot carry grader truth."""

    question: str
    scope: FrozenJsonObjectV1
    prior_turns: tuple[FrozenJsonObjectV1, ...]

    @classmethod
    def from_json_obj(cls, value: object) -> EvaluationRequestV1:
        if type(value) is not dict or any(type(key) is not str for key in value):
            raise ReviewSemanticError("Evaluation request must be a JSON object.")
        payload = cast(dict[str, JsonValue], value)
        expected = frozenset({"question", "scope", "priorTurns"})
        if frozenset(payload) != expected:
            forbidden = {
                "answer",
                "expectedAnswer",
                "expectedOutcome",
                "requiredTrail",
                "rubric",
                "grader",
                "atomicFacts",
            }
            if any(key in forbidden for key in payload):
                raise ReviewSemanticError(
                    "Evaluator request contains answer-key material.",
                    code=ReviewSemanticErrorCodeV1.ANSWER_KEY_MATERIAL,
                )
            raise ReviewSemanticError("Evaluation request has missing or unknown fields.")
        question = _require_non_empty_text(payload["question"], field_name="question")
        scope = freeze_json_object_v1(payload["scope"])
        _validate_evaluation_scope(scope.to_json_obj())
        raw_turns = _require_list(payload["priorTurns"], field_name="priorTurns")
        turns = tuple(freeze_json_object_v1(turn) for turn in raw_turns)
        for turn in turns:
            _validate_prior_turn(turn.to_json_obj())
        return cls(question=question, scope=scope, prior_turns=turns)

    def __post_init__(self) -> None:
        _require_non_empty_text(self.question, field_name="question")
        if type(self.scope) is not FrozenJsonObjectV1:
            raise ReviewSemanticError("scope must be a frozen JSON object.")
        _validate_evaluation_scope(self.scope.to_json_obj())
        if type(self.prior_turns) is not tuple:
            raise ReviewSemanticError("prior_turns must be an immutable tuple.")
        for turn in self.prior_turns:
            if type(turn) is not FrozenJsonObjectV1:
                raise ReviewSemanticError("prior_turns contains an invalid turn.")
            _validate_prior_turn(turn.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "question": self.question,
            "scope": self.scope.to_json_obj(),
            "priorTurns": [turn.to_json_obj() for turn in self.prior_turns],
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class HumanAuthorityCommandV1:
    """Semantic validation for the six append-only reviewer mutation commands."""

    command: ReviewCommandV1

    _METHODS = frozenset(
        {
            ReviewMethodV1.FINDING_DISPOSITION_APPEND,
            ReviewMethodV1.CLARIFICATION_RESPOND,
            ReviewMethodV1.CLARIFICATION_WAIVE,
            ReviewMethodV1.KNOWLEDGE_CONFIRM,
            ReviewMethodV1.REVIEW_COMPLETION_APPEND,
            ReviewMethodV1.REVIEW_COMPLETION_SUPERSEDE,
        }
    )

    def __post_init__(self) -> None:
        if type(self.command) is not ReviewCommandV1 or self.command.method not in self._METHODS:
            raise ReviewSemanticError(
                "Command is not a frozen human-authority mutation.",
                code=ReviewSemanticErrorCodeV1.HUMAN_AUTHORITY,
            )
        _validate_human_authority_payload(self.command)

    @classmethod
    def from_json_obj(cls, value: object) -> HumanAuthorityCommandV1:
        return cls(ReviewCommandV1.from_json_obj(value))

    @property
    def actor_id(self) -> str:
        return _require_identifier(
            self.command.payload.to_json_obj()["actorId"],
            field_name="actorId",
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return self.command.to_json_obj()

    @property
    def digest(self) -> str:
        return self.command.digest


def _require_context_layer(
    revision: object,
    expected: ContextLayerV1,
) -> ContextRevisionRefV1:
    if type(revision) is not ContextRevisionRefV1 or revision.layer is not expected:
        raise ReviewSemanticError(f"Expected the {expected.value} context layer.")
    return revision


def _require_network_destination(value: object) -> str:
    text = _require_nfc_text(value, field_name="network_destination")
    if (
        not text
        or len(text) > 253
        or text.startswith(".")
        or text.endswith(".")
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for character in text)
    ):
        raise ReviewSemanticError("network_destination must be a lowercase host name.")
    return text


def _validate_evaluation_scope(value: object) -> None:
    scope = _require_exact_object(
        value,
        expected=frozenset({"mode", "roots"}),
        field_name="evaluationScope",
    )
    if scope["mode"] not in ("global", "scoped"):
        raise ReviewSemanticError("Evaluation scope mode contains an unknown value.")
    roots = _parse_string_tuple(scope["roots"], field_name="roots")
    if not roots:
        raise ReviewSemanticError("Evaluation scope roots must not be empty.")
    _require_unique_identifiers(roots, field_name="roots")


def _validate_prior_turn(value: object) -> None:
    turn = _require_exact_object(
        value,
        expected=frozenset({"role", "content"}),
        field_name="priorTurn",
    )
    if turn["role"] not in ("user", "assistant"):
        raise ReviewSemanticError("Prior turn role contains an unknown value.")
    _require_non_empty_text(turn["content"], field_name="priorTurn.content")


def _validate_human_authority_payload(command: ReviewCommandV1) -> None:
    payload = command.payload.to_json_obj()
    method = command.method
    fields_by_method = {
        ReviewMethodV1.FINDING_DISPOSITION_APPEND: frozenset(
            {
                "actorId",
                "findingId",
                "disposition",
                "note",
                "expectedHeadSha256",
                "supersedesDispositionId",
            }
        ),
        ReviewMethodV1.CLARIFICATION_RESPOND: frozenset(
            {
                "actorId",
                "questionId",
                "responseKind",
                "response",
                "expectedHeadSha256",
                "supersedesResolutionId",
            }
        ),
        ReviewMethodV1.CLARIFICATION_WAIVE: frozenset(
            {"actorId", "questionId", "reason", "expectedHeadSha256"}
        ),
        ReviewMethodV1.KNOWLEDGE_CONFIRM: frozenset(
            {
                "actorId",
                "proposalId",
                "knowledgeKey",
                "content",
                "applicability",
                "predecessorId",
                "expectedHeadSha256",
                "authorityKind",
            }
        ),
        ReviewMethodV1.REVIEW_COMPLETION_APPEND: frozenset(
            {
                "actorId",
                "runId",
                "outcome",
                "profileId",
                "evidenceSha256",
                "grantSha256",
                "assessmentHeadSha256",
                "decisionHeadSha256",
                "limitationIds",
                "expectedHeadSha256",
            }
        ),
        ReviewMethodV1.REVIEW_COMPLETION_SUPERSEDE: frozenset(
            {
                "actorId",
                "runId",
                "supersedesCompletionId",
                "outcome",
                "profileId",
                "evidenceSha256",
                "grantSha256",
                "assessmentHeadSha256",
                "decisionHeadSha256",
                "limitationIds",
                "expectedHeadSha256",
            }
        ),
    }
    expected = fields_by_method[method]
    _require_exact_object(payload, expected=expected, field_name=method.value)
    _require_identifier(payload["actorId"], field_name="actorId")
    _require_sha256(payload["expectedHeadSha256"], field_name="expectedHeadSha256")
    if method is ReviewMethodV1.FINDING_DISPOSITION_APPEND:
        _validate_finding_disposition(payload)
    elif method is ReviewMethodV1.CLARIFICATION_RESPOND:
        _validate_clarification_response(payload)
    elif method is ReviewMethodV1.CLARIFICATION_WAIVE:
        _require_identifier(payload["questionId"], field_name="questionId")
        _require_non_empty_text(payload["reason"], field_name="reason")
    elif method is ReviewMethodV1.KNOWLEDGE_CONFIRM:
        _validate_knowledge_confirmation(payload)
    else:
        _validate_completion(
            payload, superseding=method is ReviewMethodV1.REVIEW_COMPLETION_SUPERSEDE
        )


def _validate_finding_disposition(payload: dict[str, JsonValue]) -> None:
    _require_identifier(payload["findingId"], field_name="findingId")
    disposition = payload["disposition"]
    if disposition not in ("accepted", "rejected", "deferred"):
        raise ReviewSemanticError(
            "Finding disposition contains an unknown value.",
            code=ReviewSemanticErrorCodeV1.HUMAN_AUTHORITY,
        )
    note = _require_optional_text(payload["note"], field_name="note")
    if disposition in ("rejected", "deferred") and note is None:
        raise ReviewSemanticError("Rejected or deferred findings require a reviewer note.")
    _require_optional_identifier(
        payload["supersedesDispositionId"],
        field_name="supersedesDispositionId",
    )


def _validate_clarification_response(payload: dict[str, JsonValue]) -> None:
    _require_identifier(payload["questionId"], field_name="questionId")
    if payload["responseKind"] not in (
        "answered",
        "assumption",
        "not_relevant",
        "do_not_know",
        "correction",
        "follow_up",
        "reopened",
    ):
        raise ReviewSemanticError(
            "Clarification response kind contains an unknown value.",
            code=ReviewSemanticErrorCodeV1.HUMAN_AUTHORITY,
        )
    _require_non_empty_text(payload["response"], field_name="response")
    _require_optional_identifier(
        payload["supersedesResolutionId"],
        field_name="supersedesResolutionId",
    )


def _validate_knowledge_confirmation(payload: dict[str, JsonValue]) -> None:
    for field_name in ("proposalId", "knowledgeKey"):
        _require_identifier(payload[field_name], field_name=field_name)
    _require_non_empty_text(payload["content"], field_name="content")
    _require_optional_identifier(payload["predecessorId"], field_name="predecessorId")
    if payload["authorityKind"] != "non_corpus":
        raise ReviewSemanticError(
            "Confirmed knowledge must remain non-corpus human context.",
            code=ReviewSemanticErrorCodeV1.HUMAN_AUTHORITY,
        )
    applicability = _require_exact_object(
        payload["applicability"],
        expected=frozenset({"kind"}),
        field_name="applicability",
    )
    if applicability["kind"] != "workspace":
        raise ReviewSemanticError("This alpha vector admits workspace applicability only.")


def _validate_completion(payload: dict[str, JsonValue], *, superseding: bool) -> None:
    for field_name in ("runId", "profileId"):
        _require_identifier(payload[field_name], field_name=field_name)
    allowed_outcomes: tuple[str, ...]
    if superseding:
        _require_identifier(
            payload["supersedesCompletionId"],
            field_name="supersedesCompletionId",
        )
        allowed_outcomes = ("reviewed", "reviewed_with_limitations", "reopened")
    else:
        allowed_outcomes = ("reviewed", "reviewed_with_limitations")
    outcome = payload["outcome"]
    if outcome not in allowed_outcomes:
        raise ReviewSemanticError(
            "Completion outcome is not admitted for this append command.",
            code=ReviewSemanticErrorCodeV1.HUMAN_AUTHORITY,
        )
    for field_name in (
        "evidenceSha256",
        "grantSha256",
        "assessmentHeadSha256",
        "decisionHeadSha256",
    ):
        _require_sha256(payload[field_name], field_name=field_name)
    limitations = _parse_string_tuple(payload["limitationIds"], field_name="limitationIds")
    _require_unique_identifiers(limitations, field_name="limitationIds")
    if outcome == "reviewed_with_limitations" and not limitations:
        raise ReviewSemanticError("reviewed_with_limitations must enumerate limitations.")
    if outcome in ("reviewed", "reopened") and limitations:
        raise ReviewSemanticError(f"{outcome} cannot carry limitation IDs.")


def _require_draft_header(payload: dict[str, JsonValue], *, kind: str) -> None:
    if (
        type(payload["schemaVersion"]) is not int
        or payload["schemaVersion"] != 1
        or payload["kind"] != kind
    ):
        raise ReviewSemanticError(f"{kind} uses an incompatible draft header.")


def _validate_evidence_version_draft(value: object) -> dict[str, JsonValue]:
    try:
        public_contracts.EvidenceVersionV1.from_json_obj(value)
    except public_contracts.ContractValidationError:
        raise ReviewSemanticError("Accepted public contract rejected this value.") from None
    payload = _require_exact_object(
        value,
        expected=frozenset(
            {
                "schemaVersion",
                "kind",
                "evidenceVersionId",
                "sourceVersionIds",
                "adapterProfileId",
                "adapterProfileSha256",
                "coverageState",
                "warningCodes",
                "blockerCodes",
                "canonicalOutputSha256",
            }
        ),
        field_name="evidenceVersion",
    )
    _require_draft_header(payload, kind="evidenceVersion")
    _require_identifier(payload["evidenceVersionId"], field_name="evidenceVersionId")
    source_version_ids = _parse_string_tuple(
        payload["sourceVersionIds"],
        field_name="sourceVersionIds",
    )
    if not source_version_ids:
        raise ReviewSemanticError("sourceVersionIds must not be empty.")
    _require_unique_identifiers(source_version_ids, field_name="sourceVersionIds")
    _require_identifier(payload["adapterProfileId"], field_name="adapterProfileId")
    _require_sha256(
        payload["adapterProfileSha256"],
        field_name="adapterProfileSha256",
    )
    if payload["coverageState"] not in ("complete", "partial", "blocked"):
        raise ReviewSemanticError("coverageState contains an unknown value.")
    for field_name in ("warningCodes", "blockerCodes"):
        codes = _parse_string_tuple(payload[field_name], field_name=field_name)
        _require_unique_names(codes, field_name=field_name, pattern=_CODE)
    _require_sha256(
        payload["canonicalOutputSha256"],
        field_name="canonicalOutputSha256",
    )
    return payload


def _validate_structure_revision_draft(value: object) -> dict[str, JsonValue]:
    try:
        public_contracts.StructureRevisionV1.from_json_obj(value)
    except public_contracts.ContractValidationError:
        raise ReviewSemanticError("Accepted public contract rejected this value.") from None
    payload = _require_exact_object(
        value,
        expected=frozenset(
            {
                "schemaVersion",
                "kind",
                "structureRevisionId",
                "evidenceVersionId",
                "structureProfileId",
                "structureProfileSha256",
                "graphSha256",
            }
        ),
        field_name="structureRevision",
    )
    _require_draft_header(payload, kind="structureRevision")
    for field_name in (
        "structureRevisionId",
        "evidenceVersionId",
        "structureProfileId",
    ):
        _require_identifier(payload[field_name], field_name=field_name)
    _require_sha256(
        payload["structureProfileSha256"],
        field_name="structureProfileSha256",
    )
    _require_sha256(payload["graphSha256"], field_name="graphSha256")
    return payload


def _validate_projection_revision_draft(value: object) -> dict[str, JsonValue]:
    try:
        public_contracts.ProjectionRevisionV1.from_json_obj(value)
    except public_contracts.ContractValidationError:
        raise ReviewSemanticError("Accepted public contract rejected this value.") from None
    payload = _require_exact_object(
        value,
        expected=frozenset(
            {
                "schemaVersion",
                "kind",
                "projectionRevisionId",
                "structureRevisionId",
                "projectionProfileId",
                "projectionProfileVersion",
                "projectionProfileSha256",
                "payloadSha256",
            }
        ),
        field_name="projectionRevision",
    )
    _require_draft_header(payload, kind="projectionRevision")
    for field_name in (
        "projectionRevisionId",
        "structureRevisionId",
        "projectionProfileId",
        "projectionProfileVersion",
    ):
        _require_identifier(payload[field_name], field_name=field_name)
    _require_sha256(
        payload["projectionProfileSha256"],
        field_name="projectionProfileSha256",
    )
    _require_sha256(payload["payloadSha256"], field_name="payloadSha256")
    return payload


def _validate_citation_address_shape(value: object) -> dict[str, JsonValue]:
    try:
        public_contracts.CitationAddressV1.from_json_obj(value)
    except public_contracts.ContractValidationError:
        raise ReviewSemanticError("Accepted public contract rejected this value.") from None
    expected = frozenset(
        {
            "schemaVersion",
            "kind",
            "evidenceVersionId",
            "structureRevisionId",
            "projectionRevisionId",
            "rootAnchorId",
            "anchorId",
            "occurrenceId",
            "selector",
            "exactQuoteSha256",
            "projectionProfileId",
            "projectionProfileVersion",
            "projectionPayloadSha256",
            "admittedByToolCallId",
        }
    )
    address = _require_exact_object(value, expected=expected, field_name="citationAddress")
    if (
        type(address["schemaVersion"]) is not int
        or address["schemaVersion"] != 1
        or address["kind"] != "citationAddress"
    ):
        raise ReviewSemanticError("Citation address uses an incompatible schema or kind.")
    for field_name in (
        "evidenceVersionId",
        "structureRevisionId",
        "projectionRevisionId",
        "rootAnchorId",
        "anchorId",
        "projectionProfileId",
        "projectionProfileVersion",
        "admittedByToolCallId",
    ):
        _require_identifier(address[field_name], field_name=field_name)
    _require_optional_identifier(address["occurrenceId"], field_name="occurrenceId")
    _require_optional_sha256(address["exactQuoteSha256"], field_name="exactQuoteSha256")
    _require_sha256(
        address["projectionPayloadSha256"],
        field_name="projectionPayloadSha256",
    )
    _validate_citation_selector_shape(
        address["selector"],
        anchor_id=cast(str, address["anchorId"]),
    )
    return address


def _validate_citation_selector_shape(value: object, *, anchor_id: str) -> None:
    if type(value) is not dict:
        raise ReviewSemanticError("citationSelector must be a JSON object.")
    kind = value.get("kind")
    fields_by_kind = {
        "node": frozenset({"kind", "anchorId"}),
        "lineRange": frozenset({"kind", "startLine", "endLine"}),
        "textSpan": frozenset({"kind", "startOffset", "endOffset"}),
        "section": frozenset({"kind", "sectionOrdinalPath"}),
        "tableRange": frozenset(
            {
                "kind",
                "tableOrdinalPath",
                "startRow",
                "endRow",
                "startColumn",
                "endColumn",
            }
        ),
        "pageRegion": frozenset(
            {"kind", "pageNumber", "x", "y", "width", "height", "coordinateProfile"}
        ),
        "mediaRegion": frozenset(
            {"kind", "mediaObjectId", "x", "y", "width", "height", "coordinateProfile"}
        ),
    }
    if type(kind) is not str or kind not in fields_by_kind:
        raise ReviewSemanticError("citationSelector contains an unknown selector kind.")
    selector = _require_exact_object(
        value,
        expected=fields_by_kind[kind],
        field_name="citationSelector",
    )
    if kind == "node":
        if _require_identifier(selector["anchorId"], field_name="selector.anchorId") != anchor_id:
            raise ReviewSemanticError("Citation node selector must bind the exact anchor.")
    elif kind == "lineRange":
        _require_ordered_positive_range(
            selector["startLine"],
            selector["endLine"],
            field_name="lineRange",
        )
    elif kind == "textSpan":
        start = _require_non_negative_int(selector["startOffset"], field_name="startOffset")
        end = _require_non_negative_int(selector["endOffset"], field_name="endOffset")
        if end <= start:
            raise ReviewSemanticError("textSpan must be ordered and non-empty.")
    elif kind == "section":
        _require_ordinal_path(selector["sectionOrdinalPath"], field_name="sectionOrdinalPath")
    elif kind == "tableRange":
        _require_ordinal_path(selector["tableOrdinalPath"], field_name="tableOrdinalPath")
        _require_ordered_positive_range(
            selector["startRow"],
            selector["endRow"],
            field_name="tableRows",
        )
        _require_ordered_positive_range(
            selector["startColumn"],
            selector["endColumn"],
            field_name="tableColumns",
        )
    else:
        assert kind in ("pageRegion", "mediaRegion")
        if kind == "pageRegion":
            _require_positive_int(selector["pageNumber"], field_name="pageNumber")
        else:
            _require_identifier(selector["mediaObjectId"], field_name="mediaObjectId")
        _require_non_negative_int(selector["x"], field_name="x")
        _require_non_negative_int(selector["y"], field_name="y")
        _require_positive_int(selector["width"], field_name="width")
        _require_positive_int(selector["height"], field_name="height")
        _require_identifier(selector["coordinateProfile"], field_name="coordinateProfile")


def _require_ordinal_path(value: object, *, field_name: str) -> tuple[int, ...]:
    if type(value) is not list or not value:
        raise ReviewSemanticError(f"{field_name} must be a non-empty JSON array.")
    return tuple(_require_non_negative_int(item, field_name=field_name) for item in value)


def _require_ordered_positive_range(
    start: object,
    end: object,
    *,
    field_name: str,
) -> None:
    first = _require_positive_int(start, field_name=f"{field_name}.start")
    last = _require_positive_int(end, field_name=f"{field_name}.end")
    if last < first:
        raise ReviewSemanticError(f"{field_name} must be ordered and non-empty.")


def _validate_citation_against_grant(
    address: dict[str, JsonValue],
    *,
    grant: StructuralGrantV1,
    admitted_tool_call_ids: tuple[str, ...],
) -> None:
    address = _validate_citation_address_shape(address)
    binding = grant.evidence_binding
    if (
        address["evidenceVersionId"] != binding.evidence_version_id
        or address["structureRevisionId"] != binding.structure_revision_id
        or address["projectionRevisionId"] != binding.projection_revision_id
        or address["projectionPayloadSha256"] != binding.projection_payload_sha256
    ):
        raise ReviewSemanticError(
            "Citation uses an identity outside the structural grant.",
            code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
        )
    admitted_roots = {root.stable_id for root in grant.evidence_roots}
    if address["rootAnchorId"] not in admitted_roots:
        raise ReviewSemanticError(
            "Citation root is outside the structural grant.",
            code=ReviewSemanticErrorCodeV1.CROSS_GRANT,
        )
    admitted_call = cast(str, address["admittedByToolCallId"])
    if admitted_call not in admitted_tool_call_ids:
        raise ReviewSemanticError(
            "Citation was not admitted by a successful tool call.",
            code=ReviewSemanticErrorCodeV1.UNADMITTED_CITATION,
        )


def _require_header(payload: dict[str, JsonValue], *, kind: str) -> None:
    _require_header_version(payload, kind=kind, version=1)


def _require_header_version(
    payload: dict[str, JsonValue],
    *,
    kind: str,
    version: int,
) -> None:
    if (
        type(payload["schemaVersion"]) is not int
        or payload["schemaVersion"] != version
        or payload["kind"] != kind
    ):
        raise ReviewSemanticError("Contract header uses an incompatible schema or kind.")
    if payload["contractId"] != HARNESS_REVIEW_CONTRACT_ID:
        raise ReviewSemanticError("Contract header uses an incompatible contract ID.")


def _require_exact_object(
    value: object,
    *,
    expected: frozenset[str],
    field_name: str,
) -> dict[str, JsonValue]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ReviewSemanticError(f"{field_name} must be a JSON object.")
    result = cast(dict[str, JsonValue], value)
    if frozenset(result) != expected:
        raise ReviewSemanticError(f"{field_name} has missing or unknown fields.")
    return result


def _require_nfc_text(value: object, *, field_name: str) -> str:
    if type(value) is not str or unicodedata.normalize("NFC", value) != value:
        raise ReviewSemanticError(f"{field_name} must be an NFC string.")
    return value


def _require_non_empty_text(value: object, *, field_name: str) -> str:
    text = _require_nfc_text(value, field_name=field_name)
    if not text.strip():
        raise ReviewSemanticError(f"{field_name} must not be blank.")
    return text


def _require_optional_text(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_non_empty_text(value, field_name=field_name)


def _require_optional_code(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    text = _require_nfc_text(value, field_name=field_name)
    if _CODE.fullmatch(text) is None:
        raise ReviewSemanticError(f"{field_name} must be a bounded machine code.")
    return text


def _require_identifier(value: object, *, field_name: str) -> str:
    text = _require_nfc_text(value, field_name=field_name)
    if _IDENTIFIER.fullmatch(text) is None:
        raise ReviewSemanticError(f"{field_name} must be a bounded opaque identifier.")
    return text


def _require_optional_identifier(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_identifier(value, field_name=field_name)


def _provider_failure_diagnostic_v1(value: object) -> ProviderFailureDiagnosticV1:
    try:
        return ProviderFailureDiagnosticV1.from_json_obj(value)
    except (TypeError, ValueError):
        raise ReviewSemanticError("Provider failure diagnostic is invalid.") from None


def _require_sha256(value: object, *, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ReviewSemanticError(f"{field_name} must be a lowercase SHA-256 digest.")
    return value


def _require_optional_sha256(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name=field_name)


def _require_non_negative_int(value: object, *, field_name: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER:
        raise ReviewSemanticError(f"{field_name} must be a safe non-negative integer.")
    return value


def _require_positive_int(value: object, *, field_name: str) -> int:
    result = _require_non_negative_int(value, field_name=field_name)
    if result == 0:
        raise ReviewSemanticError(f"{field_name} must be positive.")
    return result


def _require_safe_positive_int(value: object, *, field_name: str) -> int:
    if type(value) is not int or value <= 0 or value > MAX_SAFE_INTEGER:
        raise ReviewSemanticError(f"{field_name} must be a safe positive integer.")
    return value


def _require_enum(
    enum_type: type[EnumV1],
    value: object,
    *,
    field_name: str,
    unknown_code: ReviewSemanticErrorCodeV1,
) -> EnumV1:
    if type(value) is not str:
        raise ReviewSemanticError(f"{field_name} must be a string enum value.")
    try:
        return enum_type(value)
    except ValueError:
        raise ReviewSemanticError(
            f"{field_name} contains an unknown enum value.",
            code=unknown_code,
        ) from None


def _require_list(value: object, *, field_name: str) -> list[JsonValue]:
    if type(value) is not list:
        raise ReviewSemanticError(f"{field_name} must be a JSON array.")
    return cast(list[JsonValue], value)


def _parse_string_tuple(value: object, *, field_name: str) -> tuple[str, ...]:
    raw = _require_list(value, field_name=field_name)
    if any(type(item) is not str for item in raw):
        raise ReviewSemanticError(f"{field_name} must contain only strings.")
    return cast(tuple[str, ...], tuple(raw))


def _require_unique_names(
    values: tuple[str, ...],
    *,
    field_name: str,
    pattern: re.Pattern[str],
) -> None:
    if type(values) is not tuple or any(
        type(value) is not str or pattern.fullmatch(value) is None for value in values
    ):
        raise ReviewSemanticError(f"{field_name} contains an invalid value.")
    if len(values) != len(set(values)):
        raise ReviewSemanticError(f"{field_name} contains a duplicate value.")


def _require_unique_identifiers(values: tuple[str, ...], *, field_name: str) -> None:
    if type(values) is not tuple:
        raise ReviewSemanticError(f"{field_name} must be an immutable tuple.")
    for value in values:
        _require_identifier(value, field_name=field_name)
    if len(values) != len(set(values)):
        raise ReviewSemanticError(f"{field_name} contains a duplicate identifier.")


ReviewSemanticValueV1: TypeAlias = (
    EvidenceBindingV1
    | ReviewLimitsV1
    | StructuralGrantV1
    | CitationAdmissionV1
    | CitationResolutionV1
    | ContextBindingV1
    | EgressPolicyV1
    | TerminalReviewResultV1
    | ReviewReceiptV1
    | EvaluationRequestV1
    | HumanAuthorityCommandV1
)


def parse_review_semantic_value_v1(
    value: object,
    *,
    grant: StructuralGrantV1 | None = None,
    admitted_tool_call_ids: tuple[str, ...] = (),
    citation: CitationAdmissionV1 | None = None,
    draft_identities: EvidenceIdentityDraftsV1 | None = None,
) -> ReviewSemanticValueV1:
    """Dispatch one semantic vector without importing storage, providers, or parser code."""

    if type(value) is not dict:
        raise ReviewSemanticError("Review semantic value must be a JSON object.")
    kind = value.get("kind")
    if kind == "evidenceBinding":
        return EvidenceBindingV1.from_json_obj(
            value,
            draft_identities=draft_identities,
        )
    if kind == "reviewLimits":
        return ReviewLimitsV1.from_json_obj(value)
    if kind == "structuralGrant":
        return StructuralGrantV1.from_json_obj(
            value,
            draft_identities=draft_identities,
        )
    if kind == "citationAdmission":
        return CitationAdmissionV1.from_json_obj(
            value,
            grant=grant,
            admitted_tool_call_ids=admitted_tool_call_ids,
        )
    if kind == "citationResolution":
        return CitationResolutionV1.from_json_obj(
            value,
            citation=citation,
            grant=grant,
        )
    if kind == "contextBinding":
        return ContextBindingV1.from_json_obj(value)
    if kind == "egressPolicy":
        return EgressPolicyV1.from_json_obj(value)
    if kind == "terminalReviewResult":
        return TerminalReviewResultV1.from_json_obj(
            value,
            grant=grant,
            admitted_tool_call_ids=admitted_tool_call_ids,
        )
    if kind == "reviewReceipt":
        return ReviewReceiptV1.from_json_obj(value)
    if kind == "reviewCommand":
        return HumanAuthorityCommandV1.from_json_obj(value)
    if kind is None and frozenset(value) == frozenset({"question", "scope", "priorTurns"}):
        return EvaluationRequestV1.from_json_obj(value)
    raise ReviewSemanticError("Review semantic value contains an unknown kind.")
