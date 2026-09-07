from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from sangrep_harness.providers.base import OpenAIProtocolIdV1, ProviderReasoningEffortV1
from sangrep_harness.review import (
    EgressDataClassV1,
    EgressPolicyV1,
    EgressPolicyV2,
    ReviewSemanticError,
)
from sangrep_harness.wire import canonical_json_sha256_v1

_PRIVATE_FIELD_TOKENS = (
    "client",
    "connection",
    "credential",
    "database",
    "handle",
    "path",
    "sqlite",
    "vault",
)


_GENERATED_METADATA_FIELDS = frozenset({"height", "page", "sourceSha256", "width"})


class EgressDenied(ValueError):
    """Sanitized denial raised before any provider transport is accessible."""


@dataclass(frozen=True, slots=True, repr=False)
class AdmittedMediaV1:
    media_id: str
    mime_type: str
    payload: bytes = field(repr=False)
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.media_id.strip() or len(self.media_id.encode()) > 128:
            raise ValueError("media_id must be a bounded identifier.")
        if type(self.mime_type) is not str or "/" not in self.mime_type:
            raise ValueError("mime_type must be a MIME type.")
        if type(self.payload) is not bytes:
            raise TypeError("Media payload must be exact bytes.")
        copied = dict(self.metadata)
        for key, value in copied.items():
            if key not in _GENERATED_METADATA_FIELDS:
                raise ValueError(
                    "Media metadata is outside the approved generated schema; private field "
                    "names are not accepted."
                )
            normalized = key.casefold().replace("_", "").replace("-", "")
            if any(token in normalized for token in _PRIVATE_FIELD_TOKENS):
                raise ValueError("Media metadata contains a private field.")
            if type(value) is not str:
                raise TypeError("Media metadata values must be strings.")
            value_normalized = value.casefold()
            if (
                any(token in value_normalized for token in _PRIVATE_FIELD_TOKENS)
                or value.startswith(("/", "~", "\\"))
                or re.search(r"[A-Za-z]:[\\/]", value) is not None
                or value_normalized.startswith(("sk-", "api-", "bearer "))
            ):
                raise ValueError("Media metadata contains a private value.")
            if key in {"height", "page", "width"} and (
                not value.isascii() or not value.isdigit() or int(value) <= 0
            ):
                raise ValueError("Generated media dimensions and page must be positive integers.")
            if key == "sourceSha256" and (
                len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError("Generated media sourceSha256 must be lowercase SHA-256.")
        object.__setattr__(self, "metadata", MappingProxyType(copied))

    def __repr__(self) -> str:
        return (
            f"AdmittedMediaV1(media_id={self.media_id!r}, "
            f"mime_type={self.mime_type!r}, payload=<redacted>)"
        )

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class SealedReviewRequestV1:
    """Workspace-derived provider bytes bound to exact projection and context identities."""

    evidence_version_id: str
    projection_id: str
    projection_sha256: str
    resolved_context_sha256: str
    request_payload: bytes = field(repr=False)
    admitted_media: tuple[AdmittedMediaV1, ...] = field(repr=False)
    seal_sha256: str

    def __post_init__(self) -> None:
        if type(self.request_payload) is not bytes:
            raise TypeError("Sealed request payload must be exact bytes.")
        if type(self.admitted_media) is not tuple or any(
            type(item) is not AdmittedMediaV1 for item in self.admitted_media
        ):
            raise TypeError("Sealed admitted media must be an immutable tuple.")
        if self.seal_sha256 != self._expected_seal():
            raise ValueError("Sealed request projection identity is invalid.")

    @classmethod
    def create(
        cls,
        *,
        evidence_version_id: str,
        projection_id: str,
        projection_sha256: str,
        resolved_context_sha256: str,
        request_payload: bytes,
        admitted_media: tuple[AdmittedMediaV1, ...],
    ) -> SealedReviewRequestV1:
        return cls(
            evidence_version_id=evidence_version_id,
            projection_id=projection_id,
            projection_sha256=projection_sha256,
            resolved_context_sha256=resolved_context_sha256,
            request_payload=request_payload,
            admitted_media=admitted_media,
            seal_sha256=_sealed_request_digest(
                evidence_version_id=evidence_version_id,
                projection_id=projection_id,
                projection_sha256=projection_sha256,
                resolved_context_sha256=resolved_context_sha256,
                request_payload=request_payload,
                admitted_media=admitted_media,
            ),
        )

    @property
    def request_sha256(self) -> str:
        return hashlib.sha256(self.request_payload).hexdigest()

    def _expected_seal(self) -> str:
        return _sealed_request_digest(
            evidence_version_id=self.evidence_version_id,
            projection_id=self.projection_id,
            projection_sha256=self.projection_sha256,
            resolved_context_sha256=self.resolved_context_sha256,
            request_payload=self.request_payload,
            admitted_media=self.admitted_media,
        )


@dataclass(frozen=True, slots=True, repr=False)
class SealedReviewRequestV2:
    """Workspace-derived Responses bytes with independent protocol/output authority."""

    evidence_version_id: str
    projection_id: str
    projection_sha256: str
    resolved_context_sha256: str
    provider_protocol_id: OpenAIProtocolIdV1
    reasoning_effort: ProviderReasoningEffortV1
    model_max_output_tokens: int
    admitted_max_output_tokens: int
    request_payload: bytes = field(repr=False)
    admitted_media: tuple[AdmittedMediaV1, ...] = field(repr=False)
    seal_sha256: str

    def __post_init__(self) -> None:
        if type(self.request_payload) is not bytes:
            raise TypeError("Sealed request payload must be exact bytes.")
        if type(self.admitted_media) is not tuple or any(
            type(item) is not AdmittedMediaV1 for item in self.admitted_media
        ):
            raise TypeError("Sealed admitted media must be an immutable tuple.")
        if self.provider_protocol_id is not OpenAIProtocolIdV1.RESPONSES_V1:
            raise EgressDenied("provider_protocol_substitution")
        if self.reasoning_effort is not ProviderReasoningEffortV1.MEDIUM:
            raise EgressDenied("provider_protocol_substitution")
        for value, field_name in (
            (self.model_max_output_tokens, "model_max_output_tokens"),
            (self.admitted_max_output_tokens, "admitted_max_output_tokens"),
        ):
            if type(value) is not int or value <= 0 or value > 2**53 - 1:
                raise ValueError(f"{field_name} must be a safe positive integer.")
        if self.seal_sha256 != self._expected_seal():
            raise ValueError("Sealed Responses request projection identity is invalid.")

    @property
    def request_sha256(self) -> str:
        return hashlib.sha256(self.request_payload).hexdigest()

    def _expected_seal(self) -> str:
        return _sealed_request_digest_v2(
            evidence_version_id=self.evidence_version_id,
            projection_id=self.projection_id,
            projection_sha256=self.projection_sha256,
            resolved_context_sha256=self.resolved_context_sha256,
            request_payload=self.request_payload,
            admitted_media=self.admitted_media,
            provider_protocol_id=self.provider_protocol_id,
            reasoning_effort=self.reasoning_effort,
            model_max_output_tokens=self.model_max_output_tokens,
            admitted_max_output_tokens=self.admitted_max_output_tokens,
        )


@dataclass(frozen=True, slots=True, repr=False)
class ProviderEgressRequestV1:
    provider_id: str
    model_id: str
    network_destination: str
    evidence_version_id: str
    request_payload: bytes = field(repr=False)
    admitted_media: tuple[AdmittedMediaV1, ...] = field(repr=False)
    request_sha256: str
    total_bytes: int
    policy_digest: str
    review_authority_digest: str
    structural_grant_digest: str
    citations_required: bool
    provenance_required: bool
    projection_id: str
    projection_sha256: str
    resolved_context_sha256: str
    sealed_request_sha256: str
    route_decision_sha256: str | None = None
    route_policy_sha256: str | None = None
    pricing_authority_sha256: str | None = None
    reasoning_effort: ProviderReasoningEffortV1 | None = None

    def __post_init__(self) -> None:
        if self.reasoning_effort is not None and type(self.reasoning_effort) is not (
            ProviderReasoningEffortV1
        ):
            raise TypeError("Provider egress reasoning effort is invalid.")
        routed = (
            self.route_decision_sha256,
            self.route_policy_sha256,
            self.pricing_authority_sha256,
        )
        if any(value is not None for value in routed):
            if any(value is None for value in routed):
                raise ValueError("Routed provider egress authority must be complete.")
            for value in routed:
                if (
                    type(value) is not str
                    or len(value) != 64
                    or any(character not in "0123456789abcdef" for character in value)
                ):
                    raise ValueError("Routed provider egress authority digest is invalid.")

    def __repr__(self) -> str:
        return (
            "ProviderEgressRequestV1("
            f"provider_id={self.provider_id!r}, model_id={self.model_id!r}, "
            f"request_sha256={self.request_sha256!r}, total_bytes={self.total_bytes}, "
            "payloads=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ProviderEgressRequestV2:
    provider_id: str
    model_id: str
    provider_protocol_id: OpenAIProtocolIdV1
    reasoning_effort: ProviderReasoningEffortV1
    model_max_output_tokens: int
    admitted_max_output_tokens: int
    network_destination: str
    evidence_version_id: str
    request_payload: bytes = field(repr=False)
    admitted_media: tuple[AdmittedMediaV1, ...] = field(repr=False)
    request_sha256: str
    total_bytes: int
    policy_digest: str
    review_authority_digest: str
    structural_grant_digest: str
    citations_required: bool
    provenance_required: bool
    projection_id: str
    projection_sha256: str
    resolved_context_sha256: str
    sealed_request_sha256: str
    route_decision_sha256: str
    route_policy_sha256: str
    pricing_authority_sha256: str

    def __post_init__(self) -> None:
        if self.provider_id != "openai" or self.provider_protocol_id is not (
            OpenAIProtocolIdV1.RESPONSES_V1
        ):
            raise EgressDenied("provider_protocol_substitution")
        if self.reasoning_effort is not ProviderReasoningEffortV1.MEDIUM:
            raise EgressDenied("provider_protocol_substitution")
        for token_limit, field_name in (
            (self.model_max_output_tokens, "model_max_output_tokens"),
            (self.admitted_max_output_tokens, "admitted_max_output_tokens"),
        ):
            if type(token_limit) is not int or token_limit <= 0 or token_limit > 2**53 - 1:
                raise ValueError(f"{field_name} must be a safe positive integer.")
        for digest, field_name in (
            (self.request_sha256, "request_sha256"),
            (self.policy_digest, "policy_digest"),
            (self.review_authority_digest, "review_authority_digest"),
            (self.structural_grant_digest, "structural_grant_digest"),
            (self.projection_sha256, "projection_sha256"),
            (self.resolved_context_sha256, "resolved_context_sha256"),
            (self.sealed_request_sha256, "sealed_request_sha256"),
            (self.route_decision_sha256, "route_decision_sha256"),
            (self.route_policy_sha256, "route_policy_sha256"),
            (self.pricing_authority_sha256, "pricing_authority_sha256"),
        ):
            if (
                type(digest) is not str
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise ValueError(f"{field_name} must be lowercase SHA-256.")

    def __repr__(self) -> str:
        return (
            "ProviderEgressRequestV2("
            f"provider_id={self.provider_id!r}, model_id={self.model_id!r}, "
            f"provider_protocol_id={self.provider_protocol_id.value!r}, "
            f"request_sha256={self.request_sha256!r}, total_bytes={self.total_bytes}, "
            "payloads=<redacted>)"
        )


def seal_review_request_v2(
    *,
    evidence_version_id: str,
    projection_id: str,
    projection_sha256: str,
    resolved_context_sha256: str,
    request_payload: bytes,
    admitted_media: tuple[AdmittedMediaV1, ...],
    provider_protocol_id: OpenAIProtocolIdV1,
    reasoning_effort: ProviderReasoningEffortV1,
    model_max_output_tokens: int,
    admitted_max_output_tokens: int,
) -> SealedReviewRequestV2:
    """Seal exact Responses authority without consulting policy defaults."""

    seal = _sealed_request_digest_v2(
        evidence_version_id=evidence_version_id,
        projection_id=projection_id,
        projection_sha256=projection_sha256,
        resolved_context_sha256=resolved_context_sha256,
        request_payload=request_payload,
        admitted_media=admitted_media,
        provider_protocol_id=provider_protocol_id,
        reasoning_effort=reasoning_effort,
        model_max_output_tokens=model_max_output_tokens,
        admitted_max_output_tokens=admitted_max_output_tokens,
    )
    return SealedReviewRequestV2(
        evidence_version_id=evidence_version_id,
        projection_id=projection_id,
        projection_sha256=projection_sha256,
        resolved_context_sha256=resolved_context_sha256,
        provider_protocol_id=provider_protocol_id,
        reasoning_effort=reasoning_effort,
        model_max_output_tokens=model_max_output_tokens,
        admitted_max_output_tokens=admitted_max_output_tokens,
        request_payload=request_payload,
        admitted_media=admitted_media,
        seal_sha256=seal,
    )


def prepare_provider_egress(
    *,
    policy: EgressPolicyV1,
    provider_id: str,
    model_id: str,
    network_destination: str,
    sealed_request: SealedReviewRequestV1 | None = None,
    evidence_version_id: str | None = None,
    request_payload: bytes | None = None,
    admitted_media: tuple[AdmittedMediaV1, ...] | None = None,
    review_authority_digest: str,
    structural_grant_digest: str,
    citations_required: bool,
    provenance_required: bool,
    reasoning_effort: ProviderReasoningEffortV1 | None = None,
) -> ProviderEgressRequestV1:
    """Validate exact destination, data classes, media identities, and total bytes."""

    if type(policy) is not EgressPolicyV1:
        raise TypeError("policy must be an EgressPolicyV1.")
    if type(sealed_request) is not SealedReviewRequestV1:
        del evidence_version_id, request_payload, admitted_media
        raise EgressDenied("Provider egress requires a sealed request projection.")
    for digest, field_name in (
        (review_authority_digest, "review_authority_digest"),
        (structural_grant_digest, "structural_grant_digest"),
    ):
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError(f"{field_name} must be lowercase SHA-256.")
    if citations_required is not True or provenance_required is not True:
        raise EgressDenied("Provider egress requires citations and truthful provenance.")
    request_payload = sealed_request.request_payload
    admitted_media = sealed_request.admitted_media
    evidence_version_id = sealed_request.evidence_version_id
    if admitted_media:
        raise EgressDenied(
            "Provider media requires an authoritative media artifact binding; this workspace "
            "schema cannot prove one."
        )
    if len({item.media_id for item in admitted_media}) != len(admitted_media):
        raise EgressDenied("Provider request repeats an admitted media identity.")
    if provider_id != policy.provider_id or model_id != policy.model_id:
        raise EgressDenied("Provider request is outside the approved egress policy.")
    total_bytes = len(request_payload) + sum(len(item.payload) for item in admitted_media)
    if total_bytes > policy.max_total_bytes:
        raise EgressDenied("Provider request exceeds the approved egress byte budget.")
    try:
        policy.authorize(
            data_class=EgressDataClassV1.MODEL_PROJECTION,
            network_destination=network_destination,
            evidence_version_id=evidence_version_id,
            media_id=None,
            byte_count=len(request_payload),
        )
        for media in admitted_media:
            policy.authorize(
                data_class=EgressDataClassV1.ADMITTED_MEDIA,
                network_destination=network_destination,
                evidence_version_id=evidence_version_id,
                media_id=media.media_id,
                byte_count=len(media.payload),
            )
    except ReviewSemanticError:
        raise EgressDenied("Provider request is outside the approved egress policy.") from None
    return ProviderEgressRequestV1(
        provider_id=provider_id,
        model_id=model_id,
        network_destination=network_destination,
        evidence_version_id=evidence_version_id,
        request_payload=request_payload,
        admitted_media=admitted_media,
        request_sha256=hashlib.sha256(request_payload).hexdigest(),
        total_bytes=total_bytes,
        policy_digest=policy.digest,
        review_authority_digest=review_authority_digest,
        structural_grant_digest=structural_grant_digest,
        citations_required=citations_required,
        provenance_required=provenance_required,
        projection_id=sealed_request.projection_id,
        projection_sha256=sealed_request.projection_sha256,
        resolved_context_sha256=sealed_request.resolved_context_sha256,
        sealed_request_sha256=sealed_request.seal_sha256,
        route_decision_sha256=policy.route_decision_sha256,
        route_policy_sha256=policy.route_policy_sha256,
        pricing_authority_sha256=policy.pricing_authority_sha256,
        reasoning_effort=reasoning_effort,
    )


def prepare_provider_egress_v2(
    *,
    policy: EgressPolicyV2,
    provider_id: str,
    model_id: str,
    network_destination: str,
    sealed_request: SealedReviewRequestV2,
    review_authority_digest: str,
    structural_grant_digest: str,
    citations_required: bool,
    provenance_required: bool,
) -> ProviderEgressRequestV2:
    """Require independently sealed Responses authority before egress construction."""

    if type(policy) is not EgressPolicyV2:
        raise TypeError("policy must be an EgressPolicyV2.")
    if type(sealed_request) is not SealedReviewRequestV2:
        raise TypeError("sealed_request must be a SealedReviewRequestV2.")
    if (
        policy.provider_protocol_id is not sealed_request.provider_protocol_id
        or policy.reasoning_effort is not sealed_request.reasoning_effort
    ):
        raise EgressDenied("provider_protocol_substitution")
    if (
        policy.model_max_output_tokens != sealed_request.model_max_output_tokens
        or policy.admitted_max_output_tokens != sealed_request.admitted_max_output_tokens
    ):
        raise EgressDenied("Provider output authority differs from its immutable egress policy.")
    for digest, field_name in (
        (review_authority_digest, "review_authority_digest"),
        (structural_grant_digest, "structural_grant_digest"),
    ):
        if (
            type(digest) is not str
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError(f"{field_name} must be lowercase SHA-256.")
    if citations_required is not True or provenance_required is not True:
        raise EgressDenied("Provider egress requires citations and truthful provenance.")
    if sealed_request.admitted_media:
        raise EgressDenied(
            "Provider media requires an authoritative media artifact binding; this workspace "
            "schema cannot prove one."
        )
    if provider_id != policy.provider_id or model_id != policy.model_id:
        raise EgressDenied("Provider request is outside the approved egress policy.")
    total_bytes = len(sealed_request.request_payload)
    if total_bytes > policy.max_total_bytes:
        raise EgressDenied("Provider request exceeds the approved egress byte budget.")
    try:
        policy.authorize(
            data_class=EgressDataClassV1.MODEL_PROJECTION,
            network_destination=network_destination,
            evidence_version_id=sealed_request.evidence_version_id,
            media_id=None,
            byte_count=total_bytes,
        )
    except ReviewSemanticError:
        raise EgressDenied("Provider request is outside the approved egress policy.") from None
    return ProviderEgressRequestV2(
        provider_id=provider_id,
        model_id=model_id,
        provider_protocol_id=policy.provider_protocol_id,
        reasoning_effort=policy.reasoning_effort,
        model_max_output_tokens=policy.model_max_output_tokens,
        admitted_max_output_tokens=policy.admitted_max_output_tokens,
        network_destination=network_destination,
        evidence_version_id=sealed_request.evidence_version_id,
        request_payload=sealed_request.request_payload,
        admitted_media=sealed_request.admitted_media,
        request_sha256=sealed_request.request_sha256,
        total_bytes=total_bytes,
        policy_digest=policy.digest,
        review_authority_digest=review_authority_digest,
        structural_grant_digest=structural_grant_digest,
        citations_required=citations_required,
        provenance_required=provenance_required,
        projection_id=sealed_request.projection_id,
        projection_sha256=sealed_request.projection_sha256,
        resolved_context_sha256=sealed_request.resolved_context_sha256,
        sealed_request_sha256=sealed_request.seal_sha256,
        route_decision_sha256=policy.route_decision_sha256,
        route_policy_sha256=policy.route_policy_sha256,
        pricing_authority_sha256=policy.pricing_authority_sha256,
    )


def _sealed_request_digest(
    *,
    evidence_version_id: str,
    projection_id: str,
    projection_sha256: str,
    resolved_context_sha256: str,
    request_payload: bytes,
    admitted_media: tuple[AdmittedMediaV1, ...],
) -> str:
    return canonical_json_sha256_v1(
        {
            "admittedMedia": [
                {
                    "mediaId": media.media_id,
                    "metadata": dict(media.metadata),
                    "mimeType": media.mime_type,
                    "payloadSha256": media.payload_sha256,
                    "payloadSize": len(media.payload),
                }
                for media in admitted_media
            ],
            "evidenceVersionId": evidence_version_id,
            "projectionId": projection_id,
            "projectionSha256": projection_sha256,
            "requestSha256": hashlib.sha256(request_payload).hexdigest(),
            "resolvedContextSha256": resolved_context_sha256,
        }
    )


def _sealed_request_digest_v2(
    *,
    evidence_version_id: str,
    projection_id: str,
    projection_sha256: str,
    resolved_context_sha256: str,
    request_payload: bytes,
    admitted_media: tuple[AdmittedMediaV1, ...],
    provider_protocol_id: OpenAIProtocolIdV1,
    reasoning_effort: ProviderReasoningEffortV1,
    model_max_output_tokens: int,
    admitted_max_output_tokens: int,
) -> str:
    return canonical_json_sha256_v1(
        {
            "admittedMedia": [
                {
                    "mediaId": media.media_id,
                    "metadata": dict(media.metadata),
                    "mimeType": media.mime_type,
                    "payloadSha256": media.payload_sha256,
                    "payloadSize": len(media.payload),
                }
                for media in admitted_media
            ],
            "admittedMaxOutputTokens": admitted_max_output_tokens,
            "evidenceVersionId": evidence_version_id,
            "modelMaxOutputTokens": model_max_output_tokens,
            "projectionId": projection_id,
            "projectionSha256": projection_sha256,
            "providerProtocolId": provider_protocol_id.value,
            "reasoningEffort": reasoning_effort.value,
            "requestSha256": hashlib.sha256(request_payload).hexdigest(),
            "resolvedContextSha256": resolved_context_sha256,
        }
    )
