from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from sangrep_harness.providers.base import OpenAIProtocolIdV1, ProviderReasoningEffortV1
from sangrep_harness.providers.egress import (
    AdmittedMediaV1,
    EgressDenied,
    ProviderEgressRequestV2,
    SealedReviewRequestV1,
    SealedReviewRequestV2,
    prepare_provider_egress,
    prepare_provider_egress_v2,
    seal_review_request_v2,
)
from sangrep_harness.review import EgressDataClassV1, EgressPolicyV1, EgressPolicyV2
from sangrep_harness.wire import canonical_json_bytes_v1

_AUTHORITY_ARGUMENTS = {
    "review_authority_digest": "a" * 64,
    "structural_grant_digest": "b" * 64,
    "citations_required": True,
    "provenance_required": True,
}


def _policy(*, max_total_bytes: int = 4096) -> EgressPolicyV1:
    return EgressPolicyV1(
        policy_id="egress_01",
        provider_id="provider_01",
        model_id="model_01",
        network_destination="provider.example",
        allowed_data_classes=(
            EgressDataClassV1.MODEL_PROJECTION,
            EgressDataClassV1.ADMITTED_MEDIA,
        ),
        evidence_version_ids=("evidence_01",),
        media_ids=("media_01",),
        max_total_bytes=max_total_bytes,
    )


def _sealed(
    request_payload: bytes,
    admitted_media: tuple[AdmittedMediaV1, ...],
    *,
    evidence_version_id: str = "evidence_01",
) -> SealedReviewRequestV1:
    return SealedReviewRequestV1.create(
        evidence_version_id=evidence_version_id,
        projection_id="projection_01",
        projection_sha256="c" * 64,
        resolved_context_sha256="d" * 64,
        request_payload=request_payload,
        admitted_media=admitted_media,
    )


def _policy_v2(
    *,
    model_max_output_tokens: int = 128_000,
    admitted_max_output_tokens: int = 4_096,
) -> EgressPolicyV2:
    return EgressPolicyV2(
        policy_id="egress-route-" + "1" * 32,
        provider_id="openai",
        model_id="gpt-5.6-luna",
        provider_protocol_id=OpenAIProtocolIdV1.RESPONSES_V1,
        reasoning_effort=ProviderReasoningEffortV1.MEDIUM,
        network_destination="api.openai.com",
        allowed_data_classes=(EgressDataClassV1.MODEL_PROJECTION,),
        evidence_version_ids=("evidence_01",),
        media_ids=(),
        max_total_bytes=67_108_864,
        model_max_output_tokens=model_max_output_tokens,
        admitted_max_output_tokens=admitted_max_output_tokens,
        route_decision_sha256="1" * 64,
        route_policy_sha256="2" * 64,
        pricing_authority_sha256="3" * 64,
    )


def _sealed_v2(
    *,
    model_max_output_tokens: int = 128_000,
    admitted_max_output_tokens: int = 4_096,
) -> SealedReviewRequestV2:
    return seal_review_request_v2(
        evidence_version_id="evidence_01",
        projection_id="projection_01",
        projection_sha256="c" * 64,
        resolved_context_sha256="d" * 64,
        request_payload=b'{"schemaVersion":2,"kind":"sealedAgentTurnRequest"}',
        admitted_media=(),
        provider_protocol_id=OpenAIProtocolIdV1.RESPONSES_V1,
        reasoning_effort=ProviderReasoningEffortV1.MEDIUM,
        model_max_output_tokens=model_max_output_tokens,
        admitted_max_output_tokens=admitted_max_output_tokens,
    )


def test_legacy_egress_policy_serialization_bytes_remain_exact() -> None:
    assert canonical_json_bytes_v1(_policy().to_json_obj()) == (
        b'{"allowedDataClasses":["model_projection","admitted_media"],'
        b'"contractId":"sangrep.harness.review.v1",'
        b'"evidenceVersionIds":["evidence_01"],"kind":"egressPolicy",'
        b'"maxTotalBytes":4096,"mediaIds":["media_01"],"modelId":"model_01",'
        b'"networkDestination":"provider.example","policyId":"egress_01",'
        b'"providerId":"provider_01","schemaVersion":1}'
    )


def test_egress_contains_only_approved_projection_and_admitted_media() -> None:
    request_payload = b'{"question":"Which control is approved?"}'

    request = prepare_provider_egress(
        policy=_policy(),
        provider_id="provider_01",
        model_id="model_01",
        network_destination="provider.example",
        sealed_request=_sealed(request_payload, ()),
        **_AUTHORITY_ARGUMENTS,
    )

    assert request.request_payload == request_payload
    assert request.admitted_media == ()
    assert request.request_sha256 == hashlib.sha256(request_payload).hexdigest()
    assert request.total_bytes == len(request_payload)


@pytest.mark.parametrize(
    "missing_field",
    ("route_decision_sha256", "route_policy_sha256", "pricing_authority_sha256"),
)
def test_provider_egress_rejects_incomplete_routed_identity(missing_field: str) -> None:
    policy = replace(
        _policy(),
        route_decision_sha256="1" * 64,
        route_policy_sha256="2" * 64,
        pricing_authority_sha256="3" * 64,
    )
    request = prepare_provider_egress(
        policy=policy,
        provider_id="provider_01",
        model_id="model_01",
        network_destination="provider.example",
        sealed_request=_sealed(b"request", ()),
        **_AUTHORITY_ARGUMENTS,
    )

    with pytest.raises(ValueError, match="Routed provider egress authority must be complete"):
        replace(request, **{missing_field: None})


def test_non_empty_sealed_media_is_rejected_without_an_authoritative_binding() -> None:
    media = AdmittedMediaV1(
        media_id="media_01",
        mime_type="image/png",
        payload=b"apparently-approved-image-bytes",
    )

    with pytest.raises(EgressDenied, match="authoritative media artifact binding"):
        prepare_provider_egress(
            policy=_policy(),
            provider_id="provider_01",
            model_id="model_01",
            network_destination="provider.example",
            sealed_request=_sealed(b"request", (media,)),
            **_AUTHORITY_ARGUMENTS,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_id", "other_provider"),
        ("model_id", "other_model"),
        ("network_destination", "other.example"),
        ("evidence_version_id", "evidence_02"),
    ],
)
def test_unauthorized_egress_is_rejected_before_transport(field: str, value: str) -> None:
    arguments = {
        "policy": _policy(),
        "provider_id": "provider_01",
        "model_id": "model_01",
        "network_destination": "provider.example",
        "sealed_request": _sealed(b"request", ()),
        **_AUTHORITY_ARGUMENTS,
    }
    if field == "evidence_version_id":
        arguments["sealed_request"] = _sealed(b"request", (), evidence_version_id=value)
    else:
        arguments[field] = value

    with pytest.raises(EgressDenied, match="outside the approved egress policy"):
        prepare_provider_egress(**arguments)


def test_egress_budget_counts_raw_request_bytes() -> None:
    with pytest.raises(EgressDenied, match="byte budget"):
        prepare_provider_egress(
            policy=_policy(max_total_bytes=10),
            provider_id="provider_01",
            model_id="model_01",
            network_destination="provider.example",
            sealed_request=_sealed(b"12345678901", ()),
            **_AUTHORITY_ARGUMENTS,
        )


def test_private_storage_and_credential_fields_cannot_enter_egress_metadata() -> None:
    with pytest.raises(ValueError, match="private field"):
        AdmittedMediaV1(
            media_id="media_01",
            mime_type="image/png",
            payload=b"image",
            metadata={"databaseHandle": "db-secret"},
        )


@pytest.mark.parametrize(
    "metadata",
    [
        {"label": "sk-review-secret-value"},
        {"label": "/restricted/synthetic.txt"},
        {"label": "sqlite-handle-42"},
    ],
    ids=["credential-value", "raw-path-value", "internal-handle-value"],
)
def test_safe_looking_metadata_key_cannot_carry_private_value(metadata: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="approved generated schema|private"):
        AdmittedMediaV1(
            media_id="media_01",
            mime_type="image/png",
            payload=b"image",
            metadata=metadata,
        )


def test_unsealed_caller_bytes_cannot_be_declared_a_model_projection() -> None:
    with pytest.raises((TypeError, EgressDenied), match="sealed.*projection|sealed request"):
        prepare_provider_egress(
            policy=_policy(),
            provider_id="provider_01",
            model_id="model_01",
            network_destination="provider.example",
            evidence_version_id="evidence_01",
            request_payload=b"arbitrary-caller-bytes-from-private-vault",
            admitted_media=(
                AdmittedMediaV1(
                    media_id="media_01",
                    mime_type="image/png",
                    payload=b"arbitrary-caller-media",
                ),
            ),
            **_AUTHORITY_ARGUMENTS,
        )


def test_responses_egress_requires_exact_independent_route_and_ceiling_authority() -> None:
    policy = _policy_v2()
    sealed = _sealed_v2()

    request = prepare_provider_egress_v2(
        policy=policy,
        provider_id="openai",
        model_id="gpt-5.6-luna",
        network_destination="api.openai.com",
        sealed_request=sealed,
        **_AUTHORITY_ARGUMENTS,
    )

    assert type(request) is ProviderEgressRequestV2
    assert request.provider_protocol_id is OpenAIProtocolIdV1.RESPONSES_V1
    assert request.reasoning_effort is ProviderReasoningEffortV1.MEDIUM
    assert request.model_max_output_tokens == 128_000
    assert request.admitted_max_output_tokens == 4_096
    assert request.route_decision_sha256 == "1" * 64
    assert request.policy_digest == policy.digest
    assert request.sealed_request_sha256 == sealed.seal_sha256

    changed_authorities = (
        (_policy_v2(model_max_output_tokens=127_999), sealed),
        (policy, _sealed_v2(model_max_output_tokens=127_999)),
        (_policy_v2(admitted_max_output_tokens=4_095), sealed),
        (policy, _sealed_v2(admitted_max_output_tokens=4_095)),
    )
    for changed_policy, changed_seal in changed_authorities:
        with pytest.raises(
            EgressDenied,
            match=r"Provider output authority differs from its immutable egress policy\.",
        ):
            prepare_provider_egress_v2(
                policy=changed_policy,
                provider_id="openai",
                model_id="gpt-5.6-luna",
                network_destination="api.openai.com",
                sealed_request=changed_seal,
                **_AUTHORITY_ARGUMENTS,
            )


def test_responses_egress_rejects_version_cross_use() -> None:
    with pytest.raises(TypeError, match="EgressPolicyV2"):
        prepare_provider_egress_v2(
            policy=_policy(),  # type: ignore[arg-type]
            provider_id="provider_01",
            model_id="model_01",
            network_destination="provider.example",
            sealed_request=_sealed_v2(),
            **_AUTHORITY_ARGUMENTS,
        )
    with pytest.raises((TypeError, EgressDenied), match="sealed|V2"):
        prepare_provider_egress_v2(
            policy=_policy_v2(),
            provider_id="openai",
            model_id="gpt-5.6-luna",
            network_destination="api.openai.com",
            sealed_request=_sealed(b"request", ()),  # type: ignore[arg-type]
            **_AUTHORITY_ARGUMENTS,
        )
