from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from sangrep_harness.review import ContextLayerV1, ContextRevisionRefV1, EvidenceRootRefV1
from sangrep_harness.wire import JsonValue, canonical_json_sha256_v1

CONTEXT_POLICY_VERSION_V1 = "context-policy-v1"


LOCAL_EVALUATOR_IDENTITY_PROFILE_V1 = "local-evaluator-identity-v1"


@dataclass(frozen=True, slots=True)
class ContextRevisionV1:
    """One append-only revision in one of the three persistent context layers."""

    layer: ContextLayerV1
    revision_id: str
    predecessor_id: str | None
    content: str
    digest: str
    actor_id: str
    policy_version: str = CONTEXT_POLICY_VERSION_V1

    def __post_init__(self) -> None:
        if not isinstance(self.layer, ContextLayerV1):
            raise ValueError("Context must use exactly the three persistent context layers.")
        if not self.content or len(self.content.encode("utf-8")) > 1_048_576:
            raise ValueError("Context content must be non-empty and bounded.")
        ContextRevisionRefV1(self.layer, self.revision_id, self.digest)
        if self.predecessor_id is not None:
            _require_identifier(self.predecessor_id, "predecessor_id")
        _require_identifier(self.actor_id, "actor_id")
        _require_identifier(self.policy_version, "policy_version")
        if self.digest != self._expected_digest():
            raise ValueError("Context revision digest does not match its immutable content.")

    @classmethod
    def create(
        cls,
        *,
        layer: ContextLayerV1 | str,
        revision_id: str,
        predecessor_id: str | None,
        content: str,
        actor_id: str,
        policy_version: str = CONTEXT_POLICY_VERSION_V1,
    ) -> ContextRevisionV1:
        try:
            normalized_layer = ContextLayerV1(layer)
        except ValueError:
            raise ValueError(
                "Context must use exactly the three persistent context layers."
            ) from None
        payload = _context_digest_payload(
            layer=normalized_layer,
            revision_id=revision_id,
            predecessor_id=predecessor_id,
            content=content,
            actor_id=actor_id,
            policy_version=policy_version,
        )
        return cls(
            layer=normalized_layer,
            revision_id=revision_id,
            predecessor_id=predecessor_id,
            content=content,
            digest=canonical_json_sha256_v1(payload),
            actor_id=actor_id,
            policy_version=policy_version,
        )

    def _expected_digest(self) -> str:
        return canonical_json_sha256_v1(
            _context_digest_payload(
                layer=self.layer,
                revision_id=self.revision_id,
                predecessor_id=self.predecessor_id,
                content=self.content,
                actor_id=self.actor_id,
                policy_version=self.policy_version,
            )
        )

    def to_ref(self) -> ContextRevisionRefV1:
        return ContextRevisionRefV1(self.layer, self.revision_id, self.digest)


@dataclass(frozen=True, slots=True)
class LocalEvaluatorIdentityV1:
    """Stable machine-local evaluator identity, separate from any remote account."""

    identity_id: str
    profile_version: str
    digest: str

    def __post_init__(self) -> None:
        _require_identifier(self.identity_id, "identity_id")
        _require_identifier(self.profile_version, "profile_version")
        ContextRevisionRefV1(
            ContextLayerV1.APPLICATION,
            self.identity_id,
            self.digest,
        )
        if self.digest != _local_evaluator_digest(self.profile_version):
            raise ValueError("Local evaluator identity digest is invalid.")

    @classmethod
    def create(cls, *, profile_version: str) -> LocalEvaluatorIdentityV1:
        _require_identifier(profile_version, "profile_version")
        digest = _local_evaluator_digest(profile_version)
        return cls(
            identity_id=f"local-evaluator-{digest[:32]}",
            profile_version=profile_version,
            digest=digest,
        )

    @property
    def descriptor(self) -> Mapping[str, str]:
        return {
            "identityProfile": LOCAL_EVALUATOR_IDENTITY_PROFILE_V1,
            "profileVersion": self.profile_version,
        }


@dataclass(frozen=True, slots=True)
class SessionStateV1:
    """Transient request state whose identity, not mutable content tier, is durable."""

    request: str
    selected_roots: tuple[EvidenceRootRefV1, ...]
    prior_turn_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.request.strip():
            raise ValueError("Session request must not be blank.")
        if type(self.selected_roots) is not tuple or not self.selected_roots:
            raise ValueError("Session selected_roots must be a non-empty tuple.")
        if any(type(root) is not EvidenceRootRefV1 for root in self.selected_roots):
            raise TypeError("Session selected_roots contains an invalid root.")
        if len(self.selected_roots) != len(set(self.selected_roots)):
            raise ValueError("Session selected_roots contains a duplicate root.")
        if type(self.prior_turn_ids) is not tuple:
            raise TypeError("Session prior_turn_ids must be a tuple.")
        for turn_id in self.prior_turn_ids:
            _require_identifier(turn_id, "prior_turn_id")
        if len(self.prior_turn_ids) != len(set(self.prior_turn_ids)):
            raise ValueError("Session prior_turn_ids contains a duplicate ID.")

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(
            {
                "priorTurnIds": list(self.prior_turn_ids),
                "request": self.request,
                "selectedRoots": [root.to_json_obj() for root in self.selected_roots],
            }
        )


def _context_digest_payload(
    *,
    layer: ContextLayerV1,
    revision_id: str,
    predecessor_id: str | None,
    content: str,
    actor_id: str,
    policy_version: str,
) -> dict[str, JsonValue]:
    return {
        "actorId": actor_id,
        "content": content,
        "layer": layer.value,
        "policyVersion": policy_version,
        "predecessorId": predecessor_id,
        "revisionId": revision_id,
    }


def _local_evaluator_digest(profile_version: str) -> str:
    return canonical_json_sha256_v1(
        {
            "identityProfile": LOCAL_EVALUATOR_IDENTITY_PROFILE_V1,
            "profileVersion": profile_version,
        }
    )


def _require_identifier(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > 128
        or not value[0].isalnum()
        or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
            for character in value
        )
    ):
        raise ValueError(f"{field_name} must be a bounded opaque identifier.")
    return value
