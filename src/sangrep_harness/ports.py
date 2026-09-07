"""Trusted immutable evidence interfaces and sanitized adapter-shape refusals.

Shape checks do not grant authority or validate evidence identity/containment.
Applications must inject independently validated immutable adapters through code.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, Protocol, TypeVar, cast, runtime_checkable

from sangrep_harness.review import EvidenceBindingV1, StructuralGrantV1
from sangrep_harness.wire import JsonValue


class EvidencePortError(ValueError):
    """An evidence adapter does not implement its declared public interface."""

    code = "invalid_evidence_adapter"

    def __init__(self) -> None:
        super().__init__("Evidence adapter is incomplete or returned invalid interface values.")


@runtime_checkable
class EvidenceLabelV1(Protocol):
    @property
    def value(self) -> str: ...


@runtime_checkable
class EvidenceNodeV1(Protocol):
    @property
    def stable_id(self) -> str: ...
    @property
    def occurrence_id(self) -> str: ...
    @property
    def parent_stable_id(self) -> str | None: ...
    @property
    def parent_occurrence_id(self) -> str | None: ...
    @property
    def kind(self) -> EvidenceLabelV1: ...
    @property
    def ordinal(self) -> int: ...
    @property
    def title_or_none(self) -> str | None: ...
    @property
    def text_or_none(self) -> str | None: ...
    @property
    def coverage(self) -> EvidenceLabelV1: ...
    @property
    def limitation_code_or_none(self) -> str | None: ...


@runtime_checkable
class ProjectedEvidenceNodeV1(Protocol):
    @property
    def projection_revision_id(self) -> str: ...
    @property
    def structure_revision_id(self) -> str: ...
    @property
    def anchor_id(self) -> str: ...
    @property
    def occurrence_id(self) -> str: ...
    @property
    def payload_kind(self) -> str: ...
    @property
    def payload(self) -> str: ...
    @property
    def inclusion_state(self) -> str: ...
    @property
    def citable_state(self) -> str: ...
    @property
    def limitation_codes(self) -> tuple[str, ...]: ...
    @property
    def projected_payload_sha256(self) -> str: ...


@runtime_checkable
class EvidenceRevisionV1(Protocol):
    @property
    def evidence_version_id(self) -> str: ...
    @property
    def structure_revision_id(self) -> str: ...
    @property
    def source_sha256(self) -> str: ...
    @property
    def semantic_ir_sha256(self) -> str: ...
    @property
    def canonicalization_profile_id(self) -> str: ...
    @property
    def canonicalization_profile_sha256(self) -> str: ...
    @property
    def root_stable_id(self) -> str: ...
    @property
    def nodes(self) -> tuple[EvidenceNodeV1, ...]: ...
    @property
    def digest(self) -> str: ...

    def to_structure_revision_json(self) -> dict[str, JsonValue]: ...


@runtime_checkable
class EvidenceProjectionRevisionV1(Protocol):
    @property
    def projection_revision_id(self) -> str: ...
    @property
    def structure_revision_id(self) -> str: ...
    @property
    def projection_kind(self) -> str: ...
    @property
    def projection_profile_id(self) -> str: ...
    @property
    def projection_profile_version(self) -> str: ...
    @property
    def projection_profile_sha256(self) -> str: ...
    @property
    def payload_sha256(self) -> str: ...
    @property
    def nodes(self) -> tuple[ProjectedEvidenceNodeV1, ...]: ...

    def to_projection_revision_json(self) -> dict[str, JsonValue]: ...


@runtime_checkable
class ReviewEvidenceHeadV1(Protocol):
    """Full immutable surface consumed by grant, citation, tool and loop code.

    Methods must refuse stale, ambiguous and out-of-scope evidence. Implementations
    must validate the entire identity chain before entering this interface. These
    declarations and their shape checks do not establish provenance or authority.
    """

    @property
    def evidence_binding(self) -> EvidenceBindingV1: ...
    @property
    def canonical_revision(self) -> EvidenceRevisionV1: ...
    @property
    def projection_revision(self) -> EvidenceProjectionRevisionV1: ...

    @property
    def digest(self) -> str: ...
    @property
    def source_format(self) -> str: ...
    def require_grant(self, grant: StructuralGrantV1) -> None: ...
    def canonical_node(self, anchor_id: str, occurrence_id: str) -> EvidenceNodeV1 | None: ...
    def projected_node(
        self, anchor_id: str, occurrence_id: str
    ) -> ProjectedEvidenceNodeV1 | None: ...
    def root_for_anchor(
        self, grant: StructuralGrantV1, anchor_id: str, occurrence_id: str
    ) -> str | None: ...
    def require_stable_ids_in_grant(
        self, grant: StructuralGrantV1, stable_ids: tuple[str, ...]
    ) -> None: ...
    def granted_nodes(self, grant: StructuralGrantV1) -> tuple[EvidenceNodeV1, ...]: ...
    def descendants_or_self(
        self, grant: StructuralGrantV1, stable_id: str
    ) -> tuple[EvidenceNodeV1, ...]: ...
    def depth_from(self, node: EvidenceNodeV1, root: EvidenceNodeV1) -> int: ...
    def _unique_node_for_stable_id(self, stable_id: str) -> EvidenceNodeV1: ...
    def _is_descendant_or_self(self, node: EvidenceNodeV1, root: EvidenceNodeV1) -> bool: ...


def _strings(value: object, names: tuple[str, ...], *, optional: bool = False) -> None:
    for name in names:
        field = getattr(value, name)
        if optional and field is None:
            continue
        if type(field) is not str:
            raise EvidencePortError()
        if (name.endswith("sha256") or name == "digest") and re.fullmatch(
            r"[0-9a-f]{64}", field
        ) is None:
            raise EvidencePortError()


def _callables(value: object, names: tuple[str, ...]) -> None:
    if any(not callable(getattr(value, name)) for name in names):
        raise EvidencePortError()


def require_evidence_head_v1(value: object) -> ReviewEvidenceHeadV1:
    """Refuse missing/invalid members without including adapter data in errors."""
    try:
        if (
            not isinstance(value, ReviewEvidenceHeadV1)
            or type(value.evidence_binding) is not EvidenceBindingV1
        ):
            raise EvidencePortError()
        _strings(value, ("digest", "source_format"))
        _callables(
            value,
            (
                "require_grant",
                "canonical_node",
                "projected_node",
                "root_for_anchor",
                "require_stable_ids_in_grant",
                "granted_nodes",
                "descendants_or_self",
                "depth_from",
                "_unique_node_for_stable_id",
                "_is_descendant_or_self",
            ),
        )
        canonical, projection = value.canonical_revision, value.projection_revision
        if not isinstance(canonical, EvidenceRevisionV1) or not isinstance(
            projection, EvidenceProjectionRevisionV1
        ):
            raise EvidencePortError()
        _strings(
            canonical,
            (
                "evidence_version_id",
                "structure_revision_id",
                "source_sha256",
                "semantic_ir_sha256",
                "canonicalization_profile_id",
                "canonicalization_profile_sha256",
                "root_stable_id",
                "digest",
            ),
        )
        _strings(
            projection,
            (
                "projection_revision_id",
                "structure_revision_id",
                "projection_kind",
                "projection_profile_id",
                "projection_profile_version",
                "projection_profile_sha256",
                "payload_sha256",
            ),
        )
        _callables(canonical, ("to_structure_revision_json",))
        _callables(projection, ("to_projection_revision_json",))
        if type(canonical.nodes) is not tuple or type(projection.nodes) is not tuple:
            raise EvidencePortError()
        for node in canonical.nodes:
            if (
                not isinstance(node, EvidenceNodeV1)
                or type(node.ordinal) is not int
                or node.ordinal < 0
            ):
                raise EvidencePortError()
            _strings(node, ("stable_id", "occurrence_id"))
            _strings(
                node,
                (
                    "parent_stable_id",
                    "parent_occurrence_id",
                    "title_or_none",
                    "text_or_none",
                    "limitation_code_or_none",
                ),
                optional=True,
            )
            _strings(node.kind, ("value",))
            _strings(node.coverage, ("value",))
        for projected in projection.nodes:
            if not isinstance(projected, ProjectedEvidenceNodeV1):
                raise EvidencePortError()
            _strings(
                projected,
                (
                    "projection_revision_id",
                    "structure_revision_id",
                    "anchor_id",
                    "occurrence_id",
                    "payload_kind",
                    "payload",
                    "inclusion_state",
                    "citable_state",
                    "projected_payload_sha256",
                ),
            )
            if (
                projected.citable_state not in {"citable", "limited", "notCitable"}
                or type(projected.limitation_codes) is not tuple
                or any(type(code) is not str for code in projected.limitation_codes)
            ):
                raise EvidencePortError()
        return value
    except (AttributeError, TypeError):
        raise EvidencePortError() from None


P = ParamSpec("P")
R = TypeVar("R")


def evidence_port_boundary(function: Callable[P, R]) -> Callable[P, R]:
    """Check evidence consumers and turn malformed adapter access into typed refusal.

    The immutable adapter remains responsible for semantic validation. This wrapper
    deliberately preserves existing domain refusals and does not retry any operation.
    """

    @wraps(function)
    def guarded(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            head = kwargs.get("evidence_head")
            if head is None and args:
                head = getattr(args[0], "_evidence_head", args[0])
            require_evidence_head_v1(head)
            return function(*args, **kwargs)
        except AttributeError:
            raise EvidencePortError() from None

    return cast(Callable[P, R], guarded)
