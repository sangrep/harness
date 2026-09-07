from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from sangrep_harness.evidence_models import (
    EvidenceNodeV1,
    EvidenceProjectionRevisionV1,
    EvidenceRevisionV1,
    ProjectedEvidenceNodeV1,
)
from sangrep_harness.grants import (
    MAX_GRANT_ROOTS,
    REVIEW_TOOL_NAMES,
    GrantViolation,
    GrantViolationCodeV1,
)
from sangrep_harness.ports import EvidenceNodeV1 as EvidenceNodePortV1
from sangrep_harness.ports import evidence_port_boundary
from sangrep_harness.review import EvidenceBindingV1, EvidenceIdentityDraftsV1, StructuralGrantV1
from sangrep_harness.text_snapshot import TextSnapshotV1, snapshot_text_v1
from sangrep_harness.wire import canonical_json_sha256_v1

_RUNTIME_AUTHORITY = object()


@dataclass(frozen=True, slots=True)
class ReviewEvidenceHeadV1:
    evidence_binding: EvidenceBindingV1

    canonical_revision: EvidenceRevisionV1

    projection_revision: EvidenceProjectionRevisionV1

    _canonical_by_address: Mapping[tuple[str, str], EvidenceNodeV1] = field(
        init=False,
        repr=False,
        compare=False,
    )

    _canonical_by_stable_id: Mapping[str, tuple[EvidenceNodeV1, ...]] = field(
        init=False,
        repr=False,
        compare=False,
    )

    _projection_by_address: Mapping[tuple[str, str], ProjectedEvidenceNodeV1] = field(
        init=False,
        repr=False,
        compare=False,
    )

    _authority: object = field(default=None, repr=False, compare=False)

    @evidence_port_boundary
    def __post_init__(self) -> None:
        if self._authority is not _RUNTIME_AUTHORITY:
            raise GrantViolation(
                GrantViolationCodeV1.STALE_EVIDENCE,
                "Evidence head requires a fully revalidated evidence adapter value.",
            )
        if type(self.evidence_binding) is not EvidenceBindingV1:
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "Evidence head requires one validated evidence binding.",
            )
        if type(self.canonical_revision) is not EvidenceRevisionV1:
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "Evidence head requires one canonical text revision.",
            )
        if type(self.projection_revision) is not EvidenceProjectionRevisionV1:
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "Evidence head requires one text projection revision.",
            )
        binding = self.evidence_binding
        canonical = self.canonical_revision
        projection = self.projection_revision
        if (
            canonical.source_sha256 != binding.source_content_sha256
            or canonical.evidence_version_id != binding.evidence_version_id
            or canonical.structure_revision_id != binding.structure_revision_id
            or canonical.digest != binding.structure_graph_sha256
            or canonical.semantic_ir_sha256 != binding.evidence_canonical_output_sha256
            or projection.structure_revision_id != binding.structure_revision_id
            or projection.projection_revision_id != binding.projection_revision_id
            or projection.payload_sha256 != binding.projection_payload_sha256
            or canonical_json_sha256_v1(canonical.to_structure_revision_json())
            != binding.structure_record_sha256
            or canonical_json_sha256_v1(projection.to_projection_revision_json())
            != binding.projection_record_sha256
        ):
            raise GrantViolation(
                GrantViolationCodeV1.STALE_EVIDENCE,
                "Evidence, tree, and projection identities do not form one immutable head.",
            )
        canonical_by_address: dict[tuple[str, str], EvidenceNodeV1] = {}
        canonical_by_stable_id: dict[str, list[EvidenceNodeV1]] = {}
        canonical_addresses: list[tuple[str, str]] = []
        for node in canonical.nodes:
            address = (node.stable_id, node.occurrence_id)
            if address in canonical_by_address:
                raise GrantViolation(
                    GrantViolationCodeV1.STALE_EVIDENCE,
                    "Canonical evidence contains a duplicate anchor occurrence.",
                )
            canonical_addresses.append(address)
            canonical_by_address[address] = node
            canonical_by_stable_id.setdefault(node.stable_id, []).append(node)
        projection_by_address: dict[tuple[str, str], ProjectedEvidenceNodeV1] = {}
        projection_addresses: list[tuple[str, str]] = []
        for projected_node in projection.nodes:
            address = (projected_node.anchor_id, projected_node.occurrence_id)
            if address in projection_by_address:
                raise GrantViolation(
                    GrantViolationCodeV1.STALE_EVIDENCE,
                    "Projected evidence contains a duplicate anchor occurrence.",
                )
            projection_addresses.append(address)
            projection_by_address[address] = projected_node
        if not canonical_addresses or canonical_addresses != projection_addresses:
            raise GrantViolation(
                GrantViolationCodeV1.STALE_EVIDENCE,
                "Canonical and projected evidence do not share one ordered anchor economy.",
            )
        object.__setattr__(self, "_canonical_by_address", MappingProxyType(canonical_by_address))
        object.__setattr__(
            self,
            "_canonical_by_stable_id",
            MappingProxyType(
                {stable_id: tuple(nodes) for stable_id, nodes in canonical_by_stable_id.items()}
            ),
        )
        object.__setattr__(
            self,
            "_projection_by_address",
            MappingProxyType(projection_by_address),
        )

    @property
    def source_format(self) -> str:
        return self.canonical_revision.snapshot.relative_path.rsplit(".", 1)[-1].lower()

    @property
    def digest(self) -> str:
        """Return the exact head identity without serializing evidence payload text."""

        return canonical_json_sha256_v1(
            {
                "evidenceBindingSha256": self.evidence_binding.digest,
                "structureGraphSha256": self.canonical_revision.digest,
                "projectionPayloadSha256": self.projection_revision.payload_sha256,
            }
        )

    def require_grant(self, grant: StructuralGrantV1) -> None:
        """Reject a grant that was minted for any other immutable head."""

        if type(grant) is not StructuralGrantV1:
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "Grant must use the frozen structural-grant contract.",
            )
        if grant.evidence_binding.to_json_obj() != self.evidence_binding.to_json_obj():
            raise GrantViolation(
                GrantViolationCodeV1.STALE_EVIDENCE,
                "Structural grant does not match the current immutable evidence head.",
            )
        if (
            not grant.tool_names
            or any(name not in REVIEW_TOOL_NAMES for name in grant.tool_names)
            or len(grant.evidence_roots) > MAX_GRANT_ROOTS
        ):
            raise GrantViolation(
                GrantViolationCodeV1.UNADMITTED_TOOL,
                "Structural grant exceeds the closed text review authority.",
            )
        canonical_roots: list[EvidenceNodeV1] = []
        for root in grant.evidence_roots:
            if root.evidence_version_id != self.evidence_binding.evidence_version_id:
                raise GrantViolation(
                    GrantViolationCodeV1.MIXED_VERSION,
                    "Structural grant mixes evidence versions.",
                )
            canonical_roots.append(self._unique_node_for_stable_id(root.stable_id))
        for index, first in enumerate(canonical_roots):
            for second in canonical_roots[index + 1 :]:
                if self._is_descendant_or_self(
                    first,
                    second,
                ) or self._is_descendant_or_self(second, first):
                    raise GrantViolation(
                        GrantViolationCodeV1.OVERLAPPING_ROOTS,
                        "Structural grant roots overlap.",
                    )

    def canonical_node(
        self,
        anchor_id: str,
        occurrence_id: str,
    ) -> EvidenceNodeV1 | None:
        """Resolve only an exact canonical anchor occurrence."""

        return self._canonical_by_address.get((anchor_id, occurrence_id))

    def projected_node(
        self,
        anchor_id: str,
        occurrence_id: str,
    ) -> ProjectedEvidenceNodeV1 | None:
        """Resolve only the projection payload at an exact canonical occurrence."""

        return self._projection_by_address.get((anchor_id, occurrence_id))

    def root_for_anchor(
        self,
        grant: StructuralGrantV1,
        anchor_id: str,
        occurrence_id: str,
    ) -> str | None:
        """Return the admitted root containing an exact occurrence, without fuzzy lookup."""

        self.require_grant(grant)
        target = self.canonical_node(anchor_id, occurrence_id)
        if target is None:
            return None
        for root in grant.evidence_roots:
            root_node = self._unique_node_for_stable_id(root.stable_id)
            if self._is_descendant_or_self(target, root_node):
                return root.stable_id
        return None

    def require_stable_ids_in_grant(
        self,
        grant: StructuralGrantV1,
        stable_ids: tuple[str, ...],
    ) -> None:
        """Reject ambiguous, missing, or out-of-grant model-supplied stable IDs."""

        self.require_grant(grant)
        for stable_id in stable_ids:
            node = self._unique_node_for_stable_id(stable_id)
            if self.root_for_anchor(grant, node.stable_id, node.occurrence_id) is None:
                raise GrantViolation(
                    GrantViolationCodeV1.OUT_OF_SCOPE,
                    "Requested evidence is outside the immutable structural grant.",
                )

    def granted_nodes(self, grant: StructuralGrantV1) -> tuple[EvidenceNodeV1, ...]:
        """Return canonical-order nodes contained by the immutable roots."""

        self.require_grant(grant)
        roots = tuple(
            self._unique_node_for_stable_id(root.stable_id) for root in grant.evidence_roots
        )
        return tuple(
            node
            for node in self.canonical_revision.nodes
            if any(self._is_descendant_or_self(node, root) for root in roots)
        )

    def descendants_or_self(
        self,
        grant: StructuralGrantV1,
        stable_id: str,
    ) -> tuple[EvidenceNodeV1, ...]:
        """Return one in-grant subtree in canonical order."""

        self.require_stable_ids_in_grant(grant, (stable_id,))
        root = self._unique_node_for_stable_id(stable_id)
        return tuple(
            node for node in self.granted_nodes(grant) if self._is_descendant_or_self(node, root)
        )

    def depth_from(self, node: EvidenceNodePortV1, root: EvidenceNodePortV1) -> int:
        """Return canonical parent depth or refuse an unrelated node."""

        depth = 0
        current = node
        while (current.stable_id, current.occurrence_id) != (
            root.stable_id,
            root.occurrence_id,
        ):
            if current.parent_stable_id is None or current.parent_occurrence_id is None:
                raise GrantViolation(
                    GrantViolationCodeV1.OUT_OF_SCOPE,
                    "Canonical node is outside the selected root.",
                )
            parent = self.canonical_node(
                current.parent_stable_id,
                current.parent_occurrence_id,
            )
            if parent is None:
                raise GrantViolation(
                    GrantViolationCodeV1.STALE_EVIDENCE,
                    "Canonical parent occurrence is missing.",
                )
            current = parent
            depth += 1
        return depth

    def _unique_node_for_stable_id(self, stable_id: str) -> EvidenceNodeV1:
        matches = self._canonical_by_stable_id.get(stable_id, ())
        if len(matches) != 1:
            code = (
                GrantViolationCodeV1.OUT_OF_SCOPE
                if not matches
                else GrantViolationCodeV1.INVALID_ARGUMENT
            )
            raise GrantViolation(code, "Stable evidence root is missing or ambiguous.")
        return matches[0]

    def _is_descendant_or_self(
        self,
        node: EvidenceNodePortV1,
        root: EvidenceNodePortV1,
    ) -> bool:
        current = node
        while True:
            if (current.stable_id, current.occurrence_id) == (
                root.stable_id,
                root.occurrence_id,
            ):
                return True
            if current.parent_stable_id is None or current.parent_occurrence_id is None:
                return False
            parent = self.canonical_node(
                current.parent_stable_id,
                current.parent_occurrence_id,
            )
            if parent is None:
                raise GrantViolation(
                    GrantViolationCodeV1.STALE_EVIDENCE,
                    "Canonical parent occurrence is missing.",
                )
            current = parent


def text_evidence_head_v1(snapshot: TextSnapshotV1) -> ReviewEvidenceHeadV1:
    """Validate an entire text snapshot before granting inherited engine authority.

    Rebuild the public records and hierarchy from immutable source bytes and the
    declared text profile. Equality rejects forged payloads, duplicate or reordered
    occurrences, stale records, altered roots and cyclic/ambiguous parent graphs.
    This adapter is scoped to the reference text profile. Other profiles must supply
    an equally complete validation gate through the public evidence port.
    """
    if type(snapshot) is not TextSnapshotV1 or snapshot != snapshot_text_v1(
        snapshot.source_bytes, relative_path=snapshot.relative_path
    ):
        raise ValueError("snapshot-authority-invalid")
    drafts = EvidenceIdentityDraftsV1.from_json_obj(
        {
            "evidenceVersion": snapshot.evidence.to_json_obj(),
            "structureRevision": snapshot.structure.to_json_obj(),
            "projectionRevision": snapshot.projection.to_json_obj(),
        }
    )
    binding = EvidenceBindingV1(
        source_version_id=snapshot.source.source_version_id,
        source_content_sha256=snapshot.source.content_sha256,
        evidence_version_id=snapshot.evidence.evidence_version_id,
        evidence_record_sha256=snapshot.evidence.digest,
        evidence_canonical_output_sha256=snapshot.evidence.canonical_output_sha256,
        structure_revision_id=snapshot.structure.structure_revision_id,
        structure_record_sha256=snapshot.structure.digest,
        structure_graph_sha256=snapshot.structure.graph_sha256,
        projection_revision_id=snapshot.projection.projection_revision_id,
        projection_record_sha256=snapshot.projection.digest,
        projection_payload_sha256=snapshot.projection.payload_sha256,
        _draft_identities=drafts,
    )
    return ReviewEvidenceHeadV1(
        binding,
        EvidenceRevisionV1(
            snapshot,
            tuple(
                EvidenceNodeV1(node, ProjectedEvidenceNodeV1(projected).payload)
                for node, projected in zip(snapshot.nodes, snapshot.projections, strict=True)
            ),
        ),
        EvidenceProjectionRevisionV1(
            snapshot, tuple(ProjectedEvidenceNodeV1(node) for node in snapshot.projections)
        ),
        _authority=_RUNTIME_AUTHORITY,
    )
