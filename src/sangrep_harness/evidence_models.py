"""Read-only views from accepted public contracts into inherited engine ports."""

from __future__ import annotations

from dataclasses import dataclass

import sangrep_contracts as c

from sangrep_harness.text_snapshot import TextSnapshotV1


@dataclass(frozen=True, slots=True)
class EvidenceNodeV1:
    value: c.EvidenceNodeV1
    text: str

    @property
    def text_or_none(self) -> str | None:
        return self.text

    @property
    def ordinal(self) -> int:
        return self.value.ordinal

    @property
    def coverage(self) -> c.EvidenceCoverageStateV1:
        return self.value.coverage_state

    @property
    def limitation_code_or_none(self) -> str | None:
        codes = self.value.warning_codes + self.value.omission_codes
        return codes[0] if codes else None

    @property
    def stable_id(self) -> str:
        return self.value.anchor_id

    @property
    def occurrence_id(self) -> str:
        return self.value.occurrence_id

    @property
    def parent_stable_id(self) -> str | None:
        return self.value.parent_anchor_id

    @property
    def parent_occurrence_id(self) -> str | None:
        return self.value.parent_occurrence_id

    @property
    def kind(self) -> c.EvidenceNodeKindV1:
        return self.value.node_kind

    @property
    def title_or_none(self) -> str | None:
        return self.value.title


@dataclass(frozen=True, slots=True)
class ProjectedEvidenceNodeV1:
    value: c.ProjectedNodeV1

    @property
    def projection_revision_id(self) -> str:
        return self.value.projection_revision_id

    @property
    def structure_revision_id(self) -> str:
        return self.value.structure_revision_id

    @property
    def payload_kind(self) -> str:
        return self.value.payload_kind.value

    @property
    def inclusion_state(self) -> str:
        return self.value.inclusion_state.value

    @property
    def anchor_id(self) -> str:
        return self.value.anchor_id

    @property
    def occurrence_id(self) -> str:
        return self.value.occurrence_id

    @property
    def citable_state(self) -> str:
        return self.value.citable_state.value

    @property
    def projected_payload_sha256(self) -> str:
        return self.value.projected_payload_sha256

    @property
    def limitation_codes(self) -> tuple[str, ...]:
        return self.value.limitation_codes

    @property
    def payload(self) -> str:
        value = c.thaw_json_value_v1(self.value.payload)
        if not isinstance(value, str):
            raise ValueError("text-projection-required")
        return value


@dataclass(frozen=True, slots=True)
class EvidenceRevisionV1:
    snapshot: TextSnapshotV1
    nodes: tuple[EvidenceNodeV1, ...]

    @property
    def canonicalization_profile_id(self) -> str:
        return self.snapshot.structure.structure_profile_id

    @property
    def canonicalization_profile_sha256(self) -> str:
        return self.snapshot.structure.structure_profile_sha256

    @property
    def root_stable_id(self) -> str:
        return self.snapshot.nodes[0].anchor_id

    @property
    def source_sha256(self) -> str:
        return self.snapshot.source.content_sha256

    @property
    def evidence_version_id(self) -> str:
        return self.snapshot.evidence.evidence_version_id

    @property
    def structure_revision_id(self) -> str:
        return self.snapshot.structure.structure_revision_id

    @property
    def digest(self) -> str:
        return self.snapshot.structure.graph_sha256

    @property
    def semantic_ir_sha256(self) -> str:
        return self.snapshot.evidence.canonical_output_sha256

    def to_structure_revision_json(self) -> dict[str, c.JsonValue]:
        return self.snapshot.structure.to_json_obj()


@dataclass(frozen=True, slots=True)
class EvidenceProjectionRevisionV1:
    snapshot: TextSnapshotV1
    nodes: tuple[ProjectedEvidenceNodeV1, ...]

    @property
    def projection_kind(self) -> str:
        return self.snapshot.projections[0].payload_kind.value

    @property
    def projection_profile_sha256(self) -> str:
        return self.snapshot.projection.projection_profile_sha256

    @property
    def structure_revision_id(self) -> str:
        return self.snapshot.structure.structure_revision_id

    @property
    def projection_revision_id(self) -> str:
        return self.snapshot.projection.projection_revision_id

    @property
    def payload_sha256(self) -> str:
        return self.snapshot.projection.payload_sha256

    @property
    def projection_profile_id(self) -> str:
        return self.snapshot.projection.projection_profile_id

    @property
    def projection_profile_version(self) -> str:
        return self.snapshot.projection.projection_profile_version

    def to_projection_revision_json(self) -> dict[str, c.JsonValue]:
        return self.snapshot.projection.to_json_obj()
