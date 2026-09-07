from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sangrep_harness.grants import (
    AuthorizedToolCallV1,
    GrantViolation,
    GrantViolationCodeV1,
    SuccessfulToolCallV1,
    ToolEvidenceSupportV1,
    _mint_authorized_tool_call_v1,
    _mint_successful_tool_call_v1,
)
from sangrep_harness.ports import (
    EvidenceNodeV1,
    ProjectedEvidenceNodeV1,
    ReviewEvidenceHeadV1,
    evidence_port_boundary,
)
from sangrep_harness.review import StructuralGrantV1
from sangrep_harness.wire import (
    JsonValue,
    canonical_json_bytes_v1,
    canonical_json_sha256_v1,
    freeze_json_object_v1,
)

HarnessToolStatus = Literal["succeeded", "failed"]


MAX_READ_NODES = 20


MAX_READ_CHARACTERS = 40_000


MAX_QUERY_PATTERN_LENGTH = 256


MAX_RESULT_EVIDENCE_ITEMS = 1_000


class HarnessToolError(RuntimeError):
    """Typed failure raised before an unsafe or invalid tool result can escape."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, repr=False)
class HarnessToolRequest:
    """One normalized model-requested tool invocation."""

    call_id: str
    name: str
    arguments: dict[str, object]

    def __repr__(self) -> str:
        return (
            "<HarnessToolRequest "
            f"name={self.name!r} argument_count={len(self.arguments)} redacted>"
        )


@dataclass(frozen=True)
class HarnessToolDefinition:
    """Provider-neutral tool metadata and JSON input schema."""

    name: str
    description: str
    input_schema: dict[str, object]


@dataclass(frozen=True, repr=False)
class HarnessToolResult:
    """Normalized deterministic result safe to return to a model and audit log."""

    call_id: str
    name: str
    status: HarnessToolStatus
    payload: dict[str, object]
    projection_digest: str
    citable_stable_ids: tuple[str, ...] = ()
    citable_evidence: tuple[ToolEvidenceSupportV1, ...] = ()

    def __repr__(self) -> str:
        return (
            "<HarnessToolResult "
            f"name={self.name!r} status={self.status!r} "
            f"payload_field_count={len(self.payload)} "
            f"citable_count={len(self.citable_stable_ids)} "
            f"projection_digest={self.projection_digest!r} redacted>"
        )

    @property
    def digest(self) -> str:
        """Bind the provider-visible result to its exact citable payload identities."""

        return canonical_json_sha256_v1(
            cast(
                JsonValue,
                {
                    "callId": self.call_id,
                    "name": self.name,
                    "status": self.status,
                    "payload": self.payload,
                    "projectionDigest": self.projection_digest,
                    "citableStableIds": list(self.citable_stable_ids),
                    "citableEvidence": [support.to_json_obj() for support in self.citable_evidence],
                },
            )
        )


class _ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class _ListScopeArguments(_ToolArguments):
    pass


class _OutlineArguments(_ToolArguments):
    root_stable_id: str | None = Field(default=None, alias="rootStableId", min_length=1)
    max_depth: int = Field(default=6, alias="maxDepth", ge=0, le=20)


class _ReadNodesArguments(_ToolArguments):
    stable_ids: list[str] = Field(alias="stableIds", min_length=1, max_length=MAX_READ_NODES)
    include_descendants: bool = Field(default=False, alias="includeDescendants")


class _SearchArguments(_ToolArguments):
    query: str = Field(min_length=1, max_length=200)
    limit: int = Field(default=10, ge=1, le=50)


class _QueryBlocksArguments(_ToolArguments):
    node_types: list[str] | None = Field(default=None, alias="nodeTypes", max_length=20)
    source_formats: list[str] | None = Field(default=None, alias="sourceFormats", max_length=20)
    text_pattern: str | None = Field(
        default=None,
        alias="textPattern",
        min_length=1,
        max_length=MAX_QUERY_PATTERN_LENGTH,
    )
    resolution_states: list[str] | None = Field(
        default=None,
        alias="resolutionStates",
        max_length=5,
    )
    limit: int = Field(default=20, ge=1, le=100)


_ARGUMENT_MODELS: dict[str, type[_ToolArguments]] = {
    "list_scope": _ListScopeArguments,
    "outline": _OutlineArguments,
    "read_nodes": _ReadNodesArguments,
    "search": _SearchArguments,
    "query_blocks": _QueryBlocksArguments,
}


_TOOL_DESCRIPTIONS = {
    "list_scope": "List the evidence roots granted for this run and their parse state.",
    "outline": "Inspect the structural hierarchy of one granted evidence root.",
    "read_nodes": "Read fresh, citable projections of specifically addressed evidence nodes.",
    "search": "Search granted evidence text and titles with deterministic lexical ranking.",
    "query_blocks": "Filter granted blocks by type, format, resolution state, or safe regex.",
}


class AdmittedToolRegistryV1:
    """Authorize every text review tool call before execution and account its budget."""

    __slots__ = ("_authorized_call_ids", "_successful_calls")

    def __init__(self) -> None:
        self._authorized_call_ids: set[str] = set()
        self._successful_calls: list[SuccessfulToolCallV1] = []

    @property
    def successful_tool_calls(self) -> tuple[SuccessfulToolCallV1, ...]:
        return tuple(self._successful_calls)

    @evidence_port_boundary
    def authorize(
        self,
        name: str,
        arguments: dict[str, object],
        *,
        call_id: str,
        grant: StructuralGrantV1,
        evidence_head: ReviewEvidenceHeadV1,
    ) -> AuthorizedToolCallV1:
        """Validate name, arguments, containment, freshness, and budget in that order."""

        if type(name) is not str or type(call_id) is not str or call_id.strip() == "":
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "Tool name and call identity must be bounded non-empty strings.",
            )
        if type(arguments) is not dict:
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "Tool arguments must be one JSON object.",
            )
        evidence_head.require_grant(grant)
        if name not in grant.tool_names or name not in _ARGUMENT_MODELS:
            raise GrantViolation(
                GrantViolationCodeV1.UNADMITTED_TOOL,
                "Tool is outside the immutable structural grant.",
            )
        try:
            validated = _ARGUMENT_MODELS[name].model_validate(arguments)
        except ValidationError as error:
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "Tool arguments do not match the closed schema.",
            ) from error
        normalized = cast(dict[str, object], validated.model_dump(by_alias=True))
        evidence_head.require_stable_ids_in_grant(
            grant,
            _requested_stable_ids(name, normalized, grant=grant),
        )
        if call_id in self._authorized_call_ids:
            raise GrantViolation(
                GrantViolationCodeV1.DUPLICATE_CALL,
                "Tool call identity was already authorized.",
            )
        if len(self._authorized_call_ids) >= grant.limits.max_tool_calls:
            raise GrantViolation(
                GrantViolationCodeV1.BUDGET_EXHAUSTED,
                "Structural grant tool-call budget is exhausted.",
            )
        authorization = _mint_authorized_tool_call_v1(
            call_id=call_id,
            name=name,
            arguments=freeze_json_object_v1(cast(dict[str, JsonValue], normalized)),
            grant_id=grant.grant_id,
            grant_sha256=grant.digest,
            evidence_head_sha256=evidence_head.digest,
            ordinal=len(self._authorized_call_ids) + 1,
        )
        self._authorized_call_ids.add(call_id)
        return authorization

    @evidence_port_boundary
    def record_success(
        self,
        authorization: AuthorizedToolCallV1,
        result: HarnessToolResult,
        *,
        grant: StructuralGrantV1,
        evidence_head: ReviewEvidenceHeadV1,
    ) -> SuccessfulToolCallV1:
        """Record only exact citable identities from a successful admitted result."""

        evidence_head.require_grant(grant)
        if (
            type(authorization) is not AuthorizedToolCallV1
            or authorization.call_id not in self._authorized_call_ids
            or authorization.grant_id != grant.grant_id
            or authorization.grant_sha256 != grant.digest
            or authorization.evidence_head_sha256 != evidence_head.digest
            or type(result) is not HarnessToolResult
            or result.call_id != authorization.call_id
            or result.name != authorization.name
            or result.status != "succeeded"
            or result.projection_digest != grant.evidence_binding.projection_payload_sha256
            or any(call.call_id == authorization.call_id for call in self._successful_calls)
        ):
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "Successful tool provenance does not match its authorization.",
            )
        if tuple(dict.fromkeys(result.citable_stable_ids)) != result.citable_stable_ids:
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "Citable stable IDs must be unique and ordered.",
            )
        supports: list[ToolEvidenceSupportV1] = []
        for support in result.citable_evidence:
            if type(support) is not ToolEvidenceSupportV1:
                raise GrantViolation(
                    GrantViolationCodeV1.INVALID_ARGUMENT,
                    "Tool result contains malformed citable evidence.",
                )
            projected = evidence_head.projected_node(
                support.anchor_id,
                support.occurrence_id,
            )
            root_id = evidence_head.root_for_anchor(
                grant,
                support.anchor_id,
                support.occurrence_id,
            )
            if (
                projected is None
                or root_id != support.root_anchor_id
                or projected.citable_state != "citable"
                or projected.projected_payload_sha256 != support.projected_payload_sha256
                or support.exact_quote_sha256 != projected.projected_payload_sha256
                or support.anchor_id not in result.citable_stable_ids
            ):
                raise GrantViolation(
                    GrantViolationCodeV1.UNADMITTED_CITATION,
                    "Tool result cannot make this evidence payload citable.",
                )
            supports.append(support)
        if {support.anchor_id for support in supports} != set(result.citable_stable_ids):
            raise GrantViolation(
                GrantViolationCodeV1.UNADMITTED_CITATION,
                "Every citable stable ID needs an exact successful-tool payload.",
            )
        successful = _mint_successful_tool_call_v1(
            authorization=authorization,
            result_sha256=result.digest,
            supports=tuple(supports),
        )
        self._successful_calls.append(successful)
        return successful


class EvidenceReviewToolsV1:
    """Projection-backed text tools with no authority beyond one structural grant."""

    __slots__ = ("_evidence_head", "_grant", "_registry")

    @evidence_port_boundary
    def __init__(
        self,
        *,
        grant: StructuralGrantV1,
        evidence_head: ReviewEvidenceHeadV1,
        registry: AdmittedToolRegistryV1,
    ) -> None:
        if type(registry) is not AdmittedToolRegistryV1:
            raise TypeError("registry must use AdmittedToolRegistryV1")
        evidence_head.require_grant(grant)
        self._grant = grant
        self._evidence_head = evidence_head
        self._registry = registry

    @property
    def definitions(self) -> tuple[HarnessToolDefinition, ...]:
        return tuple(
            HarnessToolDefinition(
                name=name,
                description=_TOOL_DESCRIPTIONS[name],
                input_schema=_ARGUMENT_MODELS[name].model_json_schema(by_alias=True),
            )
            for name in self._grant.tool_names
        )

    @property
    def successful_tool_calls(self) -> tuple[SuccessfulToolCallV1, ...]:
        return self._registry.successful_tool_calls

    @evidence_port_boundary
    def execute(self, request: HarnessToolRequest) -> HarnessToolResult:
        """Authorize, execute, then seal exact support identities for one call."""

        if type(request) is not HarnessToolRequest:
            raise TypeError("request must use HarnessToolRequest")
        authorization = self._registry.authorize(
            request.name,
            request.arguments,
            call_id=request.call_id,
            grant=self._grant,
            evidence_head=self._evidence_head,
        )
        arguments = _ARGUMENT_MODELS[request.name].model_validate(
            authorization.arguments.to_json_obj()
        )
        try:
            payload, supports = getattr(self, f"_execute_{request.name}")(arguments)
            if len(canonical_json_bytes_v1(freeze_json_object_v1(payload).to_json_obj())) > 65536:
                raise GrantViolation(
                    GrantViolationCodeV1.BUDGET_EXHAUSTED, "Tool result exceeds its byte budget."
                )
        except GrantViolation as error:
            if error.code is not GrantViolationCodeV1.BUDGET_EXHAUSTED:
                raise
            return HarnessToolResult(
                call_id=request.call_id,
                name=request.name,
                status="failed",
                payload={"errorCode": error.code.value},
                projection_digest=self._grant.evidence_binding.projection_payload_sha256,
            )
        citable_ids = tuple(dict.fromkeys(support.anchor_id for support in supports))
        result = HarnessToolResult(
            call_id=request.call_id,
            name=request.name,
            status="succeeded",
            payload=payload,
            projection_digest=self._grant.evidence_binding.projection_payload_sha256,
            citable_stable_ids=citable_ids,
            citable_evidence=supports,
        )
        self._registry.record_success(
            authorization,
            result,
            grant=self._grant,
            evidence_head=self._evidence_head,
        )
        return result

    def _execute_list_scope(
        self,
        _arguments: _ListScopeArguments,
    ) -> tuple[dict[str, object], tuple[ToolEvidenceSupportV1, ...]]:
        roots = []
        for root_ref in self._grant.evidence_roots:
            root = self._unique_granted_node(root_ref.stable_id)
            projected = self._required_projection(root)
            roots.append(
                {
                    "evidenceVersionId": root_ref.evidence_version_id,
                    "stableId": root.stable_id,
                    "occurrenceId": root.occurrence_id,
                    "semanticKind": root.kind.value,
                    "title": root.title_or_none,
                    "citableState": projected.citable_state,
                    "limitationCodes": list(projected.limitation_codes),
                }
            )
        return {"roots": roots}, ()

    def _execute_outline(
        self,
        arguments: _OutlineArguments,
    ) -> tuple[dict[str, object], tuple[ToolEvidenceSupportV1, ...]]:
        root_id = arguments.root_stable_id or self._grant.evidence_roots[0].stable_id
        if root_id not in {root.stable_id for root in self._grant.evidence_roots}:
            raise GrantViolation(
                GrantViolationCodeV1.OUT_OF_SCOPE,
                "Outline root must be one of the reviewer-selected roots.",
            )
        root = self._unique_granted_node(root_id)
        nodes: list[dict[str, object]] = []
        for node in self._evidence_head.descendants_or_self(self._grant, root_id):
            depth = self._evidence_head.depth_from(node, root)
            if depth > arguments.max_depth:
                continue
            if len(nodes) >= MAX_RESULT_EVIDENCE_ITEMS:
                raise GrantViolation(
                    GrantViolationCodeV1.BUDGET_EXHAUSTED,
                    f"outline exceeded the {MAX_RESULT_EVIDENCE_ITEMS}-node result budget.",
                )
            projected = self._required_projection(node)
            nodes.append(
                {
                    "stableId": node.stable_id,
                    "occurrenceId": node.occurrence_id,
                    "parentStableId": (None if node is root else node.parent_stable_id),
                    "depth": depth,
                    "semanticKind": node.kind.value,
                    "title": node.title_or_none,
                    "citableState": projected.citable_state,
                    "limitationCodes": list(projected.limitation_codes),
                }
            )
        return {"rootStableId": root_id, "nodes": nodes}, ()

    def _execute_read_nodes(
        self,
        arguments: _ReadNodesArguments,
    ) -> tuple[dict[str, object], tuple[ToolEvidenceSupportV1, ...]]:
        if len(arguments.stable_ids) != len(set(arguments.stable_ids)):
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "stableIds must not contain duplicates.",
            )
        payload_nodes: list[dict[str, object]] = []
        supports: list[ToolEvidenceSupportV1] = []
        character_count = 0
        evidence_item_count = 0
        for stable_id in arguments.stable_ids:
            included = (
                self._evidence_head.descendants_or_self(self._grant, stable_id)
                if arguments.include_descendants
                else (self._unique_granted_node(stable_id),)
            )
            projections = tuple(self._required_projection(node) for node in included)
            evidence_item_count += len(included)
            if evidence_item_count > MAX_RESULT_EVIDENCE_ITEMS:
                raise GrantViolation(
                    GrantViolationCodeV1.BUDGET_EXHAUSTED,
                    "read_nodes exceeded the bounded evidence-item result budget.",
                )
            markdown = "\n".join(node.payload for node in projections)
            character_count += len(markdown)
            if character_count > MAX_READ_CHARACTERS:
                raise GrantViolation(
                    GrantViolationCodeV1.BUDGET_EXHAUSTED,
                    f"read_nodes exceeded the {MAX_READ_CHARACTERS}-character result budget.",
                )
            payload_nodes.append(
                {
                    "stableId": stable_id,
                    "markdown": markdown,
                    "includedStableIds": [node.stable_id for node in included],
                    "includedOccurrences": [
                        {
                            "stableId": node.stable_id,
                            "occurrenceId": node.occurrence_id,
                            "projectedPayloadSha256": projected.projected_payload_sha256,
                            "citableState": projected.citable_state,
                        }
                        for node, projected in zip(included, projections, strict=True)
                    ],
                    "unresolvedStableIds": [
                        node.stable_id
                        for node, projected in zip(included, projections, strict=True)
                        if projected.citable_state != "citable"
                    ],
                }
            )
            supports.extend(self._supports(included))
        return {"nodes": payload_nodes}, tuple(supports)

    def _execute_search(
        self,
        arguments: _SearchArguments,
    ) -> tuple[dict[str, object], tuple[ToolEvidenceSupportV1, ...]]:
        query = arguments.query.strip()
        if query == "":
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "search query must not be blank.",
            )
        ranked: list[tuple[int, int, EvidenceNodeV1, ProjectedEvidenceNodeV1]] = []
        for index, node in enumerate(self._evidence_head.granted_nodes(self._grant)):
            projected = self._required_projection(node)
            occurrences = projected.payload.casefold().count(query.casefold())
            if occurrences:
                ranked.append((-occurrences, index, node, projected))
        ranked.sort(key=lambda item: (item[0], item[1], item[2].stable_id))
        selected = ranked[: arguments.limit]
        matches = [
            {
                "stableId": node.stable_id,
                "occurrenceId": node.occurrence_id,
                "semanticKind": node.kind.value,
                "excerpt": projected.payload,
                "projectedPayloadSha256": projected.projected_payload_sha256,
                "citableState": projected.citable_state,
            }
            for _, _, node, projected in selected
        ]
        return {
            "query": query,
            "matches": matches,
        }, self._supports(tuple(item[2] for item in selected))

    def _execute_query_blocks(
        self,
        arguments: _QueryBlocksArguments,
    ) -> tuple[dict[str, object], tuple[ToolEvidenceSupportV1, ...]]:
        node_types = set(arguments.node_types or ())
        source_formats = set(arguments.source_formats or ())
        text_pattern = self._compile_text_pattern(arguments.text_pattern)
        selected = []
        for node in self._evidence_head.granted_nodes(self._grant):
            projected = self._required_projection(node)
            if node_types and node.kind.value not in node_types:
                continue
            if source_formats and self._evidence_head.source_format not in source_formats:
                continue
            if text_pattern is not None and text_pattern.search(projected.payload) is None:
                continue
            if arguments.resolution_states and projected.citable_state not in set(
                arguments.resolution_states
            ):
                continue
            selected.append(node)
            if len(selected) >= arguments.limit:
                break
        payload_nodes = []
        for node in selected:
            projected = self._required_projection(node)
            payload_nodes.append(
                {
                    "stableId": node.stable_id,
                    "occurrenceId": node.occurrence_id,
                    "semanticKind": node.kind.value,
                    "sourceFormat": self._evidence_head.source_format,
                    "citableState": projected.citable_state,
                    "markdown": projected.payload,
                    "projectedPayloadSha256": projected.projected_payload_sha256,
                }
            )
        return {"nodes": payload_nodes}, self._supports(tuple(selected))

    def _supports(
        self,
        nodes: tuple[EvidenceNodeV1, ...],
    ) -> tuple[ToolEvidenceSupportV1, ...]:
        supports = []
        for node in nodes:
            projected = self._required_projection(node)
            root_id = self._evidence_head.root_for_anchor(
                self._grant,
                node.stable_id,
                node.occurrence_id,
            )
            if projected.citable_state != "citable" or root_id is None:
                continue
            supports.append(
                ToolEvidenceSupportV1(
                    root_anchor_id=root_id,
                    anchor_id=node.stable_id,
                    occurrence_id=node.occurrence_id,
                    projected_payload_sha256=projected.projected_payload_sha256,
                    exact_quote_sha256=projected.projected_payload_sha256,
                )
            )
        return tuple(supports)

    def _unique_granted_node(self, stable_id: str) -> EvidenceNodeV1:
        self._evidence_head.require_stable_ids_in_grant(self._grant, (stable_id,))
        matches = tuple(
            node
            for node in self._evidence_head.canonical_revision.nodes
            if node.stable_id == stable_id
        )
        if len(matches) != 1:
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "Stable evidence anchor is ambiguous.",
            )
        return matches[0]

    def _required_projection(self, node: EvidenceNodeV1) -> ProjectedEvidenceNodeV1:
        projected = self._evidence_head.projected_node(node.stable_id, node.occurrence_id)
        if projected is None:
            raise GrantViolation(
                GrantViolationCodeV1.STALE_EVIDENCE,
                "Projected evidence occurrence is missing.",
            )
        return projected

    @staticmethod
    def _compile_text_pattern(pattern: str | None) -> re.Pattern[str] | None:
        if pattern is None:
            return None
        try:
            _validate_safe_regex_subset(pattern)
            return re.compile(pattern, flags=re.IGNORECASE)
        except (HarnessToolError, re.error) as error:
            raise GrantViolation(
                GrantViolationCodeV1.INVALID_ARGUMENT,
                "textPattern does not use the bounded regex subset.",
            ) from error


def _requested_stable_ids(
    name: str,
    arguments: dict[str, object],
    *,
    grant: StructuralGrantV1,
) -> tuple[str, ...]:
    if name == "read_nodes":
        return tuple(cast(list[str], arguments["stableIds"]))
    if name == "outline":
        root = arguments.get("rootStableId")
        return (grant.evidence_roots[0].stable_id,) if root is None else (cast(str, root),)
    return ()


def _validate_safe_regex_subset(pattern: str) -> None:
    """Reject constructs that can trigger unbounded backtracking in stdlib ``re``.

    The read-only tool accepts useful linear-time matching constructs—literals,
    character classes, anchors, dot, and alternation—but deliberately excludes
    grouping, repetition, and backreferences. Richer regular expressions require
    a future timeout-capable engine rather than trusting model-supplied patterns.
    """

    escaped = False
    for character in pattern:
        if escaped:
            if character.isdigit():
                raise HarnessToolError(
                    "INVALID_ARGUMENT",
                    "textPattern must use the safe regex subset; backreferences are not allowed.",
                )
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character in "()*+?{}":
            raise HarnessToolError(
                "INVALID_ARGUMENT",
                "textPattern must use the safe regex subset; grouping and repetition "
                "are not allowed.",
            )
