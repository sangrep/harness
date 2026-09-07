from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias, TypeVar, cast

HARNESS_REVIEW_CONTRACT_ID = "sangrep.harness.review.v1"


HARNESS_REVIEW_CONTRACT_STATUS = "development"


MAX_SAFE_INTEGER = 2**53 - 1


MAX_IDENTIFIER_BYTES = 128


MAX_CANONICAL_DEPTH = 64


MAX_CANONICAL_VALUES = 10_000


MAX_CANONICAL_BYTES = 10 * 1024 * 1024


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


_COMMAND_FIELDS = frozenset(
    {
        "schemaVersion",
        "kind",
        "contractId",
        "method",
        "requestId",
        "payload",
        "payloadSha256",
    }
)


_EVENT_FIELDS = frozenset(
    {
        "schemaVersion",
        "kind",
        "contractId",
        "eventId",
        "runId",
        "sequence",
        "eventType",
        "previousEventSha256",
        "payload",
        "payloadSha256",
    }
)


_CURSOR_FIELDS = frozenset(
    {
        "schemaVersion",
        "kind",
        "contractId",
        "subjectId",
        "revisionId",
        "revisionSha256",
        "afterIndex",
        "afterItemSha256",
        "pageSize",
    }
)


_REPLAY_PAGE_FIELDS = frozenset(
    {
        "schemaVersion",
        "kind",
        "contractId",
        "runId",
        "eventHeadSha256",
        "pageSize",
        "requestCursor",
        "events",
        "nextCursor",
        "terminal",
    }
)


JsonScalar: TypeAlias = None | bool | int | str


JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


FrozenJsonScalarV1: TypeAlias = None | bool | int | str


EnumV1 = TypeVar("EnumV1", bound=StrEnum)


class ReviewContractErrorCodeV1(StrEnum):
    """Closed machine codes for alpha contract refusal."""

    INVALID_VALUE = "invalid_value"
    MALFORMED_JSON = "malformed_json"
    DUPLICATE_MEMBER = "duplicate_member"
    NON_NFC = "non_nfc"
    UNSAFE_INTEGER = "unsafe_integer"
    NON_FINITE = "non_finite"
    VERSION_MISMATCH = "version_mismatch"
    UNKNOWN_METHOD = "unknown_method"
    DIGEST_MISMATCH = "digest_mismatch"
    UNKNOWN_FIELD = "unknown_field"
    UNKNOWN_EVENT = "unknown_event"
    INVALID_IDENTIFIER = "invalid_identifier"
    STALE_EVIDENCE = "stale_evidence"


class ReviewContractError(ValueError):
    """Raised when bytes or values violate the private alpha contract."""

    def __init__(
        self,
        message: str,
        *,
        code: ReviewContractErrorCodeV1 = ReviewContractErrorCodeV1.INVALID_VALUE,
    ) -> None:
        super().__init__(message)
        self.code = code


class ReviewMethodV1(StrEnum):
    """Closed command registry for the private review engine protocol."""

    DOCUMENT_IMPORT = "document.import"
    EVIDENCE_GET_TREE = "evidence.getTree"
    EVIDENCE_GET_PROJECTION = "evidence.getProjection"
    REVIEW_START = "review.start"
    REVIEW_CONTINUE = "review.continue"
    REVIEW_GET = "review.get"
    REVIEW_CANCEL = "review.cancel"
    CITATION_RESOLVE = "citation.resolve"
    EVENTS_REPLAY = "events.replay"
    FINDING_DISPOSITION_APPEND = "finding.disposition.append"
    CLARIFICATION_RESPOND = "clarification.respond"
    CLARIFICATION_WAIVE = "clarification.waive"
    KNOWLEDGE_CONFIRM = "knowledge.confirm"
    REVIEW_COMPLETION_APPEND = "review.completion.append"
    REVIEW_COMPLETION_SUPERSEDE = "review.completion.supersede"


class ReviewEventTypeV1(StrEnum):
    """Closed observable event vocabulary; no private reasoning event exists."""

    RUN_STARTED = "run_started"
    MODEL_REQUESTED = "model_requested"
    MODEL_COMPLETED = "model_completed"
    TOOL_REQUESTED = "tool_requested"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"
    CITATION_VALIDATION = "citation_validation"
    CLARIFICATION_REQUIRED = "clarification_required"
    CANCELLATION_REQUESTED = "cancellation_requested"
    TERMINAL = "terminal"


class TerminalOutcomeV1(StrEnum):
    """Closed terminal outcomes shared by events and semantic results."""

    SUPPORTED_ANSWER = "supported_answer"
    EVIDENCE_GAP = "evidence_gap"
    ABSTAINED = "abstained"
    CLARIFICATION_REQUIRED = "clarification_required"
    CANCELLED = "cancelled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    PROVIDER_FAILED = "provider_failed"
    ENGINE_FAILED = "engine_failed"
    POLICY_SUPERSEDED = "policy_superseded"
    PROTOCOL_SUPERSEDED = "protocol_superseded"


class CitationResolutionStateV1(StrEnum):
    """Closed reviewer-visible citation resolution states."""

    RESOLVED = "resolved"
    INVALID = "invalid"
    OUT_OF_SCOPE = "out_of_scope"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class FrozenJsonArrayV1:
    """Recursively immutable canonical JSON array."""

    items: tuple[FrozenJsonValueV1, ...]

    def __post_init__(self) -> None:
        if type(self.items) is not tuple:
            raise ReviewContractError("Frozen JSON array items must be a tuple.")
        for item in self.items:
            _require_frozen_json_value(item)

    def to_json_value(self) -> list[JsonValue]:
        return [thaw_json_value_v1(item) for item in self.items]


@dataclass(frozen=True, slots=True)
class FrozenJsonObjectV1:
    """Recursively immutable canonical JSON object."""

    entries: tuple[tuple[str, FrozenJsonValueV1], ...]

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple:
            raise ReviewContractError("Frozen JSON object entries must be a tuple.")
        previous: bytes | None = None
        for entry in self.entries:
            if type(entry) is not tuple or len(entry) != 2:
                raise ReviewContractError("Frozen JSON object entries must be key/value tuples.")
            key, item = entry
            _require_nfc_string(key, field_name="JSON object key")
            sort_key = _utf16_sort_key(key)
            if previous is not None and sort_key <= previous:
                raise ReviewContractError(
                    "Frozen JSON object keys must be unique and in canonical order."
                )
            previous = sort_key
            _require_frozen_json_value(item)

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {key: thaw_json_value_v1(item) for key, item in self.entries}


FrozenJsonValueV1: TypeAlias = FrozenJsonScalarV1 | FrozenJsonArrayV1 | FrozenJsonObjectV1


@dataclass(frozen=True, slots=True)
class ReviewCommandV1:
    """One payload-bound private alpha command."""

    method: ReviewMethodV1
    request_id: str
    payload: FrozenJsonObjectV1
    payload_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.method, ReviewMethodV1):
            raise ReviewContractError("method contains an unknown review command.")
        _require_identifier(self.request_id, field_name="request_id")
        if type(self.payload) is not FrozenJsonObjectV1:
            raise ReviewContractError("payload must be a frozen JSON object.")
        _require_sha256(self.payload_sha256, field_name="payload_sha256")
        if canonical_json_sha256_v1(self.payload.to_json_obj()) != self.payload_sha256:
            raise ReviewContractError(
                "Command payload digest does not match the payload.",
                code=ReviewContractErrorCodeV1.DIGEST_MISMATCH,
            )
        _validate_command_payload(self.method, self.payload.to_json_obj())

    @classmethod
    def from_json_obj(cls, value: object) -> ReviewCommandV1:
        payload = _require_exact_object(value, expected=_COMMAND_FIELDS, field_name="reviewCommand")
        _require_schema_version(payload["schemaVersion"])
        _require_literal(payload["kind"], expected="reviewCommand", field_name="kind")
        _require_literal(
            payload["contractId"],
            expected=HARNESS_REVIEW_CONTRACT_ID,
            field_name="contractId",
        )
        method = _require_enum(
            ReviewMethodV1,
            payload["method"],
            field_name="method",
            unknown_code=ReviewContractErrorCodeV1.UNKNOWN_METHOD,
        )
        request_id = _require_identifier(payload["requestId"], field_name="requestId")
        command_payload = freeze_json_object_v1(payload["payload"])
        payload_sha256 = _require_sha256(payload["payloadSha256"], field_name="payloadSha256")
        return cls(
            method=method,
            request_id=request_id,
            payload=command_payload,
            payload_sha256=payload_sha256,
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": "reviewCommand",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "method": self.method.value,
            "requestId": self.request_id,
            "payload": self.payload.to_json_obj(),
            "payloadSha256": self.payload_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class ReviewEventV1:
    """One ordered, payload-bound observable event."""

    event_id: str
    run_id: str
    sequence: int
    event_type: ReviewEventTypeV1
    previous_event_sha256: str | None
    payload: FrozenJsonObjectV1
    payload_sha256: str

    def __post_init__(self) -> None:
        _require_identifier(self.event_id, field_name="event_id")
        _require_identifier(self.run_id, field_name="run_id")
        _require_non_negative_int(self.sequence, field_name="sequence")
        if not isinstance(self.event_type, ReviewEventTypeV1):
            raise ReviewContractError(
                "event_type contains an unknown event.",
                code=ReviewContractErrorCodeV1.UNKNOWN_EVENT,
            )
        if self.sequence == 0:
            if self.previous_event_sha256 is not None:
                raise ReviewContractError("The first event cannot reference a previous event.")
        elif self.previous_event_sha256 is None:
            raise ReviewContractError("A successor event must reference the previous event digest.")
        else:
            _require_sha256(
                self.previous_event_sha256,
                field_name="previous_event_sha256",
            )
        if type(self.payload) is not FrozenJsonObjectV1:
            raise ReviewContractError("payload must be a frozen JSON object.")
        _require_sha256(self.payload_sha256, field_name="payload_sha256")
        if canonical_json_sha256_v1(self.payload.to_json_obj()) != self.payload_sha256:
            raise ReviewContractError(
                "Event payload digest does not match the payload.",
                code=ReviewContractErrorCodeV1.DIGEST_MISMATCH,
            )
        _validate_event_payload(self.event_type, self.payload.to_json_obj())

    @classmethod
    def from_json_obj(cls, value: object) -> ReviewEventV1:
        payload = _require_exact_object(value, expected=_EVENT_FIELDS, field_name="reviewEvent")
        _require_schema_version(payload["schemaVersion"])
        _require_literal(payload["kind"], expected="reviewEvent", field_name="kind")
        _require_literal(
            payload["contractId"],
            expected=HARNESS_REVIEW_CONTRACT_ID,
            field_name="contractId",
        )
        return cls(
            event_id=_require_identifier(payload["eventId"], field_name="eventId"),
            run_id=_require_identifier(payload["runId"], field_name="runId"),
            sequence=_require_non_negative_int(payload["sequence"], field_name="sequence"),
            event_type=_require_enum(
                ReviewEventTypeV1,
                payload["eventType"],
                field_name="eventType",
                unknown_code=ReviewContractErrorCodeV1.UNKNOWN_EVENT,
            ),
            previous_event_sha256=_require_optional_sha256(
                payload["previousEventSha256"],
                field_name="previousEventSha256",
            ),
            payload=freeze_json_object_v1(payload["payload"]),
            payload_sha256=_require_sha256(
                payload["payloadSha256"],
                field_name="payloadSha256",
            ),
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": "reviewEvent",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "eventId": self.event_id,
            "runId": self.run_id,
            "sequence": self.sequence,
            "eventType": self.event_type.value,
            "previousEventSha256": self.previous_event_sha256,
            "payload": self.payload.to_json_obj(),
            "payloadSha256": self.payload_sha256,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class PageCursorV1:
    """A page position bound to one immutable revision and digest."""

    subject_id: str
    revision_id: str
    revision_sha256: str
    after_index: int
    after_item_sha256: str
    page_size: int

    def __post_init__(self) -> None:
        _require_identifier(self.subject_id, field_name="subject_id")
        _require_identifier(self.revision_id, field_name="revision_id")
        _require_sha256(self.revision_sha256, field_name="revision_sha256")
        _require_non_negative_int(self.after_index, field_name="after_index")
        _require_sha256(self.after_item_sha256, field_name="after_item_sha256")
        page_size = _require_positive_int(self.page_size, field_name="page_size")
        if page_size > 1_000:
            raise ReviewContractError("page_size exceeds the alpha page limit.")

    @classmethod
    def from_json_obj(cls, value: object) -> PageCursorV1:
        payload = _require_exact_object(value, expected=_CURSOR_FIELDS, field_name="pageCursor")
        _require_schema_version(payload["schemaVersion"])
        _require_literal(payload["kind"], expected="pageCursor", field_name="kind")
        _require_literal(
            payload["contractId"],
            expected=HARNESS_REVIEW_CONTRACT_ID,
            field_name="contractId",
        )
        return cls(
            subject_id=_require_identifier(payload["subjectId"], field_name="subjectId"),
            revision_id=_require_identifier(payload["revisionId"], field_name="revisionId"),
            revision_sha256=_require_sha256(
                payload["revisionSha256"],
                field_name="revisionSha256",
            ),
            after_index=_require_non_negative_int(
                payload["afterIndex"],
                field_name="afterIndex",
            ),
            after_item_sha256=_require_sha256(
                payload["afterItemSha256"],
                field_name="afterItemSha256",
            ),
            page_size=_require_positive_int(payload["pageSize"], field_name="pageSize"),
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": "pageCursor",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "subjectId": self.subject_id,
            "revisionId": self.revision_id,
            "revisionSha256": self.revision_sha256,
            "afterIndex": self.after_index,
            "afterItemSha256": self.after_item_sha256,
            "pageSize": self.page_size,
        }

    def require_head(self, *, revision_id: str, revision_sha256: str) -> None:
        """Reject a cursor if either immutable page binding changed."""

        _require_identifier(revision_id, field_name="revision_id")
        _require_sha256(revision_sha256, field_name="revision_sha256")
        if self.revision_id != revision_id or self.revision_sha256 != revision_sha256:
            raise ReviewContractError(
                "Page cursor is bound to stale evidence.",
                code=ReviewContractErrorCodeV1.STALE_EVIDENCE,
            )

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class ReviewStartV1:
    """Typed view of a payload-bound ``review.start`` command."""

    command: ReviewCommandV1

    def __post_init__(self) -> None:
        _require_command_method(self.command, ReviewMethodV1.REVIEW_START)
        _review_start_values(self.command)

    @classmethod
    def from_json_obj(cls, value: object) -> ReviewStartV1:
        return cls(ReviewCommandV1.from_json_obj(value))

    @property
    def question(self) -> str:
        return cast(str, self.command.payload.to_json_obj()["question"])

    @property
    def evidence_roots(self) -> tuple[tuple[str, str], ...]:
        return _review_start_values(self.command)

    @property
    def clarification_mode(self) -> str:
        return cast(str, self.command.payload.to_json_obj()["clarificationMode"])

    @property
    def evaluator_suite_id(self) -> str | None:
        return cast(str | None, self.command.payload.to_json_obj()["evaluatorSuiteId"])

    @property
    def parent_run_id(self) -> str | None:
        value = self.command.payload.to_json_obj().get("parentRunId")
        return cast(str | None, value)

    @property
    def run_admission_seed_sha256(self) -> str | None:
        value = self.command.payload.to_json_obj().get("runAdmissionSeedSha256")
        return cast(str | None, value)

    def to_json_obj(self) -> dict[str, JsonValue]:
        return self.command.to_json_obj()


@dataclass(frozen=True, slots=True)
class ReviewContinueV1:
    """Typed view of a revalidated successor-run command."""

    command: ReviewCommandV1

    def __post_init__(self) -> None:
        _require_command_method(self.command, ReviewMethodV1.REVIEW_CONTINUE)
        _review_continue_values(self.command)

    @classmethod
    def from_json_obj(cls, value: object) -> ReviewContinueV1:
        return cls(ReviewCommandV1.from_json_obj(value))

    @property
    def prior_run_id(self) -> str:
        return cast(str, self.command.payload.to_json_obj()["priorRunId"])

    @property
    def question_resolution_id(self) -> str:
        return cast(str, self.command.payload.to_json_obj()["questionResolutionId"])

    def to_json_obj(self) -> dict[str, JsonValue]:
        return self.command.to_json_obj()


@dataclass(frozen=True, slots=True)
class ReviewCancelV1:
    """Typed view of an actor-bound cancellation request."""

    command: ReviewCommandV1

    def __post_init__(self) -> None:
        _require_command_method(self.command, ReviewMethodV1.REVIEW_CANCEL)
        _review_cancel_values(self.command)

    @classmethod
    def from_json_obj(cls, value: object) -> ReviewCancelV1:
        return cls(ReviewCommandV1.from_json_obj(value))

    @property
    def actor_id(self) -> str:
        return _review_cancel_values(self.command)[0]

    @property
    def expected_event_head(self) -> int:
        return _review_cancel_values(self.command)[1]

    def to_json_obj(self) -> dict[str, JsonValue]:
        return self.command.to_json_obj()


@dataclass(frozen=True, slots=True)
class ReplayPageV1:
    """One gap-free event page bound to an immutable event head."""

    run_id: str
    event_head_sha256: str
    page_size: int
    request_cursor: PageCursorV1 | None
    events: tuple[ReviewEventV1, ...]
    next_cursor: PageCursorV1 | None
    terminal: bool

    def __post_init__(self) -> None:
        _require_identifier(self.run_id, field_name="run_id")
        _require_sha256(self.event_head_sha256, field_name="event_head_sha256")
        _require_page_size(self.page_size, field_name="page_size")
        if type(self.events) is not tuple:
            raise ReviewContractError("Replay events must be an immutable tuple.")
        if not self.events:
            raise ReviewContractError("Replay pages must contain at least one event.")
        if len(self.events) > self.page_size:
            raise ReviewContractError("Replay events exceed the requested page size.")
        if type(self.terminal) is not bool:
            raise ReviewContractError("terminal must be a boolean.")
        if self.request_cursor is not None and type(self.request_cursor) is not PageCursorV1:
            raise ReviewContractError("Replay request cursor must be a page cursor or null.")
        expected_first = 0 if self.request_cursor is None else self.request_cursor.after_index + 1
        if self.events[0].sequence != expected_first:
            raise ReviewContractError("Replay first event does not follow the request cursor.")
        previous_sequence: int | None = None
        previous_digest = (
            None if self.request_cursor is None else self.request_cursor.after_item_sha256
        )
        terminal_indexes: list[int] = []
        for index, event in enumerate(self.events):
            if type(event) is not ReviewEventV1 or event.run_id != self.run_id:
                raise ReviewContractError("Replay events must belong to one run.")
            if previous_sequence is not None and event.sequence != previous_sequence + 1:
                raise ReviewContractError("Replay event sequences must be contiguous.")
            if event.previous_event_sha256 != previous_digest:
                raise ReviewContractError(
                    "Replay event does not reference the previous event digest."
                )
            previous_sequence = event.sequence
            previous_digest = event.digest
            if event.event_type is ReviewEventTypeV1.TERMINAL:
                terminal_indexes.append(index)
        if terminal_indexes and terminal_indexes != [len(self.events) - 1]:
            raise ReviewContractError("The terminal event must be last in a replay page.")
        if self.terminal != bool(terminal_indexes):
            raise ReviewContractError("Replay terminal state does not match its events.")
        if self.terminal and self.next_cursor is not None:
            raise ReviewContractError("A terminal replay page cannot carry a next cursor.")
        if not self.terminal and self.next_cursor is None:
            raise ReviewContractError("A non-terminal replay page requires a next cursor.")
        for cursor_name, cursor in (
            ("request", self.request_cursor),
            ("next", self.next_cursor),
        ):
            if cursor is None:
                continue
            if type(cursor) is not PageCursorV1 or cursor.subject_id != self.run_id:
                raise ReviewContractError("Replay cursor must belong to the same run.")
            if cursor.revision_sha256 != self.event_head_sha256:
                raise ReviewContractError(
                    f"Replay {cursor_name} cursor is bound to stale evidence.",
                    code=ReviewContractErrorCodeV1.STALE_EVIDENCE,
                )
            if cursor.page_size != self.page_size:
                raise ReviewContractError(
                    f"Replay {cursor_name} cursor does not match the requested page size.",
                    code=ReviewContractErrorCodeV1.STALE_EVIDENCE,
                )
        if self.next_cursor is not None:
            if self.next_cursor.after_index != self.events[-1].sequence:
                raise ReviewContractError("Replay next cursor does not identify the last event.")
            if self.next_cursor.after_item_sha256 != self.events[-1].digest:
                raise ReviewContractError(
                    "Replay next cursor does not authenticate the last event."
                )
        if (
            self.request_cursor is not None
            and self.next_cursor is not None
            and (
                self.request_cursor.revision_id != self.next_cursor.revision_id
                or self.request_cursor.page_size != self.next_cursor.page_size
            )
        ):
            raise ReviewContractError(
                "Replay cursors must bind the same event revision and page size.",
                code=ReviewContractErrorCodeV1.STALE_EVIDENCE,
            )
        if self.terminal and self.events[-1].digest != self.event_head_sha256:
            raise ReviewContractError("Replay terminal event does not match the event head digest.")

    @classmethod
    def from_json_obj(cls, value: object) -> ReplayPageV1:
        payload = _require_exact_object(
            value, expected=_REPLAY_PAGE_FIELDS, field_name="replayPage"
        )
        _require_schema_version(payload["schemaVersion"])
        _require_literal(payload["kind"], expected="replayPage", field_name="kind")
        _require_literal(
            payload["contractId"],
            expected=HARNESS_REVIEW_CONTRACT_ID,
            field_name="contractId",
        )
        raw_events = payload["events"]
        if type(raw_events) is not list:
            raise ReviewContractError("events must be a JSON array.")
        raw_request_cursor = payload["requestCursor"]
        if raw_request_cursor is not None and type(raw_request_cursor) is not dict:
            raise ReviewContractError("requestCursor must be a page cursor or null.")
        raw_next_cursor = payload["nextCursor"]
        if raw_next_cursor is not None and type(raw_next_cursor) is not dict:
            raise ReviewContractError("nextCursor must be a page cursor or null.")
        terminal = payload["terminal"]
        if type(terminal) is not bool:
            raise ReviewContractError("terminal must be a boolean.")
        return cls(
            run_id=_require_identifier(payload["runId"], field_name="runId"),
            event_head_sha256=_require_sha256(
                payload["eventHeadSha256"],
                field_name="eventHeadSha256",
            ),
            page_size=_require_page_size(payload["pageSize"], field_name="pageSize"),
            request_cursor=(
                None
                if raw_request_cursor is None
                else PageCursorV1.from_json_obj(raw_request_cursor)
            ),
            events=tuple(ReviewEventV1.from_json_obj(event) for event in raw_events),
            next_cursor=(
                None if raw_next_cursor is None else PageCursorV1.from_json_obj(raw_next_cursor)
            ),
            terminal=terminal,
        )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": "replayPage",
            "contractId": HARNESS_REVIEW_CONTRACT_ID,
            "runId": self.run_id,
            "eventHeadSha256": self.event_head_sha256,
            "pageSize": self.page_size,
            "requestCursor": (
                None if self.request_cursor is None else self.request_cursor.to_json_obj()
            ),
            "events": [event.to_json_obj() for event in self.events],
            "nextCursor": None if self.next_cursor is None else self.next_cursor.to_json_obj(),
            "terminal": self.terminal,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


def _validate_event_payload(
    event_type: ReviewEventTypeV1,
    payload: dict[str, JsonValue],
) -> None:
    if payload.get("schemaVersion") == 2:
        _validate_responses_event_payload_v2(event_type, payload)
        return
    route_fields = frozenset(
        {
            "routeDecisionSha256",
            "routePolicySha256",
            "pricingAuthoritySha256",
            "providerId",
            "modelId",
        }
    )
    route_bound_event_types = frozenset(
        {
            ReviewEventTypeV1.RUN_STARTED,
            ReviewEventTypeV1.MODEL_REQUESTED,
            ReviewEventTypeV1.MODEL_COMPLETED,
            ReviewEventTypeV1.TOOL_COMPLETED,
        }
    )
    fields_by_event = {
        ReviewEventTypeV1.RUN_STARTED: frozenset(
            {"grantSha256", "contextSha256", "egressPolicySha256"}
        ),
        ReviewEventTypeV1.MODEL_REQUESTED: frozenset(
            {"providerCallId", "providerId", "modelId", "requestSha256"}
        ),
        ReviewEventTypeV1.MODEL_COMPLETED: frozenset(
            {"providerCallId", "responseSha256", "inputTokens", "outputTokens"}
        ),
        ReviewEventTypeV1.TOOL_REQUESTED: frozenset(
            {"toolCallId", "toolName", "argumentsSha256", "grantSha256"}
        ),
        ReviewEventTypeV1.TOOL_COMPLETED: frozenset(
            {
                "toolCallId",
                "toolName",
                "resultSha256",
                "evidenceVersionId",
                "projectionRevisionId",
            }
        ),
        ReviewEventTypeV1.TOOL_FAILED: frozenset({"toolCallId", "toolName", "errorCode"}),
        ReviewEventTypeV1.CITATION_VALIDATION: frozenset(
            {"citationSha256", "resolutionState", "resolutionSha256"}
        ),
        ReviewEventTypeV1.CLARIFICATION_REQUIRED: frozenset(
            {"questionId", "questionSha256", "materialityCode"}
        ),
        ReviewEventTypeV1.CANCELLATION_REQUESTED: frozenset({"actorId", "expectedEventHead"}),
        ReviewEventTypeV1.TERMINAL: frozenset({"outcome", "terminalResultSha256", "receiptSha256"}),
    }
    expected_event_fields = fields_by_event[event_type]
    if event_type in route_bound_event_types:
        routed_event_fields = expected_event_fields | route_fields
        if frozenset(payload) not in (expected_event_fields, routed_event_fields):
            _require_exact_object(
                payload,
                expected=expected_event_fields,
                field_name=f"{event_type.value} payload",
            )
    else:
        _require_exact_object(
            payload,
            expected=expected_event_fields,
            field_name=f"{event_type.value} payload",
        )
    if "routeDecisionSha256" in payload:
        for field_name in (
            "routeDecisionSha256",
            "routePolicySha256",
            "pricingAuthoritySha256",
        ):
            _require_sha256(payload[field_name], field_name=field_name)
        for field_name in ("providerId", "modelId"):
            _require_identifier(payload[field_name], field_name=field_name)
    if event_type is ReviewEventTypeV1.RUN_STARTED:
        for field_name in ("grantSha256", "contextSha256", "egressPolicySha256"):
            _require_sha256(payload[field_name], field_name=field_name)
    elif event_type is ReviewEventTypeV1.MODEL_REQUESTED:
        for field_name in ("providerCallId", "providerId", "modelId"):
            _require_identifier(payload[field_name], field_name=field_name)
        _require_sha256(payload["requestSha256"], field_name="requestSha256")
    elif event_type is ReviewEventTypeV1.MODEL_COMPLETED:
        _require_identifier(payload["providerCallId"], field_name="providerCallId")
        _require_sha256(payload["responseSha256"], field_name="responseSha256")
        _require_non_negative_int(payload["inputTokens"], field_name="inputTokens")
        _require_non_negative_int(payload["outputTokens"], field_name="outputTokens")
    elif event_type is ReviewEventTypeV1.TOOL_REQUESTED:
        for field_name in ("toolCallId", "toolName"):
            _require_identifier(payload[field_name], field_name=field_name)
        for field_name in ("argumentsSha256", "grantSha256"):
            _require_sha256(payload[field_name], field_name=field_name)
    elif event_type is ReviewEventTypeV1.TOOL_COMPLETED:
        for field_name in (
            "toolCallId",
            "toolName",
            "evidenceVersionId",
            "projectionRevisionId",
        ):
            _require_identifier(payload[field_name], field_name=field_name)
        _require_sha256(payload["resultSha256"], field_name="resultSha256")
    elif event_type is ReviewEventTypeV1.TOOL_FAILED:
        for field_name in ("toolCallId", "toolName", "errorCode"):
            _require_identifier(payload[field_name], field_name=field_name)
    elif event_type is ReviewEventTypeV1.CITATION_VALIDATION:
        _require_sha256(payload["citationSha256"], field_name="citationSha256")
        _require_enum(
            CitationResolutionStateV1,
            payload["resolutionState"],
            field_name="resolutionState",
            unknown_code=ReviewContractErrorCodeV1.INVALID_VALUE,
        )
        _require_sha256(payload["resolutionSha256"], field_name="resolutionSha256")
    elif event_type is ReviewEventTypeV1.CLARIFICATION_REQUIRED:
        for field_name in ("questionId", "materialityCode"):
            _require_identifier(payload[field_name], field_name=field_name)
        _require_sha256(payload["questionSha256"], field_name="questionSha256")
    elif event_type is ReviewEventTypeV1.CANCELLATION_REQUESTED:
        _require_identifier(payload["actorId"], field_name="actorId")
        _require_non_negative_int(payload["expectedEventHead"], field_name="expectedEventHead")
    else:
        assert event_type is ReviewEventTypeV1.TERMINAL
        _require_enum(
            TerminalOutcomeV1,
            payload["outcome"],
            field_name="outcome",
            unknown_code=ReviewContractErrorCodeV1.INVALID_VALUE,
        )
        for field_name in ("terminalResultSha256", "receiptSha256"):
            _require_sha256(payload[field_name], field_name=field_name)


def _validate_responses_event_payload_v2(
    event_type: ReviewEventTypeV1,
    payload: dict[str, JsonValue],
) -> None:
    fields_by_event = {
        ReviewEventTypeV1.MODEL_REQUESTED: frozenset(
            {
                "schemaVersion",
                "providerId",
                "modelId",
                "providerProtocolId",
                "reasoningEffort",
                "routeDecisionSha256",
                "requestSha256",
                "physicalRequestSha256",
            }
        ),
        ReviewEventTypeV1.MODEL_COMPLETED: frozenset(
            {
                "schemaVersion",
                "providerId",
                "modelId",
                "providerProtocolId",
                "reasoningEffort",
                "rawResponseSha256",
                "continuationSha256",
                "outputItemCount",
                "toolCallCount",
                "usage",
                "failureCode",
            }
        ),
        ReviewEventTypeV1.TOOL_COMPLETED: frozenset(
            {
                "schemaVersion",
                "toolReference",
                "toolName",
                "outputOrdinal",
                "status",
                "outputSha256",
            }
        ),
        ReviewEventTypeV1.TERMINAL: frozenset(
            {
                "schemaVersion",
                "providerId",
                "modelId",
                "providerProtocolId",
                "reasoningEffort",
                "terminalOutcome",
                "providerCallState",
                "failureCode",
                "receiptSha256",
            }
        ),
    }
    expected = fields_by_event.get(event_type)
    if expected is None:
        raise ReviewContractError("schema-version-2 event type is invalid.")
    _require_exact_object(payload, expected=expected, field_name=f"{event_type.value} payload")
    if payload["schemaVersion"] != 2:
        raise ReviewContractError("schema-version-2 event header is invalid.")
    if event_type is not ReviewEventTypeV1.TOOL_COMPLETED and (
        payload["providerId"] != "openai"
        or payload["modelId"] not in {"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"}
        or payload["providerProtocolId"] != "openai.responses.v1"
        or payload["reasoningEffort"] != "medium"
    ):
        raise ReviewContractError("Responses event route authority is invalid.")
    if event_type is ReviewEventTypeV1.MODEL_REQUESTED:
        for field_name in (
            "routeDecisionSha256",
            "requestSha256",
            "physicalRequestSha256",
        ):
            _require_sha256(payload[field_name], field_name=field_name)
        return
    failure_code = payload.get("failureCode")
    if failure_code is not None and failure_code not in {
        "provider_protocol_substitution",
        "invalid_response",
        "provider_response_incomplete",
        "provider_response_item_invalid",
        "provider_continuation_invalid",
    }:
        raise ReviewContractError("Responses event failure code is invalid.")
    if event_type is ReviewEventTypeV1.MODEL_COMPLETED:
        raw_sha256 = payload["rawResponseSha256"]
        continuation_sha256 = payload["continuationSha256"]
        if raw_sha256 is not None:
            _require_sha256(raw_sha256, field_name="rawResponseSha256")
        if continuation_sha256 is not None:
            _require_sha256(continuation_sha256, field_name="continuationSha256")
        for field_name in ("outputItemCount", "toolCallCount"):
            _require_non_negative_int(payload[field_name], field_name=field_name)
        if continuation_sha256 is not None and raw_sha256 is None:
            raise ReviewContractError("Responses event authority prefix is invalid.")
        if failure_code is None and (raw_sha256 is None or continuation_sha256 is None):
            raise ReviewContractError("Responses event authority prefix is invalid.")
        usage = payload["usage"]
        if type(usage) is not dict:
            raise ReviewContractError("Responses event usage is invalid.")
        _require_responses_event_usage_v2(usage)
        return
    if event_type is ReviewEventTypeV1.TOOL_COMPLETED:
        _require_identifier(payload["toolReference"], field_name="toolReference")
        _require_identifier(payload["toolName"], field_name="toolName")
        _require_non_negative_int(payload["outputOrdinal"], field_name="outputOrdinal")
        if payload["status"] not in {"succeeded", "failed"}:
            raise ReviewContractError("Responses tool event status is invalid.")
        _require_sha256(payload["outputSha256"], field_name="outputSha256")
        return
    _require_enum(
        TerminalOutcomeV1,
        payload["terminalOutcome"],
        field_name="terminalOutcome",
        unknown_code=ReviewContractErrorCodeV1.INVALID_VALUE,
    )
    if payload["providerCallState"] not in {
        "not_requested",
        "blocked_preflight",
        "sent",
        "completed",
        "outcome_unknown",
    }:
        raise ReviewContractError("Responses terminal call state is invalid.")
    _require_sha256(payload["receiptSha256"], field_name="receiptSha256")


def _require_responses_event_usage_v2(usage: dict[str, JsonValue]) -> None:
    expected = frozenset(
        {
            "inputTokens",
            "cachedInputTokens",
            "cacheWriteTokens",
            "outputTokens",
            "reasoningTokens",
            "totalTokens",
        }
    )
    _require_exact_object(usage, expected=expected, field_name="Responses event usage")
    for field_name in (
        "inputTokens",
        "cachedInputTokens",
        "outputTokens",
        "reasoningTokens",
        "totalTokens",
    ):
        _require_non_negative_int(usage[field_name], field_name=field_name)
    cache_write = usage["cacheWriteTokens"]
    if cache_write != "not_reported":
        _require_non_negative_int(cache_write, field_name="cacheWriteTokens")
    if (
        cast(int, usage["cachedInputTokens"]) > cast(int, usage["inputTokens"])
        or cast(int, usage["reasoningTokens"]) > cast(int, usage["outputTokens"])
        or cast(int, usage["totalTokens"])
        != cast(int, usage["inputTokens"]) + cast(int, usage["outputTokens"])
    ):
        raise ReviewContractError("Responses event usage is incoherent.")


def _validate_command_payload(method: ReviewMethodV1, payload: dict[str, JsonValue]) -> None:
    fields_by_method = {
        ReviewMethodV1.DOCUMENT_IMPORT: frozenset({"sourceSelectionToken", "importProfileId"}),
        ReviewMethodV1.EVIDENCE_GET_TREE: frozenset(
            {
                "evidenceVersionId",
                "structureRevisionId",
                "structureSha256",
                "cursor",
                "pageSize",
            }
        ),
        ReviewMethodV1.EVIDENCE_GET_PROJECTION: frozenset(
            {"projectionRevisionId", "projectionSha256", "cursor", "pageSize"}
        ),
        ReviewMethodV1.REVIEW_START: frozenset(
            {
                "question",
                "evidenceRoots",
                "grantId",
                "grantSha256",
                "contextSha256",
                "egressPolicySha256",
                "limitsSha256",
                "clarificationMode",
                "evaluatorSuiteId",
            }
        ),
        ReviewMethodV1.REVIEW_CONTINUE: frozenset(
            {
                "priorRunId",
                "questionResolutionId",
                "expectedEvidenceSha256",
                "expectedContextSha256",
                "expectedGrantSha256",
                "expectedEgressPolicySha256",
            }
        ),
        ReviewMethodV1.REVIEW_GET: frozenset({"runId"}),
        ReviewMethodV1.REVIEW_CANCEL: frozenset({"runId", "actorId", "expectedEventHead"}),
        ReviewMethodV1.CITATION_RESOLVE: frozenset({"runId", "citationSha256", "grantSha256"}),
        ReviewMethodV1.EVENTS_REPLAY: frozenset({"runId", "cursor", "pageSize"}),
    }
    expected = fields_by_method.get(method)
    if method is ReviewMethodV1.REVIEW_START and expected is not None:
        routed = expected | frozenset({"parentRunId", "runAdmissionSeedSha256"})
        if frozenset(payload) not in (expected, routed):
            _require_exact_object(payload, expected=expected, field_name=method.value)
    elif expected is not None:
        _require_exact_object(payload, expected=expected, field_name=method.value)
    if method is ReviewMethodV1.DOCUMENT_IMPORT:
        _require_identifier(payload["sourceSelectionToken"], field_name="sourceSelectionToken")
        _require_identifier(payload["importProfileId"], field_name="importProfileId")
    elif method is ReviewMethodV1.EVIDENCE_GET_TREE:
        _require_identifier(payload["evidenceVersionId"], field_name="evidenceVersionId")
        revision_id = _require_identifier(
            payload["structureRevisionId"],
            field_name="structureRevisionId",
        )
        revision_sha256 = _require_sha256(
            payload["structureSha256"],
            field_name="structureSha256",
        )
        _validate_page_request(
            payload,
            subject_id=cast(str, payload["evidenceVersionId"]),
            revision_id=revision_id,
            revision_sha256=revision_sha256,
        )
    elif method is ReviewMethodV1.EVIDENCE_GET_PROJECTION:
        revision_id = _require_identifier(
            payload["projectionRevisionId"],
            field_name="projectionRevisionId",
        )
        revision_sha256 = _require_sha256(
            payload["projectionSha256"],
            field_name="projectionSha256",
        )
        _validate_page_request(
            payload,
            subject_id=revision_id,
            revision_id=revision_id,
            revision_sha256=revision_sha256,
        )
    elif method is ReviewMethodV1.REVIEW_START:
        _validate_review_start_payload(payload)
    elif method is ReviewMethodV1.REVIEW_CONTINUE:
        for field_name in ("priorRunId", "questionResolutionId"):
            _require_identifier(payload[field_name], field_name=field_name)
        for field_name in (
            "expectedEvidenceSha256",
            "expectedContextSha256",
            "expectedGrantSha256",
            "expectedEgressPolicySha256",
        ):
            _require_sha256(payload[field_name], field_name=field_name)
    elif method is ReviewMethodV1.REVIEW_GET:
        _require_identifier(payload["runId"], field_name="runId")
    elif method is ReviewMethodV1.REVIEW_CANCEL:
        _require_identifier(payload["runId"], field_name="runId")
        _require_identifier(payload["actorId"], field_name="actorId")
        _require_non_negative_int(payload["expectedEventHead"], field_name="expectedEventHead")
    elif method is ReviewMethodV1.CITATION_RESOLVE:
        _require_identifier(payload["runId"], field_name="runId")
        _require_sha256(payload["citationSha256"], field_name="citationSha256")
        _require_sha256(payload["grantSha256"], field_name="grantSha256")
    elif method is ReviewMethodV1.EVENTS_REPLAY:
        run_id = _require_identifier(payload["runId"], field_name="runId")
        page_size = _require_page_size(payload["pageSize"], field_name="pageSize")
        raw_cursor = payload["cursor"]
        if raw_cursor is not None:
            cursor = PageCursorV1.from_json_obj(raw_cursor)
            if cursor.subject_id != run_id or cursor.page_size != page_size:
                raise ReviewContractError(
                    "Replay cursor does not match the requested run or page size.",
                    code=ReviewContractErrorCodeV1.STALE_EVIDENCE,
                )


def _validate_page_request(
    payload: dict[str, JsonValue],
    *,
    subject_id: str,
    revision_id: str,
    revision_sha256: str,
) -> None:
    page_size = _require_page_size(payload["pageSize"], field_name="pageSize")
    raw_cursor = payload["cursor"]
    if raw_cursor is None:
        return
    cursor = PageCursorV1.from_json_obj(raw_cursor)
    cursor.require_head(revision_id=revision_id, revision_sha256=revision_sha256)
    if cursor.subject_id != subject_id or cursor.page_size != page_size:
        raise ReviewContractError(
            "Page cursor does not match the requested subject or page size.",
            code=ReviewContractErrorCodeV1.STALE_EVIDENCE,
        )


def _require_page_size(value: object, *, field_name: str) -> int:
    page_size = _require_positive_int(value, field_name=field_name)
    if page_size > 1_000:
        raise ReviewContractError(f"{field_name} exceeds the alpha page limit.")
    return page_size


def _require_command_method(command: object, expected: ReviewMethodV1) -> ReviewCommandV1:
    if type(command) is not ReviewCommandV1 or command.method is not expected:
        raise ReviewContractError(f"Expected a {expected.value} command.")
    return command


def _review_start_values(command: ReviewCommandV1) -> tuple[tuple[str, str], ...]:
    return _validate_review_start_payload(command.payload.to_json_obj())


def _validate_review_start_payload(
    payload: dict[str, JsonValue],
) -> tuple[tuple[str, str], ...]:
    question = _require_nfc_string(payload["question"], field_name="question")
    if not question.strip():
        raise ReviewContractError("question must not be blank.")
    raw_roots = payload["evidenceRoots"]
    if type(raw_roots) is not list or not raw_roots:
        raise ReviewContractError("evidenceRoots must be a non-empty JSON array.")
    roots: list[tuple[str, str]] = []
    for raw_root in raw_roots:
        root = _require_exact_object(
            raw_root,
            expected=frozenset({"evidenceVersionId", "stableId"}),
            field_name="evidenceRoot",
        )
        roots.append(
            (
                _require_identifier(
                    root["evidenceVersionId"],
                    field_name="evidenceVersionId",
                ),
                _require_identifier(root["stableId"], field_name="stableId"),
            )
        )
    if len(roots) != len(set(roots)):
        raise ReviewContractError("evidenceRoots contains a duplicate root.")
    _require_identifier(payload["grantId"], field_name="grantId")
    for field_name in (
        "grantSha256",
        "contextSha256",
        "egressPolicySha256",
        "limitsSha256",
    ):
        _require_sha256(payload[field_name], field_name=field_name)
    if payload["clarificationMode"] not in (
        "autonomous",
        "ask_when_material",
        "collaborative",
    ):
        raise ReviewContractError("clarificationMode contains an unknown value.")
    evaluator_suite_id = payload["evaluatorSuiteId"]
    if evaluator_suite_id is not None:
        _require_identifier(evaluator_suite_id, field_name="evaluatorSuiteId")
    parent_run_id = payload.get("parentRunId")
    run_admission_seed_sha256 = payload.get("runAdmissionSeedSha256")
    if parent_run_id is not None or run_admission_seed_sha256 is not None:
        parent = _require_identifier(parent_run_id, field_name="parentRunId")
        seed = _require_sha256(
            run_admission_seed_sha256,
            field_name="runAdmissionSeedSha256",
        )
        if parent != f"run-{seed[:32]}":
            raise ReviewContractError(
                "parentRunId does not match the run-admission seed.",
                code=ReviewContractErrorCodeV1.DIGEST_MISMATCH,
            )
    return tuple(roots)


def _review_continue_values(command: ReviewCommandV1) -> tuple[str, str]:
    payload = command.payload.to_json_obj()
    prior_run_id = _require_identifier(payload["priorRunId"], field_name="priorRunId")
    resolution_id = _require_identifier(
        payload["questionResolutionId"],
        field_name="questionResolutionId",
    )
    return prior_run_id, resolution_id


def _review_cancel_values(command: ReviewCommandV1) -> tuple[str, int]:
    payload = command.payload.to_json_obj()
    actor_id = _require_identifier(payload["actorId"], field_name="actorId")
    event_head = _require_non_negative_int(
        payload["expectedEventHead"],
        field_name="expectedEventHead",
    )
    return actor_id, event_head


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def _require_frozen_json_value(value: object) -> None:
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) in (FrozenJsonArrayV1, FrozenJsonObjectV1):
        return
    raise ReviewContractError("Frozen JSON contains an unsupported value.")


def _require_nfc_string(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise ReviewContractError(f"{field_name} must be a string.")
    if unicodedata.normalize("NFC", value) != value:
        raise ReviewContractError(
            f"{field_name} must use NFC Unicode.",
            code=ReviewContractErrorCodeV1.NON_NFC,
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ReviewContractError(f"{field_name} contains invalid Unicode.") from error
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise ReviewContractError(f"{field_name} exceeds its byte limit.")
    return value


def _require_identifier(value: object, *, field_name: str) -> str:
    text = _require_nfc_string(value, field_name=field_name)
    if len(text.encode("utf-8")) > MAX_IDENTIFIER_BYTES or _IDENTIFIER.fullmatch(text) is None:
        raise ReviewContractError(
            f"{field_name} must be a bounded opaque identifier.",
            code=ReviewContractErrorCodeV1.INVALID_IDENTIFIER,
        )
    return text


def _require_sha256(value: object, *, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ReviewContractError(f"{field_name} must be a lowercase SHA-256 digest.")
    return value


def _require_optional_sha256(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, field_name=field_name)


def _require_schema_version(value: object) -> None:
    if type(value) is not int or value != 1:
        raise ReviewContractError(
            "schemaVersion must equal 1.",
            code=ReviewContractErrorCodeV1.VERSION_MISMATCH,
        )


def _require_literal(value: object, *, expected: str, field_name: str) -> None:
    if type(value) is not str or value != expected:
        raise ReviewContractError(f"{field_name} must equal {expected}.")


def _require_enum(
    enum_type: type[EnumV1],
    value: object,
    *,
    field_name: str,
    unknown_code: ReviewContractErrorCodeV1,
) -> EnumV1:
    if type(value) is not str:
        raise ReviewContractError(f"{field_name} must be a string enum value.")
    try:
        return enum_type(value)
    except ValueError:
        raise ReviewContractError(
            f"{field_name} contains an unknown enum value.",
            code=unknown_code,
        ) from None


def _require_exact_object(
    value: object,
    *,
    expected: frozenset[str],
    field_name: str,
) -> dict[str, JsonValue]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ReviewContractError(f"{field_name} must be a JSON object.")
    result = cast(dict[str, JsonValue], value)
    if frozenset(result) != expected:
        raise ReviewContractError(
            f"{field_name} has missing or unknown fields.",
            code=ReviewContractErrorCodeV1.UNKNOWN_FIELD,
        )
    return result


def _require_non_negative_int(value: object, *, field_name: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER:
        raise ReviewContractError(f"{field_name} must be a safe non-negative integer.")
    return value


def _require_positive_int(value: object, *, field_name: str) -> int:
    result = _require_non_negative_int(value, field_name=field_name)
    if result == 0:
        raise ReviewContractError(f"{field_name} must be positive.")
    return result


def _normalize_json(
    value: JsonValue,
    *,
    depth: int,
    count: list[int],
) -> JsonValue:
    if depth > MAX_CANONICAL_DEPTH:
        raise ReviewContractError("Canonical JSON exceeds the maximum depth.")
    count[0] += 1
    if count[0] > MAX_CANONICAL_VALUES:
        raise ReviewContractError("Canonical JSON exceeds the maximum value count.")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > MAX_SAFE_INTEGER:
            raise ReviewContractError(
                "Canonical JSON integer exceeds the safe integer range.",
                code=ReviewContractErrorCodeV1.UNSAFE_INTEGER,
            )
        return value
    if type(value) is str:
        return _require_nfc_string(value, field_name="JSON string")
    if type(value) is list:
        return [_normalize_json(item, depth=depth + 1, count=count) for item in value]
    if type(value) is dict:
        mapping = cast(dict[object, JsonValue], value)
        if any(type(key) is not str for key in mapping):
            raise ReviewContractError("Canonical JSON object keys must be strings.")
        normalized: dict[str, JsonValue] = {}
        for key in sorted(cast(list[str], list(mapping)), key=_utf16_sort_key):
            clean_key = _require_nfc_string(key, field_name="JSON object key")
            normalized[clean_key] = _normalize_json(
                mapping[key],
                depth=depth + 1,
                count=count,
            )
        return normalized
    if type(value) is float:
        raise ReviewContractError("Canonical JSON numbers must be safe integers.")
    raise ReviewContractError("Canonical JSON contains an unsupported value.")


def canonical_json_bytes_v1(value: JsonValue) -> bytes:
    """Return bounded deterministic JSON bytes for one alpha contract value."""

    normalized = _normalize_json(value, depth=0, count=[0])
    encoded = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise ReviewContractError("Canonical JSON exceeds the serialized byte limit.")
    return encoded


def canonical_json_sha256_v1(value: JsonValue) -> str:
    """Return the lowercase digest of canonical alpha-contract bytes."""

    return hashlib.sha256(canonical_json_bytes_v1(value)).hexdigest()


def _freeze_json_value(value: JsonValue) -> FrozenJsonValueV1:
    if value is None or type(value) in (bool, int, str):
        return cast(FrozenJsonScalarV1, value)
    if type(value) is list:
        return FrozenJsonArrayV1(tuple(_freeze_json_value(item) for item in value))
    if type(value) is dict:
        return FrozenJsonObjectV1(
            tuple(
                (key, _freeze_json_value(value[key])) for key in sorted(value, key=_utf16_sort_key)
            )
        )
    raise ReviewContractError("Canonical JSON contains an unsupported value.")


def freeze_json_object_v1(value: object) -> FrozenJsonObjectV1:
    """Validate and recursively freeze one JSON object."""

    if type(value) is not dict:
        raise ReviewContractError("JSON payload must be an object.")
    normalized = _normalize_json(cast(JsonValue, value), depth=0, count=[0])
    if type(normalized) is not dict:
        raise ReviewContractError("JSON payload must be an object.")
    frozen = _freeze_json_value(normalized)
    if type(frozen) is not FrozenJsonObjectV1:
        raise ReviewContractError("JSON payload must be an object.")
    return frozen


def thaw_json_value_v1(value: FrozenJsonValueV1) -> JsonValue:
    """Return a fresh mutable JSON projection from one frozen value."""

    if value is None or type(value) in (bool, int, str):
        return cast(FrozenJsonScalarV1, value)
    if type(value) is FrozenJsonArrayV1:
        return value.to_json_value()
    if type(value) is FrozenJsonObjectV1:
        return value.to_json_obj()
    raise ReviewContractError("Frozen JSON value is malformed.")


def _reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewContractError(
                "Canonical JSON contains a duplicate object member.",
                code=ReviewContractErrorCodeV1.DUPLICATE_MEMBER,
            )
        result[key] = value
    return result


def _reject_non_finite(_value: str) -> object:
    raise ReviewContractError(
        "Canonical JSON contains a non-finite number.",
        code=ReviewContractErrorCodeV1.NON_FINITE,
    )


def decode_canonical_json_object_v1(raw: bytes) -> dict[str, JsonValue]:
    """Decode strict JSON bytes and return their normalized object projection."""

    if type(raw) is not bytes:
        raise ReviewContractError("Canonical JSON input must be bytes.")
    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_non_finite,
        )
    except ReviewContractError:
        raise
    except (RecursionError, UnicodeDecodeError, ValueError) as error:
        raise ReviewContractError(
            "Canonical JSON bytes are malformed.",
            code=ReviewContractErrorCodeV1.MALFORMED_JSON,
        ) from error
    normalized = _normalize_json(cast(JsonValue, decoded), depth=0, count=[0])
    if type(normalized) is not dict:
        raise ReviewContractError("Canonical JSON root must be an object.")
    return normalized


def parse_review_wire_value_v1(
    value: object,
) -> ReviewCommandV1 | ReviewEventV1 | PageCursorV1 | ReplayPageV1:
    """Dispatch one private alpha wire object without importing domain or storage code."""

    if type(value) is not dict:
        raise ReviewContractError("Review wire value must be a JSON object.")
    kind = value.get("kind")
    if kind == "reviewCommand":
        return ReviewCommandV1.from_json_obj(value)
    if kind == "reviewEvent":
        return ReviewEventV1.from_json_obj(value)
    if kind == "pageCursor":
        return PageCursorV1.from_json_obj(value)
    if kind == "replayPage":
        return ReplayPageV1.from_json_obj(value)
    raise ReviewContractError(
        "Review wire value contains an unknown kind.",
        code=ReviewContractErrorCodeV1.UNKNOWN_FIELD,
    )
