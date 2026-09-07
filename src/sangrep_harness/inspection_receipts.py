from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass

from sangrep_harness.receipt_events import AgentRunEventRecord

TARGETED_INSPECTION_CLAIM_BOUNDARY = (
    "Targeted run only. This receipt does not assert corpus completeness, coverage, or "
    "generalized answer quality."
)


_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


_TERMINAL_EVENT_TYPES = frozenset({"tool_succeeded", "tool_failed"})


_SEARCH_TOOLS = frozenset({"search", "query_blocks"})


@dataclass(frozen=True)
class _RequestedTool:
    call_id: str
    tool: str
    arguments: dict[str, object]
    sequence: int


@dataclass(frozen=True)
class _TerminalTool:
    event: AgentRunEventRecord
    status: str
    returned_stable_ids: list[str]
    citable_anchor_effect: dict[str, object]
    duration_ms: int
    result_sha256: str
    error_code: str | None


class InspectionReceiptError(RuntimeError):
    """Raised when an immutable event trace cannot support a receipt."""


def build_targeted_inspection_receipt(
    events: Sequence[AgentRunEventRecord],
    *,
    provider: str,
    model: str,
    terminal_outcome: dict[str, object],
) -> dict[str, object]:
    """Build the exact v1 targeted receipt from one immutable run event stream.

    Receipt construction validates the private trace first, then projects only the
    small public allowlist. Raw tool bodies, provider state, prompts, and internal
    identifiers therefore never cross this boundary.
    """

    provider_name = _required_non_empty_string("provider", provider)
    model_name = _required_non_empty_string("model", model)
    ordered_events = _validate_event_stream(events)
    run_started = _one_event(ordered_events, "run_started")
    answer_validated = _one_event(ordered_events, "answer_validated")
    if run_started.sequence >= answer_validated.sequence:
        raise InspectionReceiptError("run_started must precede answer_validated.")

    projection_digest = _required_sha256(
        "run_started projectionDigest",
        run_started.payload.get("projectionDigest"),
    )
    granted_roots = _validated_granted_roots(run_started.payload.get("grantedRoots"))
    relevant_events = [
        event for event in ordered_events if event.sequence <= answer_validated.sequence
    ]
    requests, terminal_events = _pair_tool_events(relevant_events)

    searches: list[dict[str, object]] = []
    reads: list[dict[str, object]] = []
    tool_outcomes: list[dict[str, object]] = []
    accumulated_citable_ids: list[str] = []
    accumulated_citable_set: set[str] = set()

    for request in requests:
        terminal_event = terminal_events[request.call_id]
        terminal = _validate_terminal_tool(
            request,
            terminal_event,
            projection_digest=projection_digest,
            accumulated_citable_ids=accumulated_citable_ids,
            accumulated_citable_set=accumulated_citable_set,
        )
        if request.tool in _SEARCH_TOOLS:
            searches.append(_search_projection(request, terminal))
        if request.tool == "read_nodes":
            reads.append(_read_projection(request, terminal))
        tool_outcomes.append(
            {
                "callId": request.call_id,
                "tool": request.tool,
                "status": terminal.status,
                "requestSequence": request.sequence,
                "terminalSequence": terminal.event.sequence,
                "durationMs": terminal.duration_ms,
                "resultSha256": terminal.result_sha256,
                "citableAnchorEffect": terminal.citable_anchor_effect,
                "errorCode": terminal.error_code,
            }
        )

    validated_outcome = _validated_terminal_outcome(
        terminal_outcome,
        answer_event=answer_validated,
        accumulated_citable_ids=accumulated_citable_ids,
    )
    return {
        "schemaVersion": 1,
        "kind": "targeted_inspection",
        "intent": "targeted",
        "exhaustive": False,
        "provider": provider_name,
        "model": model_name,
        "projectionDigest": projection_digest,
        "grantedRoots": granted_roots,
        "searches": searches,
        "reads": reads,
        "toolOutcomes": tool_outcomes,
        "terminalOutcome": validated_outcome,
        "traceThroughSequence": answer_validated.sequence,
        "claimBoundary": TARGETED_INSPECTION_CLAIM_BOUNDARY,
    }


def _validate_event_stream(
    events: Sequence[AgentRunEventRecord],
) -> list[AgentRunEventRecord]:
    if not events:
        raise InspectionReceiptError("Receipt assembly requires a non-empty event trace.")
    ordered_events = list(events)
    if any(not isinstance(event, AgentRunEventRecord) for event in ordered_events):
        raise InspectionReceiptError("Receipt events must be AgentRunEventRecord values.")
    run_ids = {event.agent_run_id for event in ordered_events}
    if len(run_ids) != 1:
        raise InspectionReceiptError("Receipt events must belong to one agent run.")
    sequences = [event.sequence for event in ordered_events]
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
        raise InspectionReceiptError("Receipt event sequences must be unique and ordered.")
    return ordered_events


def _one_event(
    events: Sequence[AgentRunEventRecord],
    event_type: str,
) -> AgentRunEventRecord:
    matching = [event for event in events if event.event_type == event_type]
    if len(matching) != 1:
        raise InspectionReceiptError(
            f"Receipt trace must contain exactly one {event_type} event; found {len(matching)}."
        )
    return matching[0]


def _validated_granted_roots(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise InspectionReceiptError("run_started grantedRoots must be a non-empty list.")
    roots: list[dict[str, str]] = []
    seen_stable_ids: set[str] = set()
    for index, raw_root in enumerate(value):
        if not isinstance(raw_root, dict):
            raise InspectionReceiptError(f"grantedRoots[{index}] must be an object.")
        expected_keys = {"stableId", "sourceSha256", "parserVersion"}
        if set(raw_root) != expected_keys:
            raise InspectionReceiptError(
                f"grantedRoots[{index}] must contain only stableId, sourceSha256, and "
                "parserVersion."
            )
        stable_id = _required_non_empty_string(
            f"grantedRoots[{index}].stableId",
            raw_root.get("stableId"),
        )
        if stable_id in seen_stable_ids:
            raise InspectionReceiptError(f"Duplicate granted root stable ID {stable_id!r}.")
        seen_stable_ids.add(stable_id)
        roots.append(
            {
                "stableId": stable_id,
                "sourceSha256": _required_sha256(
                    f"grantedRoots[{index}].sourceSha256",
                    raw_root.get("sourceSha256"),
                ),
                "parserVersion": _required_non_empty_string(
                    f"grantedRoots[{index}].parserVersion",
                    raw_root.get("parserVersion"),
                ),
            }
        )
    return roots


def _pair_tool_events(
    events: Sequence[AgentRunEventRecord],
) -> tuple[list[_RequestedTool], dict[str, AgentRunEventRecord]]:
    requests: list[_RequestedTool] = []
    requests_by_id: dict[str, _RequestedTool] = {}
    terminal_events: dict[str, AgentRunEventRecord] = {}
    for event in events:
        if event.event_type == "tool_requested":
            call_id = _required_non_empty_string(
                "tool_requested callId",
                event.payload.get("callId"),
            )
            if call_id in requests_by_id:
                raise InspectionReceiptError(f"Trace contains duplicate tool request {call_id!r}.")
            tool = _required_non_empty_string(
                "tool_requested name",
                event.payload.get("name"),
            )
            arguments = event.payload.get("arguments")
            if not isinstance(arguments, dict):
                raise InspectionReceiptError(
                    f"Tool request {call_id!r} arguments must be an object."
                )
            request = _RequestedTool(
                call_id=call_id,
                tool=tool,
                arguments=arguments,
                sequence=event.sequence,
            )
            requests.append(request)
            requests_by_id[call_id] = request
            continue
        if event.event_type not in _TERMINAL_EVENT_TYPES:
            continue
        call_id = _required_non_empty_string(
            f"{event.event_type} callId",
            event.payload.get("callId"),
        )
        if call_id not in requests_by_id:
            raise InspectionReceiptError(f"Trace contains orphan terminal event for {call_id!r}.")
        if call_id in terminal_events:
            raise InspectionReceiptError(
                f"Trace contains duplicate terminal event for {call_id!r}."
            )
        if event.sequence <= requests_by_id[call_id].sequence:
            raise InspectionReceiptError(
                f"Terminal event for {call_id!r} must follow its tool request."
            )
        terminal_events[call_id] = event

    for request in requests:
        if request.call_id not in terminal_events:
            raise InspectionReceiptError(
                f"Tool request {request.call_id!r} is missing one terminal event."
            )
    return requests, terminal_events


def _validate_terminal_tool(
    request: _RequestedTool,
    event: AgentRunEventRecord,
    *,
    projection_digest: str,
    accumulated_citable_ids: list[str],
    accumulated_citable_set: set[str],
) -> _TerminalTool:
    payload = event.payload
    status = _required_non_empty_string("tool terminal status", payload.get("status"))
    expected_status = "succeeded" if event.event_type == "tool_succeeded" else "failed"
    call_id = _required_non_empty_string("tool terminal callId", payload.get("callId"))
    tool = _required_non_empty_string("tool terminal tool", payload.get("tool"))
    if call_id != request.call_id or tool != request.tool:
        raise InspectionReceiptError(f"Terminal event for {call_id!r} does not match its request.")
    if status != expected_status:
        raise InspectionReceiptError(
            f"Terminal event for {call_id!r} has status {status!r}, expected {expected_status!r}."
        )
    terminal_digest = _required_sha256(
        f"Terminal event for {call_id!r} projectionDigest",
        payload.get("projectionDigest"),
    )
    if terminal_digest != projection_digest:
        raise InspectionReceiptError(
            f"Terminal event for {call_id!r} projection digest does not match run_started."
        )
    duration_ms = payload.get("durationMs")
    if not isinstance(duration_ms, int) or isinstance(duration_ms, bool) or duration_ms < 0:
        raise InspectionReceiptError(
            f"Terminal event for {call_id!r} durationMs must be a non-negative integer."
        )
    result_sha256 = _required_sha256(
        f"Terminal event for {call_id!r} resultSha256",
        payload.get("resultSha256"),
    )
    returned_stable_ids = _required_unique_string_list(
        f"Terminal event for {call_id!r} citableStableIds",
        payload.get("citableStableIds"),
    )
    error_code: str | None = None
    if status == "succeeded":
        if "result" not in payload or not isinstance(payload["result"], dict):
            raise InspectionReceiptError(
                f"Succeeded terminal event for {call_id!r} must contain a result object."
            )
        if "error" in payload:
            raise InspectionReceiptError(
                f"Succeeded terminal event for {call_id!r} must not contain an error."
            )
    else:
        if returned_stable_ids:
            raise InspectionReceiptError(
                f"Failed terminal event for {call_id!r} must not return citable stable IDs."
            )
        error = payload.get("error")
        if not isinstance(error, dict):
            raise InspectionReceiptError(
                f"Failed terminal event for {call_id!r} must contain a typed error object."
            )
        error_code = _required_non_empty_string(
            f"Failed terminal event for {call_id!r} error code",
            error.get("code"),
        )
        _required_non_empty_string(
            f"Failed terminal event for {call_id!r} error message",
            error.get("message"),
        )
        if "result" in payload:
            raise InspectionReceiptError(
                f"Failed terminal event for {call_id!r} must not contain a result."
            )

    added_stable_ids = [
        stable_id for stable_id in returned_stable_ids if stable_id not in accumulated_citable_set
    ]
    expected_count = len(accumulated_citable_set | set(returned_stable_ids))
    expected_effect: dict[str, object] = {
        "addedStableIds": added_stable_ids,
        "citableStableIdCount": expected_count,
    }
    if payload.get("citableAnchorEffect") != expected_effect:
        raise InspectionReceiptError(
            f"Terminal event for {call_id!r} has an inconsistent citableAnchorEffect."
        )

    normalized_envelope = {
        key: value for key, value in payload.items() if key not in {"durationMs", "resultSha256"}
    }
    expected_hash = hashlib.sha256(_canonical_json_bytes(normalized_envelope)).hexdigest()
    if result_sha256 != expected_hash:
        raise InspectionReceiptError(
            f"Terminal event for {call_id!r} result hash does not match its normalized envelope."
        )

    for stable_id in added_stable_ids:
        accumulated_citable_ids.append(stable_id)
        accumulated_citable_set.add(stable_id)
    return _TerminalTool(
        event=event,
        status=status,
        returned_stable_ids=returned_stable_ids,
        citable_anchor_effect=expected_effect,
        duration_ms=duration_ms,
        result_sha256=result_sha256,
        error_code=error_code,
    )


def _search_projection(
    request: _RequestedTool,
    terminal: _TerminalTool,
) -> dict[str, object]:
    query_text: str | None = None
    criteria_summary: str | None = None
    if request.tool == "search":
        raw_query = request.arguments.get("query")
        query_text = raw_query if isinstance(raw_query, str) else None
    else:
        criteria_summary = _query_blocks_criteria_summary(request.arguments)
    return {
        "callId": request.call_id,
        "tool": request.tool,
        "status": terminal.status,
        "queryText": query_text,
        "criteriaSummary": criteria_summary,
        "returnedStableIds": terminal.returned_stable_ids,
    }


def _read_projection(
    request: _RequestedTool,
    terminal: _TerminalTool,
) -> dict[str, object]:
    raw_stable_ids = request.arguments.get("stableIds")
    requested_stable_ids = (
        list(raw_stable_ids)
        if isinstance(raw_stable_ids, list)
        and all(isinstance(stable_id, str) for stable_id in raw_stable_ids)
        else []
    )
    raw_include_descendants = request.arguments.get("includeDescendants")
    include_descendants = (
        raw_include_descendants if isinstance(raw_include_descendants, bool) else False
    )
    return {
        "callId": request.call_id,
        "tool": request.tool,
        "status": terminal.status,
        "requestedStableIds": requested_stable_ids,
        "includeDescendants": include_descendants,
        "returnedStableIds": terminal.returned_stable_ids,
    }


def _query_blocks_criteria_summary(arguments: dict[str, object]) -> str | None:
    labels = {
        "nodeTypes": "node types",
        "sourceFormats": "source formats",
        "textPattern": "text pattern",
        "resolutionStates": "resolution states",
        "limit": "limit",
    }
    summaries: list[str] = []
    for key in ("nodeTypes", "sourceFormats", "textPattern", "resolutionStates", "limit"):
        if key not in arguments:
            continue
        value = arguments[key]
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            rendered = ", ".join(value)
        elif isinstance(value, str):
            rendered = value
        elif isinstance(value, int) and not isinstance(value, bool):
            rendered = str(value)
        else:
            continue
        summaries.append(f"{labels[key]}: {rendered}")
    return "; ".join(summaries) or None


def _validated_terminal_outcome(
    terminal_outcome: dict[str, object],
    *,
    answer_event: AgentRunEventRecord,
    accumulated_citable_ids: list[str],
) -> dict[str, object]:
    expected_keys = {"type", "citationValidation", "citedStableIds"}
    if not isinstance(terminal_outcome, dict) or set(terminal_outcome) != expected_keys:
        raise InspectionReceiptError(
            "terminal_outcome must contain only type, citationValidation, and citedStableIds."
        )
    if terminal_outcome.get("type") != "supported_answer":
        raise InspectionReceiptError("terminal_outcome type must be supported_answer.")
    if terminal_outcome.get("citationValidation") != "passed":
        raise InspectionReceiptError("terminal_outcome citationValidation must be passed.")
    cited_stable_ids = _required_unique_string_list(
        "terminal_outcome citedStableIds",
        terminal_outcome.get("citedStableIds"),
        allow_empty=False,
    )
    answer_cited_ids = _required_unique_string_list(
        "answer_validated citedStableIds",
        answer_event.payload.get("citedStableIds"),
        allow_empty=False,
    )
    answer_citable_ids = _required_unique_string_list(
        "answer_validated citableStableIds",
        answer_event.payload.get("citableStableIds"),
    )
    if answer_cited_ids != cited_stable_ids:
        raise InspectionReceiptError(
            "terminal_outcome citedStableIds do not match answer_validated."
        )
    accumulated_set = set(accumulated_citable_ids)
    if set(answer_citable_ids) != accumulated_set:
        raise InspectionReceiptError(
            "answer_validated citableStableIds do not match accumulated citable evidence."
        )
    outside_ids = [stable_id for stable_id in cited_stable_ids if stable_id not in accumulated_set]
    if outside_ids:
        raise InspectionReceiptError(
            "answer_validated cites stable IDs outside accumulated citable evidence: "
            + ", ".join(outside_ids)
        )
    return {
        "type": "supported_answer",
        "citationValidation": "passed",
        "citedStableIds": cited_stable_ids,
    }


def _required_unique_string_list(
    field_name: str,
    value: object,
    *,
    allow_empty: bool = True,
) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or item.strip() == "" for item in value
    ):
        raise InspectionReceiptError(f"{field_name} must be a list of non-empty strings.")
    if not allow_empty and not value:
        raise InspectionReceiptError(f"{field_name} must not be empty.")
    if len(value) != len(set(value)):
        raise InspectionReceiptError(f"{field_name} must not contain duplicates.")
    return list(value)


def _required_non_empty_string(field_name: str, value: object) -> str:
    if not isinstance(value, str) or value.strip() == "" or value != value.strip():
        raise InspectionReceiptError(f"{field_name} must be a non-empty normalized string.")
    return value


def _required_sha256(field_name: str, value: object) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise InspectionReceiptError(f"{field_name} must be a lowercase SHA-256 digest.")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise InspectionReceiptError(
            f"Tool terminal envelope must be JSON serializable: {error}"
        ) from error
