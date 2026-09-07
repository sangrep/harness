"""Canonical fake/replay turn codecs and deterministic provider replay."""

from __future__ import annotations

from dataclasses import dataclass

from sangrep_harness.model import AgentModelRequest, AgentModelResponse
from sangrep_harness.tools import HarnessToolRequest
from sangrep_harness.wire import (
    FrozenJsonObjectV1,
    canonical_json_bytes_v1,
    canonical_json_sha256_v1,
    freeze_json_object_v1,
)

MAX_RESPONSE_BYTES = 65536
MAX_TRANSCRIPT_TURNS = 128


def request_identity_v1(request: AgentModelRequest) -> str:
    """Commit semantic request inputs; omit elapsed timeout used only for scheduling."""
    if type(request) is not AgentModelRequest or request.image_attachments:
        raise ValueError("headless-request-invalid")
    if any(
        turn.provider_state is not None
        or turn.private_provider_continuation is not None
        or turn.private_provider_raw_response_sha256 is not None
        for turn in request.conversation
    ):
        raise ValueError("headless-continuation-unsupported")
    return canonical_json_sha256_v1(
        freeze_json_object_v1(
            {
                "conversation": [
                    {
                        "role": turn.role,
                        "content": turn.content,
                        "toolCallId": turn.tool_call_id,
                        "toolName": turn.tool_name,
                        "toolCalls": [
                            {"callId": call.call_id, "name": call.name, "arguments": call.arguments}
                            for call in turn.tool_calls
                        ],
                    }
                    for turn in request.conversation
                ],
                "systemPrompt": request.system_prompt,
                "model": request.model,
                "agentName": request.agent_name,
                "renderedInput": request.rendered_input,
                "maxOutputTokens": request.max_output_tokens,
                "admittedMaxToolCalls": request.admitted_max_tool_calls,
                "remainingToolCalls": request.remaining_tool_calls,
                "tools": [
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": tool.input_schema,
                    }
                    for tool in request.tool_definitions
                ],
            }
        ).to_json_obj()
    )


def response_payload_v1(response: AgentModelResponse) -> FrozenJsonObjectV1:
    """Normalize bounded model values; the headless profile carries no opaque continuation."""
    if type(response) is not AgentModelResponse:
        raise ValueError("provider-response-invalid")
    if (
        type(response.output) is not str
        or len(response.output.encode()) > MAX_RESPONSE_BYTES
        or type(response.tool_calls) is not tuple
        or len(response.tool_calls) > 20
        or response.provider_state is not None
        or response.private_provider_continuation is not None
        or response.private_provider_raw_response_sha256 is not None
        or type(response.provider_name) is not str
        or not response.provider_name
        or len(response.provider_name) > 128
    ):
        raise ValueError("provider-response-invalid")
    if any(
        type(value) is not int or value < 0 for value in (response.tokens_in, response.tokens_out)
    ):
        raise ValueError("provider-usage-required")
    payload = freeze_json_object_v1(
        {
            "output": response.output,
            "tokensIn": response.tokens_in,
            "tokensOut": response.tokens_out,
            "providerName": response.provider_name,
            "toolCalls": [
                {"callId": call.call_id, "name": call.name, "arguments": call.arguments}
                for call in response.tool_calls
            ],
        }
    )
    if len(canonical_json_bytes_v1(payload.to_json_obj())) > MAX_RESPONSE_BYTES:
        raise ValueError("provider-response-over-budget")
    return payload


def response_from_payload_v1(value: object) -> AgentModelResponse:
    """Decode the exact headless response schema with no implicit extra fields."""
    from typing import cast

    payload = freeze_json_object_v1(value).to_json_obj()
    if set(payload) != {"output", "tokensIn", "tokensOut", "providerName", "toolCalls"}:
        raise ValueError("provider-response-invalid")
    raw_calls = payload["toolCalls"]
    if not isinstance(raw_calls, list):
        raise ValueError("provider-response-invalid")
    calls = []
    for call in raw_calls:
        if (
            not isinstance(call, dict)
            or set(call) != {"callId", "name", "arguments"}
            or not isinstance(call["callId"], str)
            or not isinstance(call["name"], str)
            or not isinstance(call["arguments"], dict)
        ):
            raise ValueError("provider-response-invalid")
        calls.append(
            HarnessToolRequest(
                call_id=call["callId"],
                name=call["name"],
                arguments=cast(dict[str, object], call["arguments"]),
            )
        )
    response = AgentModelResponse(
        output=cast(str, payload["output"]),
        tokens_in=cast(int, payload["tokensIn"]),
        tokens_out=cast(int, payload["tokensOut"]),
        provider_name=cast(str, payload["providerName"]),
        tool_calls=tuple(calls),
    )
    response_payload_v1(response)
    return response


@dataclass(frozen=True, slots=True)
class ReplayTurnV1:
    request_sha256: str
    response: FrozenJsonObjectV1

    def to_json_obj(self) -> dict[str, object]:
        return {"requestSha256": self.request_sha256, "response": self.response.to_json_obj()}


class ReplayProviderV1:
    """Replay exact request commitments in order, refusing mismatch or extra calls.

    Replayed names and usage are the recorded provider's values. This class makes
    no network call and does not qualify the original provider. Transcript data may
    contain evidence and must be protected by the integrating application.
    """

    def __init__(self, turns: tuple[ReplayTurnV1, ...]) -> None:
        from sangrep_contracts import require_sha256

        if type(turns) is not tuple or not 0 < len(turns) <= MAX_TRANSCRIPT_TURNS:
            raise ValueError("replay-transcript-invalid")
        for turn in turns:
            if type(turn) is not ReplayTurnV1:
                raise ValueError("replay-transcript-invalid")
            require_sha256(turn.request_sha256, field_name="replay-request")
            response_from_payload_v1(turn.response.to_json_obj())
        self._turns = turns
        self._index = 0

    def __call__(self, request: AgentModelRequest) -> AgentModelResponse:
        if self._index >= len(self._turns):
            raise ValueError("replay-exhausted")
        turn = self._turns[self._index]
        if request_identity_v1(request) != turn.request_sha256:
            raise ValueError("replay-request-mismatch")
        self._index += 1
        return response_from_payload_v1(turn.response.to_json_obj())

    def require_exhausted(self) -> None:
        if self._index != len(self._turns):
            raise ValueError("replay-unconsumed-turns")
