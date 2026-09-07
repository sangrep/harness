from __future__ import annotations

import json

from sangrep_harness.model import AgentModelCallable, AgentModelRequest, AgentModelResponse
from sangrep_harness.tools import HarnessToolRequest

MAX_STUB_CITATIONS = 3


def build_stub_model_callable(
    *,
    agent_id: str,
    tree_stable_ids: list[str],
) -> AgentModelCallable:
    """Return a deterministic ``AgentModelCallable`` for the requested built-in agent."""

    stable_ids = tuple(sorted(set(tree_stable_ids)))
    if len(stable_ids) == 0:
        raise ValueError("tree_stable_ids must contain at least one stable ID.")

    cited_stable_ids = stable_ids[:MAX_STUB_CITATIONS]

    def model_callable(request: AgentModelRequest) -> AgentModelResponse:
        output = _build_output(agent_id=agent_id, stable_ids=cited_stable_ids)
        return AgentModelResponse(
            output=output,
            tokens_in=_rough_token_count(request.rendered_input),
            tokens_out=_rough_token_count(output),
            provider_name="stub",
        )

    return model_callable


def build_harness_stub_model_callable(*, agent_id: str) -> AgentModelCallable:
    """Return a deterministic local model that still traverses real harness tools."""

    def model_callable(request: AgentModelRequest) -> AgentModelResponse:
        citable_stable_ids = _citable_ids_from_tool_turns(request)
        if not citable_stable_ids:
            response = AgentModelResponse(
                output="",
                tokens_in=_rough_token_count(request.rendered_input),
                tokens_out=0,
                tool_calls=(
                    HarnessToolRequest(
                        call_id="stub-query-1",
                        name="query_blocks",
                        arguments={"limit": MAX_STUB_CITATIONS},
                    ),
                ),
                provider_name="stub",
            )
            return response

        output = _build_output(
            agent_id=agent_id,
            stable_ids=citable_stable_ids[:MAX_STUB_CITATIONS],
        )
        return AgentModelResponse(
            output=output,
            tokens_in=_rough_token_count(request.rendered_input),
            tokens_out=_rough_token_count(output),
            provider_name="stub",
        )

    return model_callable


def _citable_ids_from_tool_turns(request: AgentModelRequest) -> tuple[str, ...]:
    stable_ids: list[str] = []
    for turn in request.conversation:
        if turn.role != "tool":
            continue
        try:
            payload = json.loads(turn.content)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        raw_stable_ids = payload.get("citableStableIds")
        if not isinstance(raw_stable_ids, list):
            continue
        stable_ids.extend(
            stable_id
            for stable_id in raw_stable_ids
            if isinstance(stable_id, str) and stable_id.strip() != ""
        )
    return tuple(dict.fromkeys(stable_ids))


def _build_output(agent_id: str, stable_ids: tuple[str, ...]) -> str:
    if agent_id == "find-risks":
        return _risk_output(stable_ids)
    if agent_id == "extract-key-facts":
        return _facts_output(stable_ids)
    return _summary_output(stable_ids)


def _summary_output(stable_ids: tuple[str, ...]) -> str:
    first_id = stable_ids[0]
    second_id = stable_ids[1] if len(stable_ids) > 1 else stable_ids[0]
    third_id = stable_ids[2] if len(stable_ids) > 2 else second_id
    return (
        "The selected scope has enough structure to summarize its main "
        f"thread [id:{first_id}]. A second cited point anchors the summary "
        f"to the rendered tree [id:{second_id}].\n\n"
        "Open question: confirm whether unresolved attachments need manual "
        f"handling [id:{third_id}]."
    )


def _risk_output(stable_ids: tuple[str, ...]) -> str:
    return "\n".join(
        f"- Risk {index}: review the evidence attached to this node before "
        f"relying on it [id:{stable_id}]."
        for index, stable_id in enumerate(stable_ids, start=1)
    )


def _facts_output(stable_ids: tuple[str, ...]) -> str:
    return "\n".join(
        f"- Fact {index}: this stable node is included in the rendered scope [id:{stable_id}]."
        for index, stable_id in enumerate(stable_ids, start=1)
    )


def _rough_token_count(text: str) -> int:
    return len(text) // 4
