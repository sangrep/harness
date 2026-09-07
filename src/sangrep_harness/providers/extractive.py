"""A deterministic reference provider that quotes actual tool-returned text."""

import json

from sangrep_harness.model import AgentModelRequest, AgentModelResponse
from sangrep_harness.tools import HarnessToolRequest


class ExtractiveFakeProviderV1:
    """Exercise real tools and citations without a live model or invented facts.

    ``gap`` and ``failure`` modes provide explicit example outcomes. The default
    quotes up to three paragraph nodes. It demonstrates mechanics, not relevance
    ranking, inference or semantic review quality.
    """

    def __init__(self, mode: str = "cited") -> None:
        if mode not in {"cited", "gap", "failure"}:
            raise ValueError("fake-provider-mode-invalid")
        self.mode = mode

    def __call__(self, request: AgentModelRequest) -> AgentModelResponse:
        if self.mode == "failure":
            raise RuntimeError("synthetic-provider-failure")
        turns = [turn for turn in request.conversation if turn.role == "tool"]
        output = ""
        calls: tuple[HarnessToolRequest, ...] = ()
        if not turns:
            calls = (
                HarnessToolRequest(
                    "fake-query-1", "query_blocks", {"nodeTypes": ["paragraph"], "limit": 3}
                ),
            )
        elif self.mode == "gap":
            output = "GAP: insufficient_evidence"
        else:
            payload = json.loads(turns[-1].content)
            nodes = payload.get("payload", {}).get("nodes", [])
            citable = set(payload.get("citableStableIds", []))
            output = (
                "\n".join(
                    f"{node['markdown'].strip()} [id:{node['stableId']}]"
                    for node in nodes
                    if node["stableId"] in citable
                )
                or "GAP: insufficient_evidence"
            )
        return AgentModelResponse(
            output=output,
            tokens_in=max(1, len(request.rendered_input) // 4),
            tokens_out=max(1, len(output) // 4),
            tool_calls=calls,
            provider_name="fake",
        )
