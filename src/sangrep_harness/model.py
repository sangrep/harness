from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from sangrep_harness.media import ProviderImageAttachment
from sangrep_harness.providers.base import PrivateProviderContinuationV1
from sangrep_harness.tools import HarnessToolDefinition, HarnessToolRequest


class AgentRunnerError(RuntimeError):
    """Raised when a scoped agent run cannot be completed safely."""


@dataclass(frozen=True, repr=False)
class AgentConversationTurn:
    """One provider-neutral conversation turn, including normalized tool exchange."""

    role: Literal["user", "assistant", "tool"]
    content: str = field(repr=False)
    tool_calls: tuple[HarnessToolRequest, ...] = field(default=(), repr=False)
    tool_call_id: str | None = None
    tool_name: str | None = None
    provider_state: dict[str, object] | None = field(default=None, repr=False)
    private_provider_continuation: PrivateProviderContinuationV1 | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    private_provider_raw_response_sha256: str | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __repr__(self) -> str:
        continuation_sha256 = (
            None
            if self.private_provider_continuation is None
            else self.private_provider_continuation.canonical_sha256
        )
        return (
            "<AgentConversationTurn "
            f"role={self.role!r} tool_call_count={len(self.tool_calls)} "
            f"has_provider_state={self.provider_state is not None} "
            f"continuation_sha256={continuation_sha256!r} redacted>"
        )


@dataclass(frozen=True, repr=False)
class AgentModelRequest:
    """Provider-agnostic request passed to an agent model callable."""

    system_prompt: str = field(repr=False)
    rendered_input: str = field(repr=False)
    model: str
    agent_name: str | None = None
    image_attachments: tuple[ProviderImageAttachment, ...] = field(default=(), repr=False)
    conversation: tuple[AgentConversationTurn, ...] = field(default=(), repr=False)
    tool_definitions: tuple[HarnessToolDefinition, ...] = field(default=(), repr=False)
    timeout_seconds: float | None = None
    max_output_tokens: int | None = None
    admitted_max_tool_calls: int | None = None
    remaining_tool_calls: int | None = None
    # The headless engine commits its frozen task (run, grant and evidence) and
    # all configured loop limits. Generic provider adapters may leave this unset.
    review_authority_sha256: str | None = None

    def __repr__(self) -> str:
        return (
            "<AgentModelRequest "
            f"model={self.model!r} agent_name={self.agent_name!r} "
            f"image_count={len(self.image_attachments)} "
            f"conversation_count={len(self.conversation)} "
            f"tool_count={len(self.tool_definitions)} "
            f"timeout_seconds={self.timeout_seconds!r} "
            f"max_output_tokens={self.max_output_tokens!r} "
            f"admitted_max_tool_calls={self.admitted_max_tool_calls!r} "
            f"remaining_tool_calls={self.remaining_tool_calls!r} redacted>"
        )


@dataclass(frozen=True, repr=False)
class AgentModelResponse:
    """Provider-agnostic response returned by an agent model callable."""

    output: str = field(repr=False)
    tokens_in: int | None = None
    tokens_out: int | None = None
    tool_calls: tuple[HarnessToolRequest, ...] = field(default=(), repr=False)
    provider_name: str | None = None
    provider_state: dict[str, object] | None = field(default=None, repr=False)
    private_provider_continuation: PrivateProviderContinuationV1 | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    private_provider_raw_response_sha256: str | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __repr__(self) -> str:
        continuation_sha256 = (
            None
            if self.private_provider_continuation is None
            else self.private_provider_continuation.canonical_sha256
        )
        return (
            "<AgentModelResponse "
            f"tokens_in={self.tokens_in!r} tokens_out={self.tokens_out!r} "
            f"tool_call_count={len(self.tool_calls)} provider_name={self.provider_name!r} "
            f"has_provider_state={self.provider_state is not None} "
            f"continuation_sha256={continuation_sha256!r} redacted>"
        )


AgentModelCallable = Callable[[AgentModelRequest], AgentModelResponse]
