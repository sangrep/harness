from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Literal, NoReturn, Protocol, SupportsIndex, final, runtime_checkable

from sangrep_harness.diagnostics import ProviderFailureDiagnosticV1
from sangrep_harness.media import ProviderImageAttachment


class ProviderReasoningEffortV1(StrEnum):
    """Closed provider-request reasoning effort admitted by trusted routing."""

    MEDIUM = "medium"


class OpenAIProtocolIdV1(StrEnum):
    """Closed OpenAI request-family identity for versioned routed authority."""

    CHAT_COMPLETIONS_V1 = "openai.chat_completions.v1"
    RESPONSES_V1 = "openai.responses.v1"


class ProviderResponseFailureCodeV1(StrEnum):
    """Closed sanitized failure vocabulary for Responses normalization."""

    PROVIDER_PROTOCOL_SUBSTITUTION = "provider_protocol_substitution"
    INVALID_RESPONSE = "invalid_response"
    PROVIDER_RESPONSE_INCOMPLETE = "provider_response_incomplete"
    PROVIDER_RESPONSE_ITEM_INVALID = "provider_response_item_invalid"
    PROVIDER_CONTINUATION_INVALID = "provider_continuation_invalid"


@runtime_checkable
class PrivateProviderContinuationV1(Protocol):
    """Digest-only interface for provider-private in-memory continuation state."""

    @property
    def canonical_sha256(self) -> str: ...

    @property
    def item_count(self) -> int: ...


@dataclass(frozen=True)
class ProviderToolCall:
    """One normalized provider-requested tool invocation."""

    call_id: str
    name: str
    arguments: dict[str, object]


@dataclass(frozen=True)
class ProviderToolDefinition:
    """Provider-neutral function metadata and JSON input schema."""

    name: str
    description: str
    input_schema: dict[str, object]


@dataclass(frozen=True)
class ProviderConversationTurn:
    """One normalized provider turn with optional opaque continuation state."""

    role: Literal["user", "assistant", "tool"]
    content: str
    tool_calls: tuple[ProviderToolCall, ...] = ()
    tool_call_id: str | None = None
    tool_name: str | None = None
    provider_state: dict[str, object] | None = None


@dataclass(frozen=True)
class ProviderCompletionRequest:
    """Provider-facing text completion request."""

    system_prompt: str | None
    user_prompt: str
    model: str
    max_output_tokens: int
    image_attachments: tuple[ProviderImageAttachment, ...] = ()
    conversation: tuple[ProviderConversationTurn, ...] = ()
    tool_definitions: tuple[ProviderToolDefinition, ...] = ()
    timeout_seconds: float | None = None
    reasoning_effort: ProviderReasoningEffortV1 | None = None

    def __post_init__(self) -> None:
        if self.reasoning_effort is not None and type(self.reasoning_effort) is not (
            ProviderReasoningEffortV1
        ):
            raise TypeError("reasoning_effort must use ProviderReasoningEffortV1")


@dataclass(frozen=True)
class ProviderCompletionResponse:
    """Provider-facing text completion response."""

    output_text: str
    tokens_in: int | None
    tokens_out: int | None
    provider_name: str
    model: str
    tool_calls: tuple[ProviderToolCall, ...] = ()
    provider_state: dict[str, object] | None = None


class ProviderFailureCategoryV1(StrEnum):
    """Closed provider-independent category for outcome-known call failures."""

    AUTHENTICATION = "authentication"
    PERMISSION = "permission"
    NOT_FOUND = "not_found"
    BAD_REQUEST = "bad_request"
    RATE_OR_QUOTA = "rate_or_quota"
    TRANSPORT = "transport"
    UPSTREAM = "upstream"
    INVALID_RESPONSE = "invalid_response"
    UNKNOWN = "unknown"


@final
class ProviderFailureAuthorityV1:
    """Raw provider failure authority that must remain private workspace data."""

    __slots__ = ("__response_body",)

    def __init__(self, *, response_body: bytes) -> None:
        if type(response_body) is not bytes:
            raise TypeError("provider failure response body must be exact bytes")
        self.__response_body = response_body

    @property
    def response_body(self) -> bytes:
        return self.__response_body

    def __eq__(self, other: object) -> bool:
        return (
            type(other) is ProviderFailureAuthorityV1
            and other.__response_body == self.__response_body
        )

    def __hash__(self) -> int:
        return hash(self.__response_body)

    def __repr__(self) -> str:
        return "<ProviderFailureAuthorityV1 redacted>"

    def __str__(self) -> str:
        return "<ProviderFailureAuthorityV1 redacted>"

    def __bytes__(self) -> NoReturn:
        raise TypeError("ProviderFailureAuthorityV1 cannot be converted to bytes")

    def __reduce__(self) -> NoReturn:
        raise TypeError("ProviderFailureAuthorityV1 cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("ProviderFailureAuthorityV1 cannot be pickled")


class ProviderCallError(RuntimeError):
    """Raised when a provider call fails after bounded adapter handling."""

    default_failure_category: ClassVar[ProviderFailureCategoryV1] = (
        ProviderFailureCategoryV1.UNKNOWN
    )

    def __init__(
        self,
        message: str,
        *,
        user_message: str | None = None,
        technical_details: str | None = None,
        failure_category: ProviderFailureCategoryV1 | None = None,
        failure_diagnostic: ProviderFailureDiagnosticV1 | None = None,
        private_failure_authority: ProviderFailureAuthorityV1 | None = None,
    ) -> None:
        category = self.default_failure_category if failure_category is None else failure_category
        if type(category) is not ProviderFailureCategoryV1:
            raise TypeError("failure_category must use ProviderFailureCategoryV1")
        if failure_diagnostic is not None:
            if type(failure_diagnostic) is not ProviderFailureDiagnosticV1:
                raise TypeError("failure_diagnostic must use ProviderFailureDiagnosticV1")
            if category is not ProviderFailureCategoryV1.BAD_REQUEST:
                raise ValueError("only bad-request failures may carry a provider diagnostic")
        if private_failure_authority is not None:
            if type(private_failure_authority) is not ProviderFailureAuthorityV1:
                raise TypeError("private_failure_authority must use ProviderFailureAuthorityV1")
            if category is not ProviderFailureCategoryV1.BAD_REQUEST or failure_diagnostic is None:
                raise ValueError(
                    "private provider failure authority requires a diagnosed bad request"
                )
        super().__init__(message)
        self.user_message = user_message or message
        self.technical_details = technical_details
        self.failure_category = category
        self.failure_diagnostic = failure_diagnostic
        self.private_failure_authority = private_failure_authority


class ProviderRateLimited(ProviderCallError):
    """Raised when a provider remains rate-limited after retries."""

    default_failure_category = ProviderFailureCategoryV1.RATE_OR_QUOTA


class ProviderTransportError(ProviderCallError):
    """Raised when provider transport fails after retries."""

    default_failure_category = ProviderFailureCategoryV1.TRANSPORT


class ProviderResponseError(ProviderCallError):
    """Raised when a provider returns an invalid or unparseable response."""

    default_failure_category = ProviderFailureCategoryV1.INVALID_RESPONSE


class EmptyProviderResponseError(ProviderResponseError):
    """Raised when a provider response contains no usable text."""


class ProviderVisionUnsupportedError(ProviderCallError):
    """Raised when a provider/model cannot accept requested vision attachments."""
