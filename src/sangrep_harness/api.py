"""Headless composition of immutable evidence, inherited engine, tools and receipts."""

from __future__ import annotations

import time
from dataclasses import dataclass

from sangrep_harness.engine import AgentLoopLimits, HarnessTaskExecutionV1
from sangrep_harness.events import build_review_event_v1
from sangrep_harness.evidence_head import text_evidence_head_v1
from sangrep_harness.grants import (
    REVIEW_TOOL_NAMES,
    GrantViolation,
    GrantViolationCodeV1,
    create_structural_grant_v1,
)
from sangrep_harness.ledger import (
    InMemoryRunRepositoryV1,
    PersistedReviewTerminalV1,
    RunAuthorityV1,
    RunRepositoryV1,
)
from sangrep_harness.model import (
    AgentModelCallable,
    AgentModelRequest,
    AgentModelResponse,
    AgentRunnerError,
)
from sangrep_harness.prompt import PromptBuilderV1, build_harness_agent_system_prompt
from sangrep_harness.providers.exchange import (
    ExchangeStoreV1,
    InMemoryExchangeStoreV1,
    ProviderExchangeFailed,
    ProviderExchangeGatewayV1,
    ProviderSendOutcomeUnknown,
)
from sangrep_harness.providers.replay_provider import (
    ReplayTurnV1,
    request_identity_v1,
    response_from_payload_v1,
    response_payload_v1,
)
from sangrep_harness.review import (
    CoverageStateV1,
    EvidenceRootRefV1,
    ProviderCallStateV1,
    ReviewLimitsV1,
)
from sangrep_harness.structural_loop import StructuralAgentTurnV1, execute_structural_review_task_v1
from sangrep_harness.task_runtime import ReviewTaskSpecV1, TaskExecutionContextV1
from sangrep_harness.terminal import TerminalReviewDraftV1
from sangrep_harness.text_snapshot import TextSnapshotV1
from sangrep_harness.tools import EvidenceReviewToolsV1, HarnessToolResult
from sangrep_harness.wire import (
    JsonValue,
    ReviewEventTypeV1,
    ReviewEventV1,
    TerminalOutcomeV1,
    canonical_json_sha256_v1,
    freeze_json_object_v1,
)


@dataclass(frozen=True, slots=True)
class ReviewResultV1:
    """A proposal, public event chain and replay transcript with deterministic receipts."""

    run_id: str
    draft: TerminalReviewDraftV1
    grant_sha256: str
    events: tuple[ReviewEventV1, ...]
    transcript: tuple[ReplayTurnV1, ...]
    terminal: PersistedReviewTerminalV1

    def to_json_obj(self) -> dict[str, JsonValue]:
        """Return a JSON-compatible result. Evidence text appears only in the proposal."""
        value: dict[str, JsonValue] = {
            "schemaVersion": 1,
            "kind": "harnessReview",
            "runId": self.run_id,
            "proposalOnly": True,
            "outcome": self.draft.outcome.value,
            "answer": self.draft.answer,
            "citations": [citation.to_json_obj() for citation in self.draft.citations],
            "evidenceGapCodes": list(self.draft.evidence_gap_codes),
            "inspectedCount": self.draft.inspected_count,
            "unreviewedCount": self.draft.unreviewed_count,
            "coverageState": self.draft.coverage_state.value,
            "providerCallState": self.draft.provider_call_state.value,
            "grantSha256": self.grant_sha256,
            "events": [event.to_json_obj() for event in self.events],
        }
        value["terminalResult"] = self.terminal.result.to_json_obj()
        value["receipt"] = self.terminal.receipt.to_json_obj()
        value["receiptSha256"] = self.terminal.receipt.digest
        value["resultSha256"] = canonical_json_sha256_v1(value)
        return value


@dataclass(frozen=True, slots=True)
class _Turn:
    response: AgentModelResponse
    tool_results: tuple[HarnessToolResult, ...]


def review_snapshot_v1(
    snapshot: TextSnapshotV1,
    *,
    question: str,
    provider: AgentModelCallable,
    limits: ReviewLimitsV1 | None = None,
    prompt_builder: PromptBuilderV1 = build_harness_agent_system_prompt,
    exchange_store: ExchangeStoreV1 | None = None,
    run_repository: RunRepositoryV1 | None = None,
) -> ReviewResultV1:
    """Run bounded cited review over one admitted snapshot with an explicit provider.

    The public prompt builder is trusted code and can be replaced by the caller.
    Reuse ``exchange_store`` to suppress resend on same-process retries. The default
    creates a fresh in-memory store; no persistent recovery is implied. Providers
    must report token usage and use the bounded headless response profile.
    """
    head = text_evidence_head_v1(snapshot)
    budgets = limits or ReviewLimitsV1(8, 20, 200_000, 120_000, 0, 0)
    policy = prompt_builder(question)
    context_sha = canonical_json_sha256_v1({"policy": policy, "question": question})
    run_digest = canonical_json_sha256_v1(
        {
            "head": head.digest,
            "question": question,
            "contextSha256": context_sha,
            "limits": budgets.to_json_obj(),
        }
    )
    run_id = "run:" + run_digest
    grant = create_structural_grant_v1(
        grant_id="grant:" + run_digest,
        reviewer_selected_roots=(
            EvidenceRootRefV1(snapshot.evidence.evidence_version_id, snapshot.nodes[0].anchor_id),
        ),
        evidence_head=head,
        tool_names=REVIEW_TOOL_NAMES,
        media_ids=(),
        limits=budgets,
    )
    task = ReviewTaskSpecV1("task:" + run_digest, run_id, question, grant, budgets, 0)
    context = TaskExecutionContextV1(
        deadline_monotonic=time.monotonic() + budgets.deadline_ms / 1000,
        parent_cancellation_check=lambda: False,
    )
    execution = HarnessTaskExecutionV1(
        task,
        context,
        AgentLoopLimits(
            budgets.max_iterations,
            budgets.max_tool_calls,
            budgets.max_total_tokens,
            budgets.deadline_ms / 1000,
        ),
    )
    gateway = ProviderExchangeGatewayV1(
        exchange_store if exchange_store is not None else InMemoryExchangeStoreV1()
    )
    transcript: list[ReplayTurnV1] = []
    repository = run_repository if run_repository is not None else InMemoryRunRepositoryV1()
    authority = RunAuthorityV1(
        grant,
        context_sha,
        canonical_json_sha256_v1(
            {"protocol": "harness.headless.v1", "tools": list(grant.tool_names)}
        ),
    )
    existing = repository.get_terminal(run_id)
    if existing is not None:
        if (
            existing.result.grant_sha256 != grant.digest
            or existing.receipt.context_sha256 != context_sha
        ):
            raise ValueError("run-authority-mismatch")
        value = existing.result
        draft = TerminalReviewDraftV1(
            value.outcome,
            value.answer,
            value.citations,
            value.evidence_gap_codes,
            value.inspected_count,
            value.unreviewed_count,
            value.coverage_state,
            value.clarification_question_id,
            existing.receipt.provider_call_state,
            value.provider_failure_diagnostic,
        )
        return ReviewResultV1(run_id, draft, grant.digest, repository.events(run_id), (), existing)
    lease = repository.start(run_id, authority)

    def event(kind: ReviewEventTypeV1, payload: dict[str, JsonValue]) -> None:
        nonlocal lease
        item = build_review_event_v1(
            lease=lease,
            event_id=f"event:{lease.expected_head_sequence + 1}",
            event_type=kind,
            payload=payload,
        )
        lease = repository.append_event(lease, item)

    def turn_factory(tools: EvidenceReviewToolsV1) -> StructuralAgentTurnV1:
        def turn(request: AgentModelRequest) -> _Turn:
            request_sha = request_identity_v1(request)
            authority = canonical_json_sha256_v1(
                {"grant": grant.digest, "request": request_sha, "protocol": "harness.headless.v1"}
            )
            call_id = f"provider:{len(transcript)}"
            event(
                ReviewEventTypeV1.MODEL_REQUESTED,
                {
                    "providerCallId": call_id,
                    "providerId": "headless",
                    "modelId": request.model,
                    "requestSha256": request_sha,
                },
            )

            def validate_execution() -> None:
                head.require_grant(grant)
                tools.require_execution_authority()

            normalized = gateway.complete(
                f"{run_id}:turn:{len(transcript)}",
                authority,
                validate_execution,
                lambda: response_payload_v1(provider(request)).to_json_obj(),
            )
            transcript.append(ReplayTurnV1(request_sha, normalized))
            response = response_from_payload_v1(normalized.to_json_obj())
            event(
                ReviewEventTypeV1.MODEL_COMPLETED,
                {
                    "providerCallId": call_id,
                    "responseSha256": canonical_json_sha256_v1(normalized.to_json_obj()),
                    "inputTokens": response.tokens_in,
                    "outputTokens": response.tokens_out,
                },
            )
            tools.require_execution_authority()
            if (response.tokens_in or 0) + (response.tokens_out or 0) > (
                request.max_output_tokens or 0
            ):
                raise GrantViolation(
                    GrantViolationCodeV1.BUDGET_EXHAUSTED,
                    "Provider usage exceeds remaining run budget.",
                )
            results: list[HarnessToolResult] = []
            for call in response.tool_calls:
                tools.require_execution_authority()
                event(
                    ReviewEventTypeV1.TOOL_REQUESTED,
                    {
                        "toolCallId": call.call_id,
                        "toolName": call.name,
                        "argumentsSha256": canonical_json_sha256_v1(
                            freeze_json_object_v1(call.arguments).to_json_obj()
                        ),
                        "grantSha256": grant.digest,
                    },
                )
                result = tools.execute(call)
                results.append(result)
                if result.status != "succeeded":
                    event(
                        ReviewEventTypeV1.TOOL_FAILED,
                        {
                            "toolCallId": result.call_id,
                            "toolName": result.name,
                            "errorCode": "budget_exhausted",
                        },
                    )
                    continue
                event(
                    ReviewEventTypeV1.TOOL_COMPLETED,
                    {
                        "toolCallId": result.call_id,
                        "toolName": result.name,
                        "resultSha256": result.digest,
                        "evidenceVersionId": snapshot.evidence.evidence_version_id,
                        "projectionRevisionId": snapshot.projection.projection_revision_id,
                    },
                )
            return _Turn(response, tuple(results))

        return turn

    try:
        draft = execute_structural_review_task_v1(
            execution,
            evidence_head=head,
            model_id="headless-v1",
            turn_factory=turn_factory,
            prompt_builder=lambda _question: policy,
        )
    except (ProviderExchangeFailed, ProviderSendOutcomeUnknown) as error:
        draft = _failure(
            TerminalOutcomeV1.PROVIDER_FAILED,
            len(snapshot.nodes),
            ProviderCallStateV1.OUTCOME_UNKNOWN
            if isinstance(error, ProviderSendOutcomeUnknown)
            else ProviderCallStateV1.COMPLETED,
        )
    except GrantViolation as error:
        draft = _failure(
            TerminalOutcomeV1.BUDGET_EXHAUSTED
            if error.code is GrantViolationCodeV1.BUDGET_EXHAUSTED
            else TerminalOutcomeV1.ENGINE_FAILED,
            len(snapshot.nodes),
            ProviderCallStateV1.COMPLETED if transcript else ProviderCallStateV1.NOT_REQUESTED,
        )
    except (AgentRunnerError, ValueError, TypeError):
        draft = _failure(
            TerminalOutcomeV1.ENGINE_FAILED,
            len(snapshot.nodes),
            ProviderCallStateV1.COMPLETED if transcript else ProviderCallStateV1.NOT_REQUESTED,
        )
    terminal = repository.terminalize(lease, draft)
    return ReviewResultV1(
        run_id, draft, grant.digest, repository.events(run_id), tuple(transcript), terminal
    )


def _failure(
    outcome: TerminalOutcomeV1, count: int, state: ProviderCallStateV1
) -> TerminalReviewDraftV1:
    return TerminalReviewDraftV1(
        outcome, None, (), (), 0, count, CoverageStateV1.PARTIAL, None, state
    )
