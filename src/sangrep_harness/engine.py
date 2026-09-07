from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass

from sangrep_harness.model import AgentRunnerError
from sangrep_harness.review import CoverageStateV1, ProviderCallStateV1, StructuralGrantV1
from sangrep_harness.task_runtime import ReviewTaskSpecV1, TaskExecutionContextV1
from sangrep_harness.terminal import TerminalReviewDraftV1
from sangrep_harness.wire import TerminalOutcomeV1


@dataclass(frozen=True)
class AgentLoopLimits:
    """One run's bounded iteration, tool, token, and wall-clock budget."""

    max_iterations: int = 8
    max_tool_calls: int = 20
    max_total_tokens: int = 200_000
    deadline_seconds: float = 120.0

    def __post_init__(self) -> None:
        for field_name in ("max_iterations", "max_tool_calls", "max_total_tokens"):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise AgentRunnerError(f"{field_name} must be a positive integer.")
        if (
            not isinstance(self.deadline_seconds, int | float)
            or isinstance(self.deadline_seconds, bool)
            or not math.isfinite(self.deadline_seconds)
            or self.deadline_seconds <= 0
        ):
            raise AgentRunnerError("deadline_seconds must be positive.")


@dataclass(frozen=True, slots=True)
class HarnessTaskExecutionV1:
    """One isolated modern harness invocation with no shared mutable session state."""

    task: ReviewTaskSpecV1
    context: TaskExecutionContextV1
    limits: AgentLoopLimits

    def __post_init__(self) -> None:
        if (
            type(self.task) is not ReviewTaskSpecV1
            or type(self.context) is not TaskExecutionContextV1
            or type(self.limits) is not AgentLoopLimits
        ):
            raise TypeError("harness task execution authority is invalid")

    @property
    def grant(self) -> StructuralGrantV1:
        return self.task.grant

    def cancellation_requested(self) -> bool:
        return self.context.cancellation_requested()


class BoundedHarnessTaskRunnerV1:
    """Map one admitted child task into the closed terminal vocabulary."""

    __slots__ = ("_execute_review",)

    def __init__(
        self,
        execute_review: Callable[[HarnessTaskExecutionV1], TerminalReviewDraftV1],
    ) -> None:
        if not callable(execute_review):
            raise TypeError("execute_review must be callable")
        self._execute_review = execute_review

    def __call__(
        self,
        task: ReviewTaskSpecV1,
        context: TaskExecutionContextV1,
    ) -> TerminalReviewDraftV1:
        if type(task) is not ReviewTaskSpecV1 or type(context) is not TaskExecutionContextV1:
            raise TypeError("bounded harness task values are invalid")
        if context.cancellation_requested():
            return _cancelled_task_draft()
        execution = HarnessTaskExecutionV1(
            task=task,
            context=context,
            limits=AgentLoopLimits(
                max_iterations=task.limits.max_iterations,
                max_tool_calls=task.limits.max_tool_calls,
                max_total_tokens=task.limits.max_total_tokens,
                deadline_seconds=task.limits.deadline_ms / 1000.0,
            ),
        )
        result = self._execute_review(execution)
        if type(result) is not TerminalReviewDraftV1:
            raise AgentRunnerError("bounded harness must return TerminalReviewDraftV1")
        if any(
            citation.grant_id != task.grant.grant_id or citation.grant_sha256 != task.grant.digest
            for citation in result.citations
        ):
            raise AgentRunnerError(
                "bounded harness returned a citation outside the child structural grant"
            )
        return result


def _cancelled_task_draft() -> TerminalReviewDraftV1:
    return TerminalReviewDraftV1(
        outcome=TerminalOutcomeV1.CANCELLED,
        answer=None,
        citations=(),
        evidence_gap_codes=(),
        inspected_count=0,
        unreviewed_count=1,
        coverage_state=CoverageStateV1.PARTIAL,
        clarification_question_id=None,
        provider_call_state=ProviderCallStateV1.NOT_REQUESTED,
    )
