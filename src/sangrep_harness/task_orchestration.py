"""Retained task orchestration with explicit prepare/terminal/store ports.

Preparation always precedes worker effects. Previously prepared batches recover
conservatively through terminals and reconciliation, never by rerunning workers.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import NoReturn, Protocol

from sangrep_harness.events import RunLeaseV1
from sangrep_harness.reconcile import (
    ReconciledReviewV1,
    ReviewTaskReconciliationCodeV1,
    ReviewTaskReconciliationError,
    reconcile_task_terminals,
)
from sangrep_harness.review import CoverageStateV1, ProviderCallStateV1, StructuralGrantV1
from sangrep_harness.task_runtime import (
    ReviewTaskRuntime,
    ReviewTaskSpecV1,
    ReviewTaskTerminalDraftV1,
    ReviewTaskTerminalV1,
    RootContainmentV1,
)
from sangrep_harness.terminal import TerminalReviewDraftV1
from sangrep_harness.wire import TerminalOutcomeV1


class ReviewTaskStoreV1(Protocol):
    """Durable task operations required by the bounded orchestrator."""

    def admit(
        self,
        *,
        parent_run_id: str,
        parent_grant: StructuralGrantV1,
        tasks: Sequence[ReviewTaskSpecV1],
        max_concurrency: int,
        root_contains: RootContainmentV1,
        created_by: str,
    ) -> tuple[ReviewTaskSpecV1, ...]: ...

    def list_tasks(
        self,
        parent_run_id: str,
        *,
        parent_grant: StructuralGrantV1,
    ) -> tuple[ReviewTaskSpecV1, ...]: ...

    def list_nonterminal(
        self,
        parent_run_id: str,
        *,
        parent_grant: StructuralGrantV1,
    ) -> tuple[ReviewTaskSpecV1, ...]: ...

    def list_terminals(
        self,
        parent_run_id: str,
        *,
        parent_grant: StructuralGrantV1,
    ) -> tuple[ReviewTaskTerminalV1, ...]: ...

    def child_run_id(self, task: ReviewTaskSpecV1) -> str | None: ...

    def bind_terminal(
        self,
        task: ReviewTaskSpecV1,
        *,
        child_run_id: str,
        failure_code: str | None,
    ) -> ReviewTaskTerminalV1: ...


class ReviewTaskOrchestrator:
    """Persist, execute/recover, and reconcile one complete child-task batch."""

    __slots__ = ("_prepare_task", "_tasks", "_terminalize")

    def __init__(
        self,
        tasks: ReviewTaskStoreV1,
        *,
        prepare_task: Callable[[ReviewTaskSpecV1], RunLeaseV1],
        terminalize: Callable[
            [ReviewTaskSpecV1, ReviewTaskTerminalDraftV1],
            ReviewTaskTerminalV1,
        ],
    ) -> None:
        for method in ("admit", "list_tasks", "list_nonterminal", "list_terminals"):
            if not callable(getattr(tasks, method, None)):
                raise TypeError("review task store is incomplete")
        if not callable(prepare_task) or not callable(terminalize):
            raise TypeError("review task orchestration ports must be callable")
        self._tasks = tasks
        self._prepare_task = prepare_task
        self._terminalize = terminalize

    def execute(
        self,
        parent: RunLeaseV1,
        parent_grant: StructuralGrantV1,
        tasks: Sequence[ReviewTaskSpecV1],
        *,
        runtime: ReviewTaskRuntime,
        max_concurrency: int,
        root_contains: RootContainmentV1,
        cancellation_check: Callable[[], bool],
        created_by: str,
    ) -> ReconciledReviewV1:
        if type(runtime) is not ReviewTaskRuntime:
            raise TypeError("runtime must use ReviewTaskRuntime")
        admitted = self._tasks.admit(
            parent_run_id=parent.run_id,
            parent_grant=parent_grant,
            tasks=tasks,
            max_concurrency=max_concurrency,
            root_contains=root_contains,
            created_by=created_by,
        )
        if any(self._tasks.child_run_id(task) is not None for task in admitted):
            return self.recover(
                parent,
                parent_grant,
                cancellation_check=cancellation_check,
            )
        try:
            for task in admitted:
                prepared = self._prepare_task(task)
                if (
                    type(prepared) is not RunLeaseV1
                    or self._tasks.child_run_id(task) != prepared.run_id
                ):
                    _reject(
                        ReviewTaskReconciliationCodeV1.AUTHORITY_MISMATCH,
                        "prepared child run does not match its admitted task",
                    )
            runtime.execute(
                admitted,
                max_concurrency=max_concurrency,
                cancellation_check=cancellation_check,
            )
            return self._reconciled(parent, parent_grant)
        except Exception as execution_error:
            try:
                return self.recover(
                    parent,
                    parent_grant,
                    cancellation_check=cancellation_check,
                )
            except Exception as recovery_error:
                failure = ReviewTaskReconciliationError(
                    ReviewTaskReconciliationCodeV1.TERMINAL_SET_MISMATCH,
                    "worker execution and conservative task recovery both failed",
                )
                failure.add_note(f"execution failure type: {type(execution_error).__name__}")
                raise failure from recovery_error

    def recover(
        self,
        parent: RunLeaseV1,
        parent_grant: StructuralGrantV1,
        *,
        cancellation_check: Callable[[], bool],
    ) -> ReconciledReviewV1:
        """Force every still-unbound task to a durable conservative terminal."""

        if not callable(cancellation_check):
            raise TypeError("cancellation_check must be callable")
        for task in self._tasks.list_nonterminal(
            parent.run_id,
            parent_grant=parent_grant,
        ):
            try:
                cancelled = cancellation_check()
            except Exception as error:
                raise ReviewTaskReconciliationError(
                    ReviewTaskReconciliationCodeV1.INVALID_ARGUMENT,
                    "parent cancellation check failed during task recovery",
                ) from error
            if type(cancelled) is not bool:
                raise ReviewTaskReconciliationError(
                    ReviewTaskReconciliationCodeV1.INVALID_ARGUMENT,
                    "parent cancellation check returned a non-boolean",
                )
            self._terminalize(
                task,
                _recovery_intent(cancelled=cancelled),
            )
        return self._reconciled(parent, parent_grant)

    def _reconciled(
        self,
        parent: RunLeaseV1,
        parent_grant: StructuralGrantV1,
    ) -> ReconciledReviewV1:
        tasks = self._tasks.list_tasks(parent.run_id, parent_grant=parent_grant)
        terminals = self._tasks.list_terminals(parent.run_id, parent_grant=parent_grant)
        return reconcile_task_terminals(parent, tasks, terminals)


def _recovery_intent(*, cancelled: bool) -> ReviewTaskTerminalDraftV1:
    return ReviewTaskTerminalDraftV1(
        TerminalReviewDraftV1(
            outcome=(TerminalOutcomeV1.CANCELLED if cancelled else TerminalOutcomeV1.ENGINE_FAILED),
            answer=None,
            citations=(),
            evidence_gap_codes=(),
            inspected_count=0,
            unreviewed_count=1,
            coverage_state=CoverageStateV1.PARTIAL,
            clarification_question_id=None,
            provider_call_state=ProviderCallStateV1.NOT_REQUESTED,
        ),
        failure_code=("parent_cancelled_recovery" if cancelled else "abandoned_task_recovery"),
    )


def _reject(code: ReviewTaskReconciliationCodeV1, message: str) -> NoReturn:
    raise ReviewTaskReconciliationError(code, message)
