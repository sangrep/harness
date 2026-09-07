"""Same-process task persistence for the retained orchestration ports."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace
from threading import RLock

from sangrep_harness.events import RunLeaseV1
from sangrep_harness.ledger import RunAuthorityV1, RunRepositoryV1
from sangrep_harness.review import ProviderCallStateV1, StructuralGrantV1
from sangrep_harness.task_runtime import (
    ReviewTaskSpecV1,
    ReviewTaskTerminalDraftV1,
    ReviewTaskTerminalV1,
    RootContainmentV1,
    validate_review_task_batch_v1,
)
from sangrep_harness.wire import ReviewEventTypeV1


class InMemoryTaskStoreV1:
    """Atomic task admissions, prepare-before-work and terminal binding.

    The caller supplies a validated run authority for each task. This memory adapter
    does not persist across process restart and cannot qualify a durable adapter.
    """

    def __init__(
        self,
        runs: RunRepositoryV1,
        authority_for_task: Callable[[ReviewTaskSpecV1], RunAuthorityV1],
    ) -> None:
        self._lock = RLock()
        self._runs = runs
        self._authority_for_task = authority_for_task
        self._batches: dict[str, tuple[StructuralGrantV1, tuple[ReviewTaskSpecV1, ...]]] = {}
        self._children: dict[str, str] = {}
        self._terminals: dict[str, ReviewTaskTerminalV1] = {}

    def admit(
        self,
        *,
        parent_run_id: str,
        parent_grant: StructuralGrantV1,
        tasks: Sequence[ReviewTaskSpecV1],
        max_concurrency: int,
        root_contains: RootContainmentV1,
        created_by: str,
    ) -> tuple[ReviewTaskSpecV1, ...]:
        if type(created_by) is not str or not created_by.strip():
            raise ValueError("task-actor-invalid")
        admitted = validate_review_task_batch_v1(
            parent_run_id=parent_run_id,
            parent_grant=parent_grant,
            tasks=tasks,
            max_concurrency=max_concurrency,
            root_contains=root_contains,
        )
        with self._lock:
            value = (parent_grant, admitted)
            if parent_run_id in self._batches and self._batches[parent_run_id] != value:
                raise ValueError("task-batch-authority-mismatch")
            self._batches[parent_run_id] = value
            return admitted

    def list_tasks(
        self, parent_run_id: str, *, parent_grant: StructuralGrantV1
    ) -> tuple[ReviewTaskSpecV1, ...]:
        with self._lock:
            grant, tasks = self._batches[parent_run_id]
            if grant != parent_grant:
                raise ValueError("task-parent-authority-mismatch")
            return tasks

    def list_nonterminal(
        self, parent_run_id: str, *, parent_grant: StructuralGrantV1
    ) -> tuple[ReviewTaskSpecV1, ...]:
        with self._lock:
            return tuple(
                task
                for task in self.list_tasks(parent_run_id, parent_grant=parent_grant)
                if task.digest not in self._terminals
            )

    def list_terminals(
        self, parent_run_id: str, *, parent_grant: StructuralGrantV1
    ) -> tuple[ReviewTaskTerminalV1, ...]:
        with self._lock:
            return tuple(
                self._terminals[task.digest]
                for task in self.list_tasks(parent_run_id, parent_grant=parent_grant)
                if task.digest in self._terminals
            )

    def child_run_id(self, task: ReviewTaskSpecV1) -> str | None:
        with self._lock:
            return self._children.get(task.digest)

    def _require_task(self, task: ReviewTaskSpecV1) -> None:
        if (
            task.parent_run_id not in self._batches
            or task not in self._batches[task.parent_run_id][1]
        ):
            raise ValueError("task-not-admitted")

    def prepare(self, task: ReviewTaskSpecV1) -> RunLeaseV1:
        with self._lock:
            self._require_task(task)
            if task.digest in self._children:
                return self._runs.current_lease(self._children[task.digest])
            authority = self._authority_for_task(task)
            if type(authority) is not RunAuthorityV1 or authority.grant != task.grant:
                raise ValueError("task-run-authority-mismatch")
            child_id = "child:" + task.digest
            lease = self._runs.start(child_id, authority)
            self._children[task.digest] = child_id
            return lease

    def terminalize(
        self, task: ReviewTaskSpecV1, intent: ReviewTaskTerminalDraftV1
    ) -> ReviewTaskTerminalV1:
        with self._lock:
            self._require_task(task)
            lease = self.prepare(task)
            if self._runs.get_terminal(lease.run_id) is None:
                draft = intent.review
                if intent.failure_code and intent.failure_code.endswith("recovery"):
                    sent = any(
                        event.event_type is ReviewEventTypeV1.MODEL_REQUESTED
                        for event in self._runs.events(lease.run_id)
                    )
                    draft = replace(
                        draft,
                        provider_call_state=ProviderCallStateV1.OUTCOME_UNKNOWN
                        if sent
                        else ProviderCallStateV1.NOT_REQUESTED,
                    )
                self._runs.terminalize(lease, draft, recovery_reason_code=intent.failure_code)
            return self.bind_terminal(
                task, child_run_id=lease.run_id, failure_code=intent.failure_code
            )

    def bind_terminal(
        self, task: ReviewTaskSpecV1, *, child_run_id: str, failure_code: str | None
    ) -> ReviewTaskTerminalV1:
        with self._lock:
            self._require_task(task)
            if self._children.get(task.digest) != child_run_id:
                raise ValueError("task-child-authority-mismatch")
            if task.digest in self._terminals:
                return self._terminals[task.digest]
            terminal = self._runs.get_terminal(child_run_id)
            if terminal is None or terminal.result.grant_sha256 != task.grant.digest:
                raise ValueError("task-terminal-authority-mismatch")
            result = terminal.result
            from sangrep_harness.terminal import TerminalReviewDraftV1

            draft = TerminalReviewDraftV1(
                result.outcome,
                result.answer,
                result.citations,
                result.evidence_gap_codes,
                result.inspected_count,
                result.unreviewed_count,
                result.coverage_state,
                result.clarification_question_id,
                terminal.receipt.provider_call_state,
                result.provider_failure_diagnostic,
            )
            bound = ReviewTaskTerminalV1.from_draft(
                task,
                child_run_id=child_run_id,
                draft=draft,
                event_head_sha256=terminal.terminal_event.digest,
                receipt_id=terminal.receipt.receipt_id,
                failure_code=terminal.recovery_reason_code,
            )
            self._terminals[task.digest] = bound
            return bound
