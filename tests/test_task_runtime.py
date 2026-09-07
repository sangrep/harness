from __future__ import annotations

from dataclasses import replace
from threading import Lock

import pytest
from synthetic_helpers import _grant

from sangrep_harness.diagnostics import (
    ProviderBadRequestSubcodeV1,
    ProviderFailureDiagnosticV1,
    ProviderRequestFieldV1,
)
from sangrep_harness.review import CoverageStateV1, EvidenceRootRefV1, ProviderCallStateV1
from sangrep_harness.task_runtime import (
    ChildGrantViolation,
    ReviewTaskRuntime,
    ReviewTaskSpecV1,
    ReviewTaskTerminalDraftV1,
    ReviewTaskTerminalV1,
    TaskExecutionContextV1,
    validate_review_task_batch_v1,
)
from sangrep_harness.terminal import TerminalReviewDraftV1
from sangrep_harness.wire import TerminalOutcomeV1


def test_child_task_accepts_only_a_bounded_descendant_grant() -> None:
    parent = _parent_grant()
    child = _child_grant(parent, root="paragraph-a")
    task = ReviewTaskSpecV1(
        task_id="task-01",
        parent_run_id="run-01",
        instruction="Inspect the granted paragraph.",
        grant=child,
        limits=child.limits,
        ordinal=0,
    )

    task.validate_under(parent, root_contains=_root_contains)


@pytest.mark.parametrize(
    "child",
    (
        lambda parent: _child_grant(parent, root="section-b"),
        lambda parent: replace(
            _child_grant(parent),
            tool_names=(*parent.tool_names, "unadmitted.extra"),
        ),
        lambda parent: replace(
            _child_grant(parent),
            limits=replace(parent.limits, max_total_tokens=parent.limits.max_total_tokens + 1),
        ),
    ),
    ids=("outside-root", "wider-tools", "larger-budget"),
)
def test_child_task_rejects_every_authority_widening(child) -> None:
    parent = _parent_grant()
    child_grant = child(parent)
    task = ReviewTaskSpecV1(
        task_id="task-01",
        parent_run_id="run-01",
        instruction="Inspect evidence.",
        grant=child_grant,
        limits=child_grant.limits,
        ordinal=0,
    )

    with pytest.raises(ChildGrantViolation):
        task.validate_under(parent, root_contains=_root_contains)


def test_task_rejects_split_budget_authority_between_spec_and_grant() -> None:
    parent = _parent_grant()
    child = _child_grant(parent)

    with pytest.raises(ChildGrantViolation, match="limits"):
        ReviewTaskSpecV1(
            task_id="task-01",
            parent_run_id="run-01",
            instruction="Inspect evidence.",
            grant=child,
            limits=replace(child.limits, max_tool_calls=child.limits.max_tool_calls - 1),
            ordinal=0,
        )


def test_batch_enforces_parent_child_and_concurrency_budgets() -> None:
    parent = _parent_grant(max_child_tasks=2, max_concurrency=1)
    tasks = tuple(_task(parent, ordinal=ordinal, budget_divisor=2) for ordinal in range(2))

    validate_review_task_batch_v1(
        parent_run_id="run-01",
        parent_grant=parent,
        tasks=tasks,
        max_concurrency=1,
        root_contains=_root_contains,
    )

    with pytest.raises(ChildGrantViolation, match="concurrency"):
        validate_review_task_batch_v1(
            parent_run_id="run-01",
            parent_grant=parent,
            tasks=tasks,
            max_concurrency=2,
            root_contains=_root_contains,
        )
    with pytest.raises(ChildGrantViolation, match="child-task"):
        validate_review_task_batch_v1(
            parent_run_id="run-01",
            parent_grant=replace(
                parent,
                limits=replace(parent.limits, max_child_tasks=1, max_concurrency=1),
            ),
            tasks=tasks,
            max_concurrency=1,
            root_contains=_root_contains,
        )


def test_parent_cancel_terminalizes_running_and_queued_children_once() -> None:
    parent = _parent_grant(max_child_tasks=2, max_concurrency=1)
    tasks = tuple(_task(parent, ordinal=ordinal, budget_divisor=2) for ordinal in range(2))
    cancel = False
    executed: list[str] = []
    terminalized: list[str] = []

    def execute(task: ReviewTaskSpecV1, context: TaskExecutionContextV1):
        nonlocal cancel
        assert context.cancellation_requested() is False
        executed.append(task.task_id)
        cancel = True
        return _draft(TerminalOutcomeV1.ABSTAINED)

    runtime = ReviewTaskRuntime(
        parent_run_id="run-01",
        parent_grant=parent,
        root_contains=_root_contains,
        execute_task=execute,
        terminalize=lambda task, draft: _terminal(task, draft, terminalized),
    )

    terminals = runtime.execute(
        tasks,
        max_concurrency=1,
        cancellation_check=lambda: cancel,
    )

    assert executed == ["task-01"]
    assert [terminal.outcome for terminal in terminals] == [
        TerminalOutcomeV1.CANCELLED,
        TerminalOutcomeV1.CANCELLED,
    ]
    assert terminalized == ["task-01", "task-02"]


def test_worker_crash_and_domain_gap_each_terminalize_without_stopping_siblings() -> None:
    parent = _parent_grant(max_child_tasks=2, max_concurrency=1)
    tasks = tuple(_task(parent, ordinal=ordinal, budget_divisor=2) for ordinal in range(2))
    terminalized: list[str] = []

    def execute(task: ReviewTaskSpecV1, context: TaskExecutionContextV1):
        del context
        if task.ordinal == 0:
            raise RuntimeError("private worker failure detail")
        return _draft(
            TerminalOutcomeV1.EVIDENCE_GAP,
            evidence_gap_codes=("missing_control",),
        )

    terminals = ReviewTaskRuntime(
        parent_run_id="run-01",
        parent_grant=parent,
        root_contains=_root_contains,
        execute_task=execute,
        terminalize=lambda task, draft: _terminal(task, draft, terminalized),
    ).execute(tasks, max_concurrency=1, cancellation_check=lambda: False)

    assert [terminal.outcome for terminal in terminals] == [
        TerminalOutcomeV1.ENGINE_FAILED,
        TerminalOutcomeV1.EVIDENCE_GAP,
    ]
    assert terminals[0].failure_code == "worker_crash"
    assert terminals[1].evidence_gap_codes == ("missing_control",)
    assert terminalized == ["task-01", "task-02"]


def test_elapsed_child_deadline_overrides_a_late_false_success() -> None:
    parent = _parent_grant(max_child_tasks=1, max_concurrency=1)
    task = _task(parent, ordinal=0)
    task = replace(
        task,
        grant=replace(task.grant, limits=replace(task.limits, deadline_ms=10)),
        limits=replace(task.limits, deadline_ms=10),
    )
    clock_value = 0.0

    def clock() -> float:
        return clock_value

    def execute(_task: ReviewTaskSpecV1, _context: TaskExecutionContextV1):
        nonlocal clock_value
        clock_value = 1.0
        return _draft(TerminalOutcomeV1.ABSTAINED)

    terminal = ReviewTaskRuntime(
        parent_run_id="run-01",
        parent_grant=parent,
        root_contains=_root_contains,
        execute_task=execute,
        terminalize=lambda spec, draft: _terminal(spec, draft, []),
        monotonic_clock=clock,
    ).execute((task,), max_concurrency=1, cancellation_check=lambda: False)[0]

    assert terminal.outcome is TerminalOutcomeV1.BUDGET_EXHAUSTED
    assert terminal.failure_code == "deadline_exceeded"


def test_runtime_never_exceeds_declared_concurrency_and_returns_ordinal_order() -> None:
    parent = _parent_grant(max_child_tasks=3, max_concurrency=2)
    tasks = tuple(_task(parent, ordinal=ordinal, budget_divisor=3) for ordinal in range(3))
    lock = Lock()
    active = 0
    maximum_active = 0

    def execute(task: ReviewTaskSpecV1, _context: TaskExecutionContextV1):
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        with lock:
            active -= 1
        return _draft(TerminalOutcomeV1.ABSTAINED, inspected_count=task.ordinal)

    terminals = ReviewTaskRuntime(
        parent_run_id="run-01",
        parent_grant=parent,
        root_contains=_root_contains,
        execute_task=execute,
        terminalize=lambda task, draft: _terminal(task, draft, []),
    ).execute(tasks, max_concurrency=2, cancellation_check=lambda: False)

    assert maximum_active <= 2
    assert [terminal.task_id for terminal in terminals] == [
        "task-01",
        "task-02",
        "task-03",
    ]


@pytest.mark.parametrize(
    "failure_code",
    (None, "transport", "provider_model_substitution"),
)
def test_diagnosed_bad_request_terminal_rejects_every_non_bad_request_failure_code(
    failure_code: str | None,
) -> None:
    parent = _parent_grant(max_child_tasks=1, max_concurrency=1)
    task = _task(parent, ordinal=0)
    diagnostic = ProviderFailureDiagnosticV1(
        http_status=400,
        request_field=ProviderRequestFieldV1.MODEL,
        bad_request_subcode=ProviderBadRequestSubcodeV1.INVALID_REQUEST,
    )
    draft = TerminalReviewDraftV1(
        outcome=TerminalOutcomeV1.PROVIDER_FAILED,
        answer=None,
        citations=(),
        evidence_gap_codes=(),
        inspected_count=0,
        unreviewed_count=1,
        coverage_state=CoverageStateV1.NOT_ASSESSED,
        clarification_question_id=None,
        provider_call_state=ProviderCallStateV1.COMPLETED,
        provider_failure_diagnostic=diagnostic,
    )

    with pytest.raises(ValueError, match="bad_request failure code"):
        ReviewTaskTerminalV1.from_draft(
            task,
            child_run_id="run-task-01",
            draft=draft,
            event_head_sha256="a" * 64,
            receipt_id="receipt-task-01",
            failure_code=failure_code,
        )


def _parent_grant(*, max_child_tasks: int = 3, max_concurrency: int = 2):
    grant = _grant()
    return replace(
        grant,
        limits=replace(
            grant.limits,
            max_child_tasks=max_child_tasks,
            max_concurrency=max_concurrency,
        ),
    )


def _task(parent, *, ordinal: int, budget_divisor: int = 1) -> ReviewTaskSpecV1:
    child = _child_grant(
        parent,
        suffix=str(ordinal + 1),
        budget_divisor=budget_divisor,
    )
    return ReviewTaskSpecV1(
        task_id=f"task-{ordinal + 1:02d}",
        parent_run_id="run-01",
        instruction=f"Inspect bounded unit {ordinal + 1}.",
        grant=child,
        limits=child.limits,
        ordinal=ordinal,
    )


def _child_grant(
    parent,
    *,
    root: str = "section-a",
    suffix: str = "01",
    budget_divisor: int = 1,
):
    limits = replace(
        parent.limits,
        max_iterations=max(1, parent.limits.max_iterations // budget_divisor),
        max_tool_calls=max(1, parent.limits.max_tool_calls // budget_divisor),
        max_total_tokens=max(1, parent.limits.max_total_tokens // budget_divisor),
        deadline_ms=max(1, parent.limits.deadline_ms - 1),
        max_child_tasks=0,
        max_concurrency=0,
    )
    return replace(
        parent,
        grant_id=f"grant-child-{suffix}",
        evidence_roots=(EvidenceRootRefV1("evidence_01", root),),
        tool_names=("read_nodes",),
        media_ids=(),
        limits=limits,
    )


def _root_contains(parent: EvidenceRootRefV1, child: EvidenceRootRefV1) -> bool:
    return parent == child or (parent.stable_id, child.stable_id) == (
        "section-a",
        "paragraph-a",
    )


def _draft(
    outcome: TerminalOutcomeV1,
    *,
    evidence_gap_codes: tuple[str, ...] = (),
    inspected_count: int = 0,
) -> TerminalReviewDraftV1:
    return TerminalReviewDraftV1(
        outcome=outcome,
        answer=None,
        citations=(),
        evidence_gap_codes=evidence_gap_codes,
        inspected_count=inspected_count,
        unreviewed_count=1,
        coverage_state=CoverageStateV1.PARTIAL,
        clarification_question_id=None,
        provider_call_state=ProviderCallStateV1.NOT_REQUESTED,
    )


def _terminal(
    task: ReviewTaskSpecV1,
    intent: ReviewTaskTerminalDraftV1,
    terminalized: list[str],
) -> ReviewTaskTerminalV1:
    terminalized.append(task.task_id)
    return ReviewTaskTerminalV1.from_draft(
        task,
        child_run_id=f"run-{task.task_id}",
        draft=intent.review,
        event_head_sha256="a" * 64,
        receipt_id=f"receipt-{task.task_id}",
        failure_code=intent.failure_code,
    )
