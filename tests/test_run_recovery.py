"""Retained lease, terminal, start-before-effect and conservative recovery semantics."""

from dataclasses import replace

import pytest
from synthetic_helpers import _grant

from sangrep_harness.events import build_review_event_v1
from sangrep_harness.ledger import InMemoryRunRepositoryV1, RunAuthorityV1
from sangrep_harness.review import CoverageStateV1, ProviderCallStateV1
from sangrep_harness.task_orchestration import ReviewTaskOrchestrator
from sangrep_harness.task_runtime import ReviewTaskRuntime, ReviewTaskSpecV1
from sangrep_harness.task_store import InMemoryTaskStoreV1
from sangrep_harness.terminal import TerminalReviewDraftV1
from sangrep_harness.wire import ReviewEventTypeV1, TerminalOutcomeV1


def _gap():
    return TerminalReviewDraftV1(
        TerminalOutcomeV1.EVIDENCE_GAP,
        None,
        (),
        ("insufficient_evidence",),
        0,
        1,
        CoverageStateV1.PARTIAL,
        None,
        ProviderCallStateV1.NOT_REQUESTED,
    )


def test_stale_lease_and_duplicate_terminal_cannot_change_history():
    runs = InMemoryRunRepositoryV1()
    authority = RunAuthorityV1(_grant(), "1" * 64, "2" * 64)
    lease = runs.start("run-test", authority)
    item = build_review_event_v1(
        lease,
        event_id="model-1",
        event_type=ReviewEventTypeV1.MODEL_REQUESTED,
        payload={
            "providerCallId": "call-1",
            "providerId": "fake",
            "modelId": "fake-v1",
            "requestSha256": "3" * 64,
        },
    )
    latest = runs.append_event(lease, item)
    with pytest.raises(ValueError, match="lease-conflict"):
        runs.append_event(lease, item)
    first = runs.terminalize(latest, _gap())
    assert runs.terminalize(latest, _gap()) == first
    assert len(runs.events("run-test")) == 3
    assert first.receipt.terminal_result_sha256 == first.result.digest
    assert first.terminal_event.payload.to_json_obj()["receiptSha256"] == first.receipt.digest


def test_recovery_never_repeats_a_started_provider():
    runs = InMemoryRunRepositoryV1()
    lease = runs.start("run-test", RunAuthorityV1(_grant(), "1" * 64, "2" * 64))
    item = build_review_event_v1(
        lease,
        event_id="model-1",
        event_type=ReviewEventTypeV1.MODEL_REQUESTED,
        payload={
            "providerCallId": "call-1",
            "providerId": "fake",
            "modelId": "fake-v1",
            "requestSha256": "3" * 64,
        },
    )
    runs.append_event(lease, item)
    (recovered,) = runs.recover_nonterminal_runs()
    assert recovered.receipt.provider_call_state is ProviderCallStateV1.OUTCOME_UNKNOWN
    assert recovered.result.outcome is TerminalOutcomeV1.ENGINE_FAILED
    assert runs.recover_nonterminal_runs() == ()


@pytest.mark.parametrize("already_prepared", [False, True])
def test_child_starts_before_worker_and_prepared_batches_never_rerun(already_prepared):
    runs = InMemoryRunRepositoryV1()
    base = _grant()
    parent = replace(base, limits=replace(base.limits, max_child_tasks=1, max_concurrency=1))
    child = replace(
        base,
        grant_id="child-grant",
        limits=replace(base.limits, max_iterations=2, max_tool_calls=2, max_total_tokens=100),
    )
    task = ReviewTaskSpecV1("task-test", "parent-test", "Inspect evidence", child, child.limits, 0)
    parent_lease = runs.start("parent-test", RunAuthorityV1(parent, "1" * 64, "2" * 64))
    store = InMemoryTaskStoreV1(runs, lambda task: RunAuthorityV1(task.grant, "1" * 64, "2" * 64))

    def contains(left, right):
        return left == right

    calls = []

    def worker(task, context):
        child_id = store.child_run_id(task)
        assert child_id is not None
        assert runs.events(child_id)[0].event_type is ReviewEventTypeV1.RUN_STARTED
        calls.append(task.task_id)
        return _gap()

    if already_prepared:
        store.admit(
            parent_run_id="parent-test",
            parent_grant=parent,
            tasks=(task,),
            max_concurrency=1,
            root_contains=contains,
            created_by="test",
        )
        store.prepare(task)
    runtime = ReviewTaskRuntime(
        parent_run_id="parent-test",
        parent_grant=parent,
        root_contains=contains,
        execute_task=worker,
        terminalize=store.terminalize,
    )
    orchestrator = ReviewTaskOrchestrator(
        store, prepare_task=store.prepare, terminalize=store.terminalize
    )
    first = orchestrator.execute(
        parent_lease,
        parent,
        (task,),
        runtime=runtime,
        max_concurrency=1,
        root_contains=contains,
        cancellation_check=lambda: False,
        created_by="test",
    )
    second = orchestrator.execute(
        parent_lease,
        parent,
        (task,),
        runtime=runtime,
        max_concurrency=1,
        root_contains=contains,
        cancellation_check=lambda: False,
        created_by="test",
    )
    assert first == second
    assert len(calls) == (0 if already_prepared else 1)
    assert len(first.child_receipt_ids) == 1
