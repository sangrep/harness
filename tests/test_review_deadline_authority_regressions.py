"""Regression probes for run deadlines and immutable replay authority."""

import json
from dataclasses import replace
from functools import partial
from types import SimpleNamespace

import pytest

import sangrep_harness.api as api
from sangrep_harness.model import AgentModelResponse
from sangrep_harness.providers.extractive import ExtractiveFakeProviderV1
from sangrep_harness.providers.replay_provider import ReplayProviderV1
from sangrep_harness.review import ReviewLimitsV1
from sangrep_harness.text_snapshot import snapshot_text_v1
from sangrep_harness.tools import EvidenceReviewToolsV1


@pytest.fixture
def controlled_clock(monkeypatch):
    value = [1000.0]

    def now():
        return value[0]

    monkeypatch.setattr(api, "time", SimpleNamespace(monotonic=now))
    monkeypatch.setattr(
        api,
        "execute_structural_review_task_v1",
        partial(api.execute_structural_review_task_v1, monotonic_clock=now),
    )
    return value


def _snapshot(raw=b"Only observers enter.\n"):
    return snapshot_text_v1(raw, relative_path="rules.txt")


def _limits():
    return ReviewLimitsV1(8, 20, 200_000, 100, 0, 0)


def test_late_final_answer_cannot_become_supported(controlled_clock):
    base = ExtractiveFakeProviderV1()

    def provider(request):
        response = base(request)
        if not response.tool_calls:
            controlled_clock[0] += 0.101
        return response

    result = api.review_snapshot_v1(
        _snapshot(), question="Quote the rule", provider=provider, limits=_limits()
    )
    print(
        json.dumps(
            {"outcome": result.draft.outcome.value, "citations": len(result.draft.citations)}
        )
    )
    assert result.draft.outcome.value == "budget_exhausted"
    assert result.draft.answer is None and result.draft.citations == ()


def test_late_first_turn_cannot_execute_tools(controlled_clock, monkeypatch):
    calls = []
    original = EvidenceReviewToolsV1.execute

    def execute(self, request):
        calls.append(request.call_id)
        return original(self, request)

    monkeypatch.setattr(EvidenceReviewToolsV1, "execute", execute)
    base = ExtractiveFakeProviderV1()

    def provider(request):
        response = base(request)
        controlled_clock[0] += 0.101
        return response

    result = api.review_snapshot_v1(
        _snapshot(), question="Quote the rule", provider=provider, limits=_limits()
    )
    print(json.dumps({"outcome": result.draft.outcome.value, "executedTools": len(calls)}))
    assert result.draft.outcome.value == "budget_exhausted"
    assert calls == []


@pytest.mark.parametrize("changed", ["source", "limits"])
def test_gap_replay_cannot_cross_run_authority(controlled_clock, changed):
    def gap(_request):
        return AgentModelResponse("GAP: insufficient_evidence", 1, 1, provider_name="fake")

    first = api.review_snapshot_v1(
        _snapshot(), question="Is there enough evidence?", provider=gap, limits=_limits()
    )
    assert len(first.transcript) == 1
    replay = ReplayProviderV1(first.transcript)
    snapshot = _snapshot(b"Different evidence.\n") if changed == "source" else _snapshot()
    limits = (
        replace(_limits(), max_iterations=4, max_tool_calls=2, deadline_ms=50)
        if changed == "limits"
        else _limits()
    )
    second = api.review_snapshot_v1(
        snapshot, question="Is there enough evidence?", provider=replay, limits=limits
    )
    assert first.run_id != second.run_id and first.grant_sha256 != second.grant_sha256
    print(
        json.dumps(
            {
                "changed": changed,
                "outcome": second.draft.outcome.value,
                "sameRequestHash": bool(second.transcript)
                and first.transcript[0].request_sha256 == second.transcript[0].request_sha256,
                "differentGrant": first.grant_sha256 != second.grant_sha256,
            }
        )
    )
    assert second.draft.outcome.value != "evidence_gap"
    with pytest.raises(ValueError, match="replay-unconsumed-turns"):
        replay.require_exhausted()


def test_late_refusal_retains_capture_and_does_not_resend(controlled_clock):
    from sangrep_harness.ledger import InMemoryRunRepositoryV1
    from sangrep_harness.providers.exchange import InMemoryExchangeStoreV1
    from sangrep_harness.wire import canonical_json_sha256_v1

    exchanges = InMemoryExchangeStoreV1()
    runs = InMemoryRunRepositoryV1()
    base = ExtractiveFakeProviderV1()
    sends = []

    def provider(request):
        sends.append(1)
        response = base(request)
        if not response.tool_calls:
            controlled_clock[0] += 0.101
        return response

    first = api.review_snapshot_v1(
        _snapshot(),
        question="Quote the rule",
        provider=provider,
        limits=_limits(),
        exchange_store=exchanges,
        run_repository=runs,
    )
    assert first.draft.outcome.value == "budget_exhausted"
    assert len(first.transcript) == 2 and len(sends) == 2
    authority = canonical_json_sha256_v1(
        {
            "grant": first.grant_sha256,
            "request": first.transcript[-1].request_sha256,
            "protocol": "harness.headless.v1",
        }
    )
    capture = exchanges.get(f"{first.run_id}:turn:1", authority)
    assert capture is not None and capture.state == "completed" and capture.payload is not None
    second = api.review_snapshot_v1(
        _snapshot(),
        question="Quote the rule",
        provider=provider,
        limits=_limits(),
        exchange_store=exchanges,
        run_repository=runs,
    )
    assert first.to_json_obj() == second.to_json_obj() and len(sends) == 2


def test_expired_tool_return_cannot_admit_output_or_start_next_tool(controlled_clock, monkeypatch):
    from sangrep_harness.tools import HarnessToolRequest

    executed = []
    original = EvidenceReviewToolsV1._execute_query_blocks

    def read(self, arguments):
        result = original(self, arguments)
        executed.append(1)
        controlled_clock[0] += 0.101
        return result

    monkeypatch.setattr(EvidenceReviewToolsV1, "_execute_query_blocks", read)

    def provider(_request):
        return AgentModelResponse(
            "",
            1,
            1,
            provider_name="fake",
            tool_calls=(
                HarnessToolRequest("first", "query_blocks", {"limit": 1}),
                HarnessToolRequest("second", "query_blocks", {"limit": 1}),
            ),
        )

    result = api.review_snapshot_v1(
        _snapshot(), question="Quote the rule", provider=provider, limits=_limits()
    )
    assert result.draft.outcome.value == "budget_exhausted" and executed == [1]
    assert result.draft.citations == ()
    assert not any(event.event_type.value == "tool_completed" for event in result.events)


def test_identical_authority_replays_after_clock_origin_changes(controlled_clock):
    first = api.review_snapshot_v1(
        _snapshot(),
        question="Quote the rule",
        provider=ExtractiveFakeProviderV1(),
        limits=_limits(),
    )
    controlled_clock[0] += 50.0
    replay = ReplayProviderV1(first.transcript)
    second = api.review_snapshot_v1(
        _snapshot(), question="Quote the rule", provider=replay, limits=_limits()
    )
    replay.require_exhausted()
    assert first.to_json_obj() == second.to_json_obj()


def test_cited_replay_refuses_changed_iteration_and_tool_limits(controlled_clock):
    first = api.review_snapshot_v1(
        _snapshot(),
        question="Quote the rule",
        provider=ExtractiveFakeProviderV1(),
        limits=_limits(),
    )
    replay = ReplayProviderV1(first.transcript)
    second = api.review_snapshot_v1(
        _snapshot(),
        question="Quote the rule",
        provider=replay,
        limits=replace(_limits(), max_iterations=3, max_tool_calls=1),
    )
    assert second.draft.outcome.value == "provider_failed"
    assert not any(event.event_type.value == "tool_completed" for event in second.events)
    with pytest.raises(ValueError, match="replay-unconsumed-turns"):
        replay.require_exhausted()


@pytest.mark.parametrize("authority", [None, "invalid"])
def test_headless_replay_identity_requires_valid_authority(authority):
    from sangrep_harness.model import AgentModelRequest
    from sangrep_harness.providers.replay_provider import request_identity_v1

    request = AgentModelRequest(
        "Policy", "Question", "headless-v1", review_authority_sha256=authority
    )
    with pytest.raises(ValueError):
        request_identity_v1(request)


def test_gap_assembly_cannot_cross_terminal_deadline(controlled_clock, monkeypatch):
    from sangrep_harness.evidence_head import ReviewEvidenceHeadV1

    original = ReviewEvidenceHeadV1.granted_nodes
    advanced = []

    def delayed_count(self, grant):
        result = original(self, grant)
        if not advanced:
            controlled_clock[0] += 0.101
            advanced.append(1)
        return result

    monkeypatch.setattr(ReviewEvidenceHeadV1, "granted_nodes", delayed_count)

    def gap(_request):
        return AgentModelResponse("GAP: insufficient_evidence", 1, 1, provider_name="fake")

    result = api.review_snapshot_v1(
        _snapshot(), question="Is there enough evidence?", provider=gap, limits=_limits()
    )
    assert result.draft.outcome.value == "budget_exhausted"
