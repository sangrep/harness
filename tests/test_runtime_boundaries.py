"""Adversarial authority and resource limits across the connected runtime."""

from dataclasses import replace

import pytest

from sangrep_harness.api import review_snapshot_v1
from sangrep_harness.evidence_head import text_evidence_head_v1
from sangrep_harness.grants import REVIEW_TOOL_NAMES, GrantViolation, create_structural_grant_v1
from sangrep_harness.model import AgentModelResponse
from sangrep_harness.providers.extractive import ExtractiveFakeProviderV1
from sangrep_harness.review import EvidenceRootRefV1, ReviewLimitsV1
from sangrep_harness.text_snapshot import snapshot_text_v1
from sangrep_harness.tools import AdmittedToolRegistryV1, EvidenceReviewToolsV1, HarnessToolRequest


def _authority(raw=b"# First\nAllowed fact.\n# Second\nSibling fact.\n", roots=None):
    snapshot = snapshot_text_v1(raw, relative_path="a.md")
    head = text_evidence_head_v1(snapshot)
    selected = roots or (snapshot.nodes[0].anchor_id,)
    grant = create_structural_grant_v1(
        grant_id="grant-test",
        evidence_head=head,
        reviewer_selected_roots=tuple(
            EvidenceRootRefV1(snapshot.evidence.evidence_version_id, root) for root in selected
        ),
        tool_names=REVIEW_TOOL_NAMES,
        media_ids=(),
        limits=ReviewLimitsV1(8, 3, 50000, 10000, 0, 0),
    )
    return snapshot, head, grant


def test_sibling_and_overlapping_roots_are_refused():
    snapshot, head, grant = _authority()
    sections = [node.anchor_id for node in snapshot.nodes if node.node_kind.value == "section"]
    with pytest.raises(GrantViolation):
        create_structural_grant_v1(
            grant_id="overlap",
            evidence_head=head,
            reviewer_selected_roots=tuple(
                EvidenceRootRefV1(snapshot.evidence.evidence_version_id, root)
                for root in (snapshot.nodes[0].anchor_id, sections[0])
            ),
            tool_names=REVIEW_TOOL_NAMES,
            media_ids=(),
            limits=grant.limits,
        )
    narrowed = replace(
        grant,
        evidence_roots=(EvidenceRootRefV1(snapshot.evidence.evidence_version_id, sections[0]),),
    )
    tools = EvidenceReviewToolsV1(
        grant=narrowed, evidence_head=head, registry=AdmittedToolRegistryV1()
    )
    with pytest.raises(GrantViolation):
        tools.execute(HarnessToolRequest("read-1", "read_nodes", {"stableIds": [sections[1]]}))


def test_stale_head_and_unadmitted_tool_are_refused():
    _, head, grant = _authority()
    other = text_evidence_head_v1(snapshot_text_v1(b"Changed evidence", relative_path="a.md"))
    with pytest.raises(GrantViolation):
        other.require_grant(grant)
    tools = EvidenceReviewToolsV1(
        grant=grant, evidence_head=head, registry=AdmittedToolRegistryV1()
    )
    with pytest.raises(GrantViolation):
        tools.execute(HarnessToolRequest("shell-1", "shell", {"command": "synthetic"}))


def test_query_output_budget_is_enforced_before_admission():
    _, head, grant = _authority(b"x" * 70000)
    tools = EvidenceReviewToolsV1(
        grant=grant, evidence_head=head, registry=AdmittedToolRegistryV1()
    )
    result = tools.execute(HarnessToolRequest("query-1", "query_blocks", {"limit": 1}))
    assert result.status == "failed"
    assert result.payload == {"errorCode": "budget_exhausted"}
    assert tools.successful_tool_calls == ()


def test_unknown_or_excess_usage_never_admits_tool_output():
    snapshot, _, _ = _authority()
    base = ExtractiveFakeProviderV1()

    def provider(request):
        response = base(request)
        return replace(response, tokens_in=1000000)

    result = review_snapshot_v1(
        snapshot,
        question="Review evidence",
        provider=provider,
        limits=ReviewLimitsV1(8, 3, 100, 10000, 0, 0),
    )
    assert result.draft.outcome.value == "budget_exhausted"
    assert not any(event.event_type.value == "tool_completed" for event in result.events)


def test_forged_citation_repair_exhaustion():
    snapshot, _, _ = _authority()

    def provider(_request):
        return AgentModelResponse("Unsupported [id:invented]", 1, 1, provider_name="fake")

    result = review_snapshot_v1(snapshot, question="Review evidence", provider=provider)
    assert result.draft.outcome.value == "engine_failed"
    assert result.draft.citations == ()
    assert len(result.transcript) == 2


@pytest.mark.parametrize("deadline", [float("nan"), float("inf")])
def test_nonfinite_deadlines_cannot_disable_run_bounds(deadline):
    from sangrep_harness.engine import AgentLoopLimits
    from sangrep_harness.task_runtime import TaskExecutionContextV1

    with pytest.raises(ValueError):
        TaskExecutionContextV1(deadline_monotonic=deadline, parent_cancellation_check=lambda: False)
    with pytest.raises(RuntimeError):
        AgentLoopLimits(deadline_seconds=deadline)
