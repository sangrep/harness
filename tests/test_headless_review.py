"""End-to-end engine acceptance through real immutable snapshots and read tools."""

from sangrep_harness.api import review_snapshot_v1
from sangrep_harness.model import AgentModelResponse
from sangrep_harness.providers.extractive import ExtractiveFakeProviderV1
from sangrep_harness.providers.replay_provider import ReplayProviderV1
from sangrep_harness.text_snapshot import snapshot_text_v1


def _snapshot():
    return snapshot_text_v1(
        b"Only observers enter.\nInspect the filter every fourteen days.\n", relative_path="a.txt"
    )


def test_cited_review_matches_public_citation_contract():
    from sangrep_contracts import CitationAddressV1

    result = review_snapshot_v1(
        _snapshot(), question="State the rules", provider=ExtractiveFakeProviderV1()
    )
    assert result.draft.outcome.value == "supported_answer"
    assert "Only observers enter." in result.draft.answer
    for citation in result.draft.citations:
        assert (
            CitationAddressV1.from_json_obj(citation.address.to_json_obj()).digest
            == citation.address_sha256
        )


def test_gap_is_explicit():
    result = review_snapshot_v1(
        _snapshot(),
        question="When was the repair completed?",
        provider=ExtractiveFakeProviderV1("gap"),
    )
    assert result.draft.outcome.value == "evidence_gap"
    assert result.draft.evidence_gap_codes == ("insufficient_evidence",)
    assert result.draft.answer is None


def test_replay_reproduces_complete_result():
    first = review_snapshot_v1(
        _snapshot(), question="State the rules", provider=ExtractiveFakeProviderV1()
    )
    replay = ReplayProviderV1(first.transcript)
    second = review_snapshot_v1(_snapshot(), question="State the rules", provider=replay)
    replay.require_exhausted()
    assert first.to_json_obj() == second.to_json_obj()


def test_repair_refuses_uncited_additional_claim():
    base = ExtractiveFakeProviderV1()

    def provider(request):
        result = base(request)
        if result.output:
            return AgentModelResponse(
                result.output + "\nRepairs are complete.",
                result.tokens_in,
                result.tokens_out,
                provider_name="fake",
            )
        return result

    result = review_snapshot_v1(_snapshot(), question="State the rules", provider=provider)
    assert result.draft.outcome.value == "engine_failed"
    assert result.draft.answer is None
    assert len(result.transcript) == 3


def test_replay_binds_conversation_not_only_rendered_text():
    from dataclasses import replace

    from sangrep_harness.model import AgentConversationTurn, AgentModelRequest
    from sangrep_harness.providers.replay_provider import request_identity_v1

    request = AgentModelRequest(
        "Policy",
        "Rendered",
        "headless-v1",
        review_authority_sha256="a" * 64,
        conversation=(AgentConversationTurn("user", "Original"),),
    )
    changed = replace(request, conversation=(AgentConversationTurn("user", "Changed"),))
    assert request_identity_v1(request) != request_identity_v1(changed)
