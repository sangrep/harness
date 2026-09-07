from __future__ import annotations

import pytest

from sangrep_harness.events import RunLeaseV1, build_review_event_v1
from sangrep_harness.wire import ReviewEventTypeV1


def test_event_builder_chains_exactly_from_the_current_lease() -> None:
    lease = RunLeaseV1("run-01", 0, "1" * 64)

    event = build_review_event_v1(
        lease,
        event_id="event-tool-failed-01",
        event_type=ReviewEventTypeV1.TOOL_FAILED,
        payload={
            "toolCallId": "tool-call-01",
            "toolName": "read_nodes",
            "errorCode": "budget_exhausted",
        },
    )

    assert event.run_id == lease.run_id
    assert event.sequence == 1
    assert event.previous_event_sha256 == lease.expected_head_sha256


def test_lease_and_event_builder_reject_forged_or_stale_shapes() -> None:
    with pytest.raises(ValueError, match="head"):
        RunLeaseV1("run-01", 0, "not-a-digest")

    lease = RunLeaseV1("run-01", 0, "1" * 64)
    with pytest.raises(ValueError, match="payload"):
        build_review_event_v1(
            lease,
            event_id="event-invalid-01",
            event_type=ReviewEventTypeV1.TOOL_FAILED,
            payload={"toolCallId": "tool-call-01"},
        )
