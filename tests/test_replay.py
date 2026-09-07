from __future__ import annotations

from sangrep_harness.events import RunLeaseV1, build_review_event_v1
from sangrep_harness.replay import build_replay_page_v1
from sangrep_harness.wire import ReviewEventTypeV1


def test_replay_pages_are_gap_free_and_terminal_only_on_the_final_page() -> None:
    first = build_review_event_v1(
        RunLeaseV1.before_start("run-01"),
        event_id="event-start-01",
        event_type=ReviewEventTypeV1.RUN_STARTED,
        payload={
            "grantSha256": "1" * 64,
            "contextSha256": "2" * 64,
            "egressPolicySha256": "3" * 64,
        },
    )
    second = build_review_event_v1(
        RunLeaseV1.from_event(first),
        event_id="event-cancel-01",
        event_type=ReviewEventTypeV1.CANCELLATION_REQUESTED,
        payload={"actorId": "reviewer-01", "expectedEventHead": 0},
    )
    terminal = build_review_event_v1(
        RunLeaseV1.from_event(second),
        event_id="event-terminal-01",
        event_type=ReviewEventTypeV1.TERMINAL,
        payload={
            "outcome": "cancelled",
            "terminalResultSha256": "4" * 64,
            "receiptSha256": "5" * 64,
        },
    )
    events = (first, second, terminal)

    page_one = build_replay_page_v1(
        run_id="run-01",
        events=events,
        event_head_sha256=terminal.digest,
        cursor=None,
        page_size=2,
    )
    assert page_one.events == (first, second)
    assert page_one.terminal is False
    assert page_one.next_cursor is not None

    page_two = build_replay_page_v1(
        run_id="run-01",
        events=events,
        event_head_sha256=terminal.digest,
        cursor=page_one.next_cursor,
        page_size=2,
    )
    assert page_two.events == (terminal,)
    assert page_two.terminal is True
    assert page_two.next_cursor is None
