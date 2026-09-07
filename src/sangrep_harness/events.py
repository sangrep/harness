from __future__ import annotations

import re
from dataclasses import dataclass

from sangrep_harness.wire import (
    FrozenJsonObjectV1,
    JsonValue,
    ReviewEventTypeV1,
    ReviewEventV1,
    canonical_json_sha256_v1,
    freeze_json_object_v1,
)

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ReviewRunError(RuntimeError):
    """Base class for sanitized durable review-run failures."""


class ReviewRunConflict(ReviewRunError):
    """The caller used a stale compare-and-append lease."""


class ReviewRunEventConflict(ReviewRunError):
    """An event idempotency identity was reused with different bytes."""


class ReviewRunAlreadyTerminal(ReviewRunError):
    """A different terminal outcome already won for the run."""


class ReviewRunNotFound(ReviewRunError):
    """The requested review run is not present in this workspace."""


class ReviewRunNotTerminal(ReviewRunError):
    """The requested review run has not reached a terminal event."""


class ReviewRunNotReplayable(ReviewRunError):
    """A required encrypted replay artifact was tombstoned or is unavailable."""


@dataclass(frozen=True, slots=True)
class RunLeaseV1:
    """One optimistic event-head authority token."""

    run_id: str
    expected_head_sequence: int
    expected_head_sha256: str | None

    def __post_init__(self) -> None:
        if type(self.run_id) is not str or _IDENTIFIER.fullmatch(self.run_id) is None:
            raise ValueError("run_id must be a bounded identifier")
        if type(self.expected_head_sequence) is not int or self.expected_head_sequence < -1:
            raise ValueError("expected event head sequence is invalid")
        if self.expected_head_sequence == -1:
            if self.expected_head_sha256 is not None:
                raise ValueError("a run before start cannot carry an event head")
        elif (
            type(self.expected_head_sha256) is not str
            or _SHA256.fullmatch(self.expected_head_sha256) is None
        ):
            raise ValueError("expected event head must be lowercase SHA-256")

    @classmethod
    def before_start(cls, run_id: str) -> RunLeaseV1:
        return cls(run_id, -1, None)

    @classmethod
    def from_event(cls, event: ReviewEventV1) -> RunLeaseV1:
        if type(event) is not ReviewEventV1:
            raise TypeError("event must use ReviewEventV1")
        return cls(event.run_id, event.sequence, event.digest)


def build_review_event_v1(
    lease: RunLeaseV1,
    *,
    event_id: str,
    event_type: ReviewEventTypeV1,
    payload: dict[str, JsonValue],
) -> ReviewEventV1:
    """Build the only valid successor event for one lease."""

    if type(lease) is not RunLeaseV1:
        raise TypeError("lease must use RunLeaseV1")
    frozen: FrozenJsonObjectV1 = freeze_json_object_v1(payload)
    return ReviewEventV1(
        event_id=event_id,
        run_id=lease.run_id,
        sequence=lease.expected_head_sequence + 1,
        event_type=event_type,
        previous_event_sha256=lease.expected_head_sha256,
        payload=frozen,
        payload_sha256=canonical_json_sha256_v1(payload),
    )
