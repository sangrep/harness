from __future__ import annotations

from typing import Protocol

from sangrep_harness.wire import (
    PageCursorV1,
    ReplayPageV1,
    ReviewContractError,
    ReviewContractErrorCodeV1,
    ReviewEventTypeV1,
    ReviewEventV1,
)


class ReviewReplayRepositoryV1(Protocol):
    def replay_events(
        self,
        run_id: str,
        *,
        cursor: PageCursorV1 | None,
        page_size: int,
    ) -> ReplayPageV1: ...


class ReviewReplayService:
    __slots__ = ("_repository",)

    def __init__(self, repository: ReviewReplayRepositoryV1) -> None:
        if not callable(getattr(repository, "replay_events", None)):
            raise TypeError("review replay repository is incomplete")
        self._repository = repository

    def replay_events(
        self,
        run_id: str,
        *,
        cursor: PageCursorV1 | None,
        page_size: int,
    ) -> ReplayPageV1:
        return self._repository.replay_events(run_id, cursor=cursor, page_size=page_size)


def build_replay_page_v1(
    *,
    run_id: str,
    events: tuple[ReviewEventV1, ...],
    event_head_sha256: str,
    cursor: PageCursorV1 | None,
    page_size: int,
) -> ReplayPageV1:
    """Build one gap-free page without redirecting a stale cursor to a newer head."""

    if type(events) is not tuple or not events:
        raise ReviewContractError("Replay requires at least one persisted event.")
    if type(page_size) is not int or not 1 <= page_size <= 1_000:
        raise ReviewContractError("Replay page size must be between 1 and 1000.")
    revision_id = f"events-{event_head_sha256[:32]}"
    if cursor is not None:
        if (
            type(cursor) is not PageCursorV1
            or cursor.subject_id != run_id
            or cursor.revision_id != revision_id
            or cursor.revision_sha256 != event_head_sha256
            or cursor.page_size != page_size
        ):
            raise ReviewContractError(
                "Replay cursor is bound to a stale event head.",
                code=ReviewContractErrorCodeV1.STALE_EVIDENCE,
            )
        start = cursor.after_index + 1
        if start <= 0 or start > len(events):
            raise ReviewContractError(
                "Replay cursor position is stale.",
                code=ReviewContractErrorCodeV1.STALE_EVIDENCE,
            )
        if events[start - 1].digest != cursor.after_item_sha256:
            raise ReviewContractError(
                "Replay cursor event identity is stale.",
                code=ReviewContractErrorCodeV1.STALE_EVIDENCE,
            )
    else:
        start = 0
    selected = events[start : start + page_size]
    if not selected:
        raise ReviewContractError("Replay cursor is already past the event stream.")
    terminal = selected[-1].event_type is ReviewEventTypeV1.TERMINAL
    next_cursor = None
    if not terminal:
        next_cursor = PageCursorV1(
            subject_id=run_id,
            revision_id=revision_id,
            revision_sha256=event_head_sha256,
            after_index=selected[-1].sequence,
            after_item_sha256=selected[-1].digest,
            page_size=page_size,
        )
    return ReplayPageV1(
        run_id=run_id,
        event_head_sha256=event_head_sha256,
        page_size=page_size,
        request_cursor=cursor,
        events=selected,
        next_cursor=next_cursor,
        terminal=terminal,
    )
