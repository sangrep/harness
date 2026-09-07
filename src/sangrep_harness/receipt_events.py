from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentRunEventRecord:
    """One immutable event in a run-local ordered activity stream."""

    id: int
    agent_run_id: int
    sequence: int
    event_key: str
    event_type: str
    title: str
    detail: str | None
    payload: dict[str, object]
    created_at: str
