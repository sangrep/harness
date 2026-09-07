from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderImageAttachment:
    """Binary image attachment passed from a scoped tree node to an LLM provider."""

    stable_id: str
    mime_type: str
    data: bytes
