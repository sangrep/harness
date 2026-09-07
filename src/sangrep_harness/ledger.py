"""Run leases, exact terminal receipt construction and same-process recovery.

Adapted from the retained run-ledger and terminal-recovery algorithms. Persistence
is an explicit port; the included repository uses memory and makes no restart claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from threading import RLock
from typing import Protocol, cast

from sangrep_contracts import require_sha256

from sangrep_harness.events import RunLeaseV1, build_review_event_v1
from sangrep_harness.review import (
    CoverageStateV1,
    ProviderCallStateV1,
    ReviewReceiptV1,
    StructuralGrantV1,
    TerminalReviewResultV1,
)
from sangrep_harness.terminal import TerminalReviewDraftV1
from sangrep_harness.wire import (
    JsonValue,
    ReviewEventTypeV1,
    ReviewEventV1,
    TerminalOutcomeV1,
    canonical_json_sha256_v1,
)

_CODE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")


@dataclass(frozen=True, slots=True)
class RunAuthorityV1:
    grant: StructuralGrantV1
    context_sha256: str
    egress_policy_sha256: str

    def __post_init__(self) -> None:
        if type(self.grant) is not StructuralGrantV1:
            raise TypeError("run-grant-invalid")
        require_sha256(self.context_sha256, field_name="context-sha256")
        require_sha256(self.egress_policy_sha256, field_name="egress-policy-sha256")


@dataclass(frozen=True, slots=True)
class PersistedReviewTerminalV1:
    """The exact terminal trio plus its resulting lease and recovery descriptor."""

    result: TerminalReviewResultV1
    receipt: ReviewReceiptV1
    terminal_event: ReviewEventV1
    lease: RunLeaseV1
    recovery_reason_code: str | None = None

    def __post_init__(self) -> None:
        from sangrep_harness.events import RunLeaseV1

        if (
            type(self.result) is not TerminalReviewResultV1
            or type(self.receipt) is not ReviewReceiptV1
            or type(self.terminal_event) is not ReviewEventV1
            or type(self.lease) is not RunLeaseV1
        ):
            raise TypeError("persisted terminal values are invalid")
        payload = self.terminal_event.payload.to_json_obj()
        if (
            self.receipt.run_id != self.result.run_id
            or self.receipt.terminal_result_sha256 != self.result.digest
            or self.receipt.pre_terminal_event_head_sha256
            != self.result.pre_terminal_event_head_sha256
            or self.terminal_event.run_id != self.result.run_id
            or self.terminal_event.event_type is not ReviewEventTypeV1.TERMINAL
            or self.terminal_event.previous_event_sha256
            != self.result.pre_terminal_event_head_sha256
            or payload
            != {
                "outcome": self.result.outcome.value,
                "terminalResultSha256": self.result.digest,
                "receiptSha256": self.receipt.digest,
            }
            or self.lease.run_id != self.result.run_id
            or self.lease.expected_head_sequence != self.terminal_event.sequence
            or self.lease.expected_head_sha256 != self.terminal_event.digest
        ):
            raise ValueError("persisted terminal identity chain is inconsistent")
        if self.recovery_reason_code is not None and (
            type(self.recovery_reason_code) is not str
            or _CODE.fullmatch(self.recovery_reason_code) is None
        ):
            raise ValueError("terminal recovery reason is invalid")


def build_terminalization_v1(
    *,
    lease: object,
    draft: TerminalReviewDraftV1,
    authority: RunAuthorityV1,
    grant: StructuralGrantV1,
    recovery_reason_code: str | None = None,
) -> PersistedReviewTerminalV1:
    """Derive result, receipt, and terminal event without circular identities."""

    from sangrep_harness.events import RunLeaseV1, build_review_event_v1

    if type(lease) is not RunLeaseV1 or lease.expected_head_sha256 is None:
        raise ValueError("terminalization requires a started run lease")
    if type(draft) is not TerminalReviewDraftV1:
        raise TypeError("draft must use TerminalReviewDraftV1")
    if recovery_reason_code is not None and _CODE.fullmatch(recovery_reason_code) is None:
        raise ValueError("recovery reason code is invalid")
    receipt_seed_payload: dict[str, JsonValue] = {
        "runId": lease.run_id,
        "outcome": draft.outcome.value,
        "preTerminalEventHeadSha256": lease.expected_head_sha256,
    }
    if draft.provider_failure_diagnostic is not None:
        receipt_seed_payload["providerFailureDiagnostic"] = cast(
            JsonValue, draft.provider_failure_diagnostic.to_json_obj()
        )
    receipt_seed = canonical_json_sha256_v1(receipt_seed_payload)
    receipt_id = f"receipt-{receipt_seed[:32]}"
    result = TerminalReviewResultV1(
        run_id=lease.run_id,
        outcome=draft.outcome,
        answer=draft.answer,
        citations=draft.citations,
        grant_id=grant.grant_id,
        grant_sha256=grant.digest,
        evidence_gap_codes=draft.evidence_gap_codes,
        inspected_count=draft.inspected_count,
        unreviewed_count=draft.unreviewed_count,
        coverage_state=draft.coverage_state,
        clarification_question_id=draft.clarification_question_id,
        pre_terminal_event_head_sha256=lease.expected_head_sha256,
        receipt_id=receipt_id,
        provider_failure_diagnostic=draft.provider_failure_diagnostic,
    )
    if authority.grant != grant:
        raise ValueError("terminal-grant-authority-mismatch")
    receipt = ReviewReceiptV1(
        receipt_id=receipt_id,
        run_id=lease.run_id,
        evidence_binding_sha256=grant.evidence_binding.digest,
        grant_sha256=grant.digest,
        context_sha256=authority.context_sha256,
        egress_policy_sha256=authority.egress_policy_sha256,
        limits_sha256=grant.limits.digest,
        pre_terminal_event_head_sha256=lease.expected_head_sha256,
        terminal_result_sha256=result.digest,
        provider_call_state=draft.provider_call_state,
    )
    terminal_payload: dict[str, JsonValue] = {
        "outcome": result.outcome.value,
        "terminalResultSha256": result.digest,
        "receiptSha256": receipt.digest,
    }
    event = build_review_event_v1(
        lease,
        event_id=f"event-{lease.run_id}-terminal",
        event_type=ReviewEventTypeV1.TERMINAL,
        payload=terminal_payload,
    )
    return PersistedReviewTerminalV1(
        result=result,
        receipt=receipt,
        terminal_event=event,
        lease=RunLeaseV1.from_event(event),
        recovery_reason_code=recovery_reason_code,
    )


class RunRepositoryV1(Protocol):
    """Atomic start/compare-and-append/terminal operations for one authority chain."""

    def start(self, run_id: str, authority: RunAuthorityV1) -> RunLeaseV1: ...
    def current_lease(self, run_id: str) -> RunLeaseV1: ...
    def append_event(self, lease: RunLeaseV1, event: ReviewEventV1) -> RunLeaseV1: ...
    def terminalize(
        self,
        lease: RunLeaseV1,
        draft: TerminalReviewDraftV1,
        *,
        recovery_reason_code: str | None = None,
    ) -> PersistedReviewTerminalV1: ...
    def get_terminal(self, run_id: str) -> PersistedReviewTerminalV1 | None: ...
    def events(self, run_id: str) -> tuple[ReviewEventV1, ...]: ...


class InMemoryRunRepositoryV1:
    """Same-process append-only reference repository with terminal uniqueness."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._authority: dict[str, RunAuthorityV1] = {}
        self._events: dict[str, tuple[ReviewEventV1, ...]] = {}
        self._terminals: dict[str, PersistedReviewTerminalV1] = {}

    def start(self, run_id: str, authority: RunAuthorityV1) -> RunLeaseV1:
        with self._lock:
            if run_id in self._authority:
                if self._authority[run_id] != authority:
                    raise ValueError("run-authority-mismatch")
                raise ValueError("run-already-started")
            event = build_review_event_v1(
                RunLeaseV1.before_start(run_id),
                event_id="event-start",
                event_type=ReviewEventTypeV1.RUN_STARTED,
                payload={
                    "grantSha256": authority.grant.digest,
                    "contextSha256": authority.context_sha256,
                    "egressPolicySha256": authority.egress_policy_sha256,
                },
            )
            self._authority[run_id] = authority
            self._events[run_id] = (event,)
            return RunLeaseV1.from_event(event)

    def current_lease(self, run_id: str) -> RunLeaseV1:
        with self._lock:
            return RunLeaseV1.from_event(self._events[run_id][-1])

    def append_event(self, lease: RunLeaseV1, event: ReviewEventV1) -> RunLeaseV1:
        with self._lock:
            if (
                lease.run_id in self._terminals
                or lease != self.current_lease(lease.run_id)
                or event.run_id != lease.run_id
                or event.sequence != lease.expected_head_sequence + 1
                or event.previous_event_sha256 != lease.expected_head_sha256
                or event.event_type in {ReviewEventTypeV1.TERMINAL, ReviewEventTypeV1.RUN_STARTED}
                or any(item.event_id == event.event_id for item in self._events[lease.run_id])
            ):
                raise ValueError("run-lease-conflict")
            self._events[lease.run_id] += (event,)
            return RunLeaseV1.from_event(event)

    def terminalize(
        self,
        lease: RunLeaseV1,
        draft: TerminalReviewDraftV1,
        *,
        recovery_reason_code: str | None = None,
    ) -> PersistedReviewTerminalV1:
        with self._lock:
            if lease.run_id in self._terminals:
                return self._terminals[lease.run_id]
            if lease != self.current_lease(lease.run_id):
                raise ValueError("run-lease-conflict")
            authority = self._authority[lease.run_id]
            terminal = build_terminalization_v1(
                lease=lease,
                draft=draft,
                authority=authority,
                grant=authority.grant,
                recovery_reason_code=recovery_reason_code,
            )
            self._events[lease.run_id] += (terminal.terminal_event,)
            self._terminals[lease.run_id] = terminal
            return terminal

    def get_terminal(self, run_id: str) -> PersistedReviewTerminalV1 | None:
        with self._lock:
            return self._terminals.get(run_id)

    def events(self, run_id: str) -> tuple[ReviewEventV1, ...]:
        with self._lock:
            return self._events[run_id]

    def recover_nonterminal_runs(self) -> tuple[PersistedReviewTerminalV1, ...]:
        """Conservatively terminalize abandoned runs without invoking providers or tools."""
        with self._lock:
            recovered = []
            for run_id in self._authority:
                if run_id in self._terminals:
                    continue
                events = self._events[run_id]
                sent = any(
                    event.event_type is ReviewEventTypeV1.MODEL_REQUESTED for event in events
                )
                draft = TerminalReviewDraftV1(
                    TerminalOutcomeV1.ENGINE_FAILED,
                    None,
                    (),
                    (),
                    0,
                    1,
                    CoverageStateV1.PARTIAL,
                    None,
                    ProviderCallStateV1.OUTCOME_UNKNOWN
                    if sent
                    else ProviderCallStateV1.NOT_REQUESTED,
                )
                recovered.append(
                    self.terminalize(
                        self.current_lease(run_id),
                        draft,
                        recovery_reason_code="abandoned_run_recovery",
                    )
                )
            return tuple(recovered)
