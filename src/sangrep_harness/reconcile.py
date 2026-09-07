from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import NoReturn, cast

from sangrep_harness.diagnostics import ProviderFailureDiagnosticV1
from sangrep_harness.events import RunLeaseV1
from sangrep_harness.review import CitationAdmissionV1, CoverageStateV1, ProviderCallStateV1
from sangrep_harness.task_runtime import ReviewTaskSpecV1, ReviewTaskTerminalV1
from sangrep_harness.wire import JsonValue, TerminalOutcomeV1, canonical_json_sha256_v1

_RECONCILED_AUTHORITY = object()


class ReviewTaskReconciliationCodeV1(StrEnum):
    """Closed fail-closed classes for parent reconciliation."""

    INVALID_ARGUMENT = "invalid_argument"
    TERMINAL_SET_MISMATCH = "terminal_set_mismatch"
    DUPLICATE_TERMINAL = "duplicate_terminal"
    AUTHORITY_MISMATCH = "authority_mismatch"
    OUT_OF_GRANT_CITATION = "out_of_grant_citation"


class ReviewTaskReconciliationError(RuntimeError):
    """One child set cannot be safely represented as a parent result."""

    def __init__(self, code: ReviewTaskReconciliationCodeV1, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ReconciledChildClaimV1:
    """One child answer retained without deduplication or silent synthesis."""

    task_id: str
    child_run_id: str
    answer: str
    citations: tuple[CitationAdmissionV1, ...]

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "taskId": self.task_id,
            "childRunId": self.child_run_id,
            "answer": self.answer,
            "citations": [citation.to_json_obj() for citation in self.citations],
        }


@dataclass(frozen=True, slots=True)
class ReconciledReviewV1:
    """One deterministic parent result that retains every child limitation."""

    outcome: TerminalOutcomeV1
    answer: str | None
    citations: tuple[CitationAdmissionV1, ...]
    evidence_gap_codes: tuple[str, ...]
    child_run_ids: tuple[str, ...]
    child_outcomes: tuple[TerminalOutcomeV1, ...]
    child_receipt_ids: tuple[str, ...]
    child_terminal_digests: tuple[str, ...]
    child_failure_codes: tuple[str | None, ...]
    candidate_claims: tuple[ReconciledChildClaimV1, ...]
    inspected_count: int
    unreviewed_count: int
    coverage_state: CoverageStateV1
    provider_call_state: ProviderCallStateV1
    provider_failure_diagnostic: ProviderFailureDiagnosticV1 | None
    _authority: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._authority is not _RECONCILED_AUTHORITY:
            raise ReviewTaskReconciliationError(
                ReviewTaskReconciliationCodeV1.AUTHORITY_MISMATCH,
                "reconciled review requires validated child terminal authority",
            )
        if self.provider_failure_diagnostic is not None and (
            type(self.provider_failure_diagnostic) is not ProviderFailureDiagnosticV1
            or self.outcome is not TerminalOutcomeV1.PROVIDER_FAILED
        ):
            raise ReviewTaskReconciliationError(
                ReviewTaskReconciliationCodeV1.AUTHORITY_MISMATCH,
                "reconciled provider failure diagnostic is invalid",
            )

    def to_json_obj(self) -> dict[str, JsonValue]:
        payload: dict[str, JsonValue] = {
            "outcome": self.outcome.value,
            "answer": self.answer,
            "citations": [citation.to_json_obj() for citation in self.citations],
            "evidenceGapCodes": list(self.evidence_gap_codes),
            "childRunIds": list(self.child_run_ids),
            "childOutcomes": [outcome.value for outcome in self.child_outcomes],
            "childReceiptIds": list(self.child_receipt_ids),
            "childTerminalDigests": list(self.child_terminal_digests),
            "childFailureCodes": list(self.child_failure_codes),
            "candidateClaims": [claim.to_json_obj() for claim in self.candidate_claims],
            "inspectedCount": self.inspected_count,
            "unreviewedCount": self.unreviewed_count,
            "coverageState": self.coverage_state.value,
            "providerCallState": self.provider_call_state.value,
        }
        if self.provider_failure_diagnostic is not None:
            payload["providerFailureDiagnostic"] = cast(
                JsonValue,
                self.provider_failure_diagnostic.to_json_obj(),
            )
        return payload

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


_FAILURE_GAPS = {
    TerminalOutcomeV1.PROTOCOL_SUPERSEDED: "child_protocol_superseded",
    TerminalOutcomeV1.POLICY_SUPERSEDED: "child_policy_superseded",
    TerminalOutcomeV1.CANCELLED: "child_cancelled",
    TerminalOutcomeV1.BUDGET_EXHAUSTED: "child_budget_exhausted",
    TerminalOutcomeV1.PROVIDER_FAILED: "child_provider_failed",
    TerminalOutcomeV1.ENGINE_FAILED: "child_engine_failed",
    TerminalOutcomeV1.CLARIFICATION_REQUIRED: "child_clarification_required",
}


_OUTCOME_PRECEDENCE = (
    TerminalOutcomeV1.CANCELLED,
    TerminalOutcomeV1.PROTOCOL_SUPERSEDED,
    TerminalOutcomeV1.POLICY_SUPERSEDED,
    TerminalOutcomeV1.ENGINE_FAILED,
    TerminalOutcomeV1.PROVIDER_FAILED,
    TerminalOutcomeV1.BUDGET_EXHAUSTED,
    TerminalOutcomeV1.CLARIFICATION_REQUIRED,
    TerminalOutcomeV1.EVIDENCE_GAP,
)


_PROVIDER_PRECEDENCE = {
    ProviderCallStateV1.NOT_REQUESTED: 0,
    ProviderCallStateV1.BLOCKED_PREFLIGHT: 1,
    ProviderCallStateV1.COMPLETED: 2,
    ProviderCallStateV1.SENT: 3,
    ProviderCallStateV1.OUTCOME_UNKNOWN: 4,
}


def reconcile_task_terminals(
    parent: RunLeaseV1,
    tasks: Sequence[ReviewTaskSpecV1],
    children: Sequence[ReviewTaskTerminalV1],
) -> ReconciledReviewV1:
    """Validate and aggregate one complete admitted child set without inventing coverage."""

    if type(parent) is not RunLeaseV1 or parent.expected_head_sha256 is None:
        _reject(
            ReviewTaskReconciliationCodeV1.INVALID_ARGUMENT,
            "parent must be a started review-run lease",
        )
    admitted = _validated_tasks(parent, tasks)
    terminals = _ordered_terminals(admitted, children)
    _require_child_authority(admitted, terminals)

    candidate_claims = tuple(
        ReconciledChildClaimV1(
            task.task_id,
            terminal.child_run_id,
            terminal.answer,
            terminal.citations,
        )
        for task, terminal in zip(admitted, terminals, strict=True)
        if terminal.outcome is TerminalOutcomeV1.SUPPORTED_ANSWER and terminal.answer is not None
    )
    citations = tuple(citation for claim in candidate_claims for citation in claim.citations)
    child_outcomes = tuple(terminal.outcome for terminal in terminals)
    outcome = _parent_outcome(child_outcomes, has_claims=bool(candidate_claims))
    provider_failed_terminals = tuple(
        terminal for terminal in terminals if terminal.outcome is TerminalOutcomeV1.PROVIDER_FAILED
    )
    first_provider_failure_diagnostic = (
        provider_failed_terminals[0].review.provider_failure_diagnostic
        if provider_failed_terminals
        else None
    )
    provider_failure_diagnostic = (
        first_provider_failure_diagnostic
        if outcome is TerminalOutcomeV1.PROVIDER_FAILED
        and first_provider_failure_diagnostic is not None
        and all(
            terminal.failure_code == "bad_request"
            and terminal.review.provider_failure_diagnostic == first_provider_failure_diagnostic
            for terminal in provider_failed_terminals
        )
        else None
    )
    coverage_state = _parent_coverage(terminals)
    gaps = _ordered_gap_codes(terminals)
    if coverage_state is not CoverageStateV1.COMPLETE:
        gaps = _append_unique(gaps, "incomplete_child_coverage")
    answer = (
        "\n\n".join(claim.answer for claim in candidate_claims)
        if outcome is TerminalOutcomeV1.SUPPORTED_ANSWER
        else None
    )
    return ReconciledReviewV1(
        outcome=outcome,
        answer=answer,
        citations=citations,
        evidence_gap_codes=gaps,
        child_run_ids=tuple(terminal.child_run_id for terminal in terminals),
        child_outcomes=child_outcomes,
        child_receipt_ids=tuple(terminal.receipt_id for terminal in terminals),
        child_terminal_digests=tuple(terminal.digest for terminal in terminals),
        child_failure_codes=tuple(terminal.failure_code for terminal in terminals),
        candidate_claims=candidate_claims,
        inspected_count=sum(terminal.inspected_count for terminal in terminals),
        unreviewed_count=sum(terminal.unreviewed_count for terminal in terminals),
        coverage_state=coverage_state,
        provider_call_state=max(
            (terminal.review.provider_call_state for terminal in terminals),
            key=_PROVIDER_PRECEDENCE.__getitem__,
        ),
        provider_failure_diagnostic=provider_failure_diagnostic,
        _authority=_RECONCILED_AUTHORITY,
    )


def _validated_tasks(
    parent: RunLeaseV1,
    tasks: Sequence[ReviewTaskSpecV1],
) -> tuple[ReviewTaskSpecV1, ...]:
    if not isinstance(tasks, Sequence) or isinstance(tasks, str | bytes) or not tasks:
        _reject(
            ReviewTaskReconciliationCodeV1.INVALID_ARGUMENT,
            "reconciliation requires a non-empty admitted task set",
        )
    admitted = tuple(tasks)
    if any(type(task) is not ReviewTaskSpecV1 for task in admitted):
        _reject(
            ReviewTaskReconciliationCodeV1.INVALID_ARGUMENT,
            "task set contains an invalid review task",
        )
    ordered = tuple(sorted(admitted, key=lambda task: task.ordinal))
    if (
        tuple(task.ordinal for task in ordered) != tuple(range(len(ordered)))
        or len({task.task_id for task in ordered}) != len(ordered)
        or any(task.parent_run_id != parent.run_id for task in ordered)
    ):
        _reject(
            ReviewTaskReconciliationCodeV1.AUTHORITY_MISMATCH,
            "task set does not match the parent run authority",
        )
    return ordered


def _ordered_terminals(
    tasks: tuple[ReviewTaskSpecV1, ...],
    children: Sequence[ReviewTaskTerminalV1],
) -> tuple[ReviewTaskTerminalV1, ...]:
    if (
        not isinstance(children, Sequence)
        or isinstance(children, str | bytes)
        or any(type(child) is not ReviewTaskTerminalV1 for child in children)
    ):
        _reject(
            ReviewTaskReconciliationCodeV1.INVALID_ARGUMENT,
            "terminal set contains an invalid child terminal",
        )
    terminal_by_task: dict[str, ReviewTaskTerminalV1] = {}
    for child in children:
        if child.task_id in terminal_by_task:
            _reject(
                ReviewTaskReconciliationCodeV1.DUPLICATE_TERMINAL,
                "duplicate child terminal is not reconcilable",
            )
        terminal_by_task[child.task_id] = child
    expected_ids = {task.task_id for task in tasks}
    if set(terminal_by_task) != expected_ids:
        _reject(
            ReviewTaskReconciliationCodeV1.TERMINAL_SET_MISMATCH,
            "child terminal set is missing or contains an unadmitted task",
        )
    return tuple(terminal_by_task[task.task_id] for task in tasks)


def _require_child_authority(
    tasks: tuple[ReviewTaskSpecV1, ...],
    terminals: tuple[ReviewTaskTerminalV1, ...],
) -> None:
    child_run_ids: set[str] = set()
    receipt_ids: set[str] = set()
    for task, terminal in zip(tasks, terminals, strict=True):
        if (
            terminal.task_id != task.task_id
            or terminal.parent_run_id != task.parent_run_id
            or terminal.child_run_id == task.parent_run_id
            or terminal.grant_id != task.grant.grant_id
            or terminal.grant_sha256 != task.grant.digest
        ):
            _reject(
                ReviewTaskReconciliationCodeV1.AUTHORITY_MISMATCH,
                "child terminal does not match its task or parent authority",
            )
        if terminal.child_run_id in child_run_ids or terminal.receipt_id in receipt_ids:
            _reject(
                ReviewTaskReconciliationCodeV1.DUPLICATE_TERMINAL,
                "duplicate child run or receipt cannot satisfy two tasks",
            )
        child_run_ids.add(terminal.child_run_id)
        receipt_ids.add(terminal.receipt_id)
        if any(
            citation.grant_id != task.grant.grant_id or citation.grant_sha256 != task.grant.digest
            for citation in terminal.citations
        ):
            _reject(
                ReviewTaskReconciliationCodeV1.OUT_OF_GRANT_CITATION,
                "child citation does not match its exact task grant",
            )


def _parent_outcome(
    child_outcomes: tuple[TerminalOutcomeV1, ...],
    *,
    has_claims: bool,
) -> TerminalOutcomeV1:
    for candidate in _OUTCOME_PRECEDENCE:
        if candidate in child_outcomes:
            return candidate
    return TerminalOutcomeV1.SUPPORTED_ANSWER if has_claims else TerminalOutcomeV1.ABSTAINED


def _parent_coverage(
    terminals: tuple[ReviewTaskTerminalV1, ...],
) -> CoverageStateV1:
    failed = any(terminal.outcome in _FAILURE_GAPS for terminal in terminals)
    if (
        not failed
        and all(terminal.coverage_state is CoverageStateV1.COMPLETE for terminal in terminals)
        and not any(terminal.unreviewed_count for terminal in terminals)
    ):
        return CoverageStateV1.COMPLETE
    if (
        not failed
        and all(terminal.coverage_state is CoverageStateV1.NOT_ASSESSED for terminal in terminals)
        and not any(terminal.inspected_count or terminal.unreviewed_count for terminal in terminals)
    ):
        return CoverageStateV1.NOT_ASSESSED
    return CoverageStateV1.PARTIAL


def _ordered_gap_codes(
    terminals: tuple[ReviewTaskTerminalV1, ...],
) -> tuple[str, ...]:
    gaps: tuple[str, ...] = ()
    for terminal in terminals:
        for code in terminal.evidence_gap_codes:
            gaps = _append_unique(gaps, code)
        failure_code = _FAILURE_GAPS.get(terminal.outcome)
        if failure_code is not None:
            gaps = _append_unique(gaps, failure_code)
    return gaps


def _append_unique(values: tuple[str, ...], value: str) -> tuple[str, ...]:
    return values if value in values else (*values, value)


def _reject(code: ReviewTaskReconciliationCodeV1, message: str) -> NoReturn:
    raise ReviewTaskReconciliationError(code, message)
