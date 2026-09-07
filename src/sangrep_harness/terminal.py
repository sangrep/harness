from __future__ import annotations

import re
from dataclasses import dataclass

from sangrep_harness.diagnostics import ProviderFailureDiagnosticV1
from sangrep_harness.review import CitationAdmissionV1, CoverageStateV1, ProviderCallStateV1
from sangrep_harness.wire import TerminalOutcomeV1

_CODE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")


@dataclass(frozen=True, slots=True)
class TerminalReviewDraftV1:
    """One pre-persistence terminal proposal with no caller-supplied identities."""

    outcome: TerminalOutcomeV1
    answer: str | None
    citations: tuple[CitationAdmissionV1, ...]
    evidence_gap_codes: tuple[str, ...]
    inspected_count: int
    unreviewed_count: int
    coverage_state: CoverageStateV1
    clarification_question_id: str | None
    provider_call_state: ProviderCallStateV1
    provider_failure_diagnostic: ProviderFailureDiagnosticV1 | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, TerminalOutcomeV1):
            raise ValueError("terminal outcome is invalid")
        if not isinstance(self.provider_call_state, ProviderCallStateV1):
            raise ValueError("provider call state is invalid")
        if type(self.citations) is not tuple or any(
            type(citation) is not CitationAdmissionV1 for citation in self.citations
        ):
            raise ValueError("citations must be an immutable admitted tuple")
        if type(self.evidence_gap_codes) is not tuple or any(
            type(code) is not str or _CODE.fullmatch(code) is None
            for code in self.evidence_gap_codes
        ):
            raise ValueError("evidence gap codes are invalid")
        if len(set(self.evidence_gap_codes)) != len(self.evidence_gap_codes):
            raise ValueError("evidence gap codes must be unique")
        for value in (self.inspected_count, self.unreviewed_count):
            if type(value) is not int or value < 0:
                raise ValueError("terminal counts must be non-negative integers")
        if not isinstance(self.coverage_state, CoverageStateV1):
            raise ValueError("coverage state is invalid")
        if self.coverage_state is CoverageStateV1.COMPLETE and self.unreviewed_count:
            raise ValueError("complete coverage cannot retain unreviewed evidence")
        if self.outcome is TerminalOutcomeV1.SUPPORTED_ANSWER:
            if type(self.answer) is not str or not self.answer.strip() or not self.citations:
                raise ValueError("supported answer requires text and admitted citations")
        elif self.answer is not None or self.citations:
            raise ValueError("only a supported answer may carry answer text or citations")
        if self.outcome is TerminalOutcomeV1.CLARIFICATION_REQUIRED:
            if type(self.clarification_question_id) is not str:
                raise ValueError("clarification terminal requires a question")
        elif self.clarification_question_id is not None:
            raise ValueError("only clarification_required may carry a question")
        if self.outcome is TerminalOutcomeV1.EVIDENCE_GAP and not self.evidence_gap_codes:
            raise ValueError("evidence_gap requires at least one gap code")
        if self.provider_failure_diagnostic is not None:
            if type(self.provider_failure_diagnostic) is not ProviderFailureDiagnosticV1:
                raise TypeError("provider_failure_diagnostic must use ProviderFailureDiagnosticV1")
            if self.outcome is not TerminalOutcomeV1.PROVIDER_FAILED:
                raise ValueError("only provider_failed may carry a provider failure diagnostic")
