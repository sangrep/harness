from __future__ import annotations

import math
import re
import time
import unicodedata
from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from enum import StrEnum
from threading import Event
from typing import cast

from sangrep_harness.review import (
    CitationAdmissionV1,
    CoverageStateV1,
    EvidenceRootRefV1,
    ProviderCallStateV1,
    ReviewLimitsV1,
    StructuralGrantV1,
)
from sangrep_harness.terminal import TerminalReviewDraftV1
from sangrep_harness.wire import JsonValue, TerminalOutcomeV1, canonical_json_sha256_v1

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


_CODE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


_MAX_INSTRUCTION_CHARS = 1_048_576


RootContainmentV1 = Callable[[EvidenceRootRefV1, EvidenceRootRefV1], bool]


class ChildGrantViolationCodeV1(StrEnum):
    """Closed failure vocabulary for child-task admission."""

    INVALID_TASK = "invalid_task"
    CROSS_RUN = "cross_run"
    STALE_EVIDENCE = "stale_evidence"
    OUT_OF_SCOPE = "out_of_scope"
    UNADMITTED_TOOL = "unadmitted_tool"
    UNADMITTED_MEDIA = "unadmitted_media"
    BUDGET_EXCEEDED = "budget_exceeded"
    DUPLICATE_TASK = "duplicate_task"


class ChildGrantViolation(ValueError):
    """A child attempted to widen or split its parent authority."""

    def __init__(self, code: ChildGrantViolationCodeV1, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ReviewTaskSpecV1:
    """One immutable child instruction with an explicit subset grant and budget."""

    task_id: str
    parent_run_id: str
    instruction: str
    grant: StructuralGrantV1
    limits: ReviewLimitsV1
    ordinal: int

    def __post_init__(self) -> None:
        _require_identifier(self.task_id, field_name="task_id")
        _require_identifier(self.parent_run_id, field_name="parent_run_id")
        if (
            type(self.instruction) is not str
            or not self.instruction.strip()
            or len(self.instruction) > _MAX_INSTRUCTION_CHARS
            or unicodedata.normalize("NFC", self.instruction) != self.instruction
        ):
            raise ChildGrantViolation(
                ChildGrantViolationCodeV1.INVALID_TASK,
                "child instruction must be bounded, nonblank NFC text",
            )
        if type(self.grant) is not StructuralGrantV1 or type(self.limits) is not ReviewLimitsV1:
            raise TypeError("child grant and limits must use frozen review contracts")
        if self.limits != self.grant.limits:
            raise ChildGrantViolation(
                ChildGrantViolationCodeV1.BUDGET_EXCEEDED,
                "child grant and task limits must be one exact authority",
            )
        if type(self.ordinal) is not int or self.ordinal < 0:
            raise ChildGrantViolation(
                ChildGrantViolationCodeV1.INVALID_TASK,
                "child task ordinal must be non-negative",
            )

    def validate_under(
        self,
        parent_grant: StructuralGrantV1,
        *,
        root_contains: RootContainmentV1,
    ) -> None:
        """Reject any child evidence, tool, media, or limit outside its parent."""

        if type(parent_grant) is not StructuralGrantV1:
            raise TypeError("parent_grant must use StructuralGrantV1")
        if not callable(root_contains):
            raise TypeError("root_contains must be callable")
        if self.grant.evidence_binding != parent_grant.evidence_binding:
            raise ChildGrantViolation(
                ChildGrantViolationCodeV1.STALE_EVIDENCE,
                "child evidence authority differs from its parent",
            )
        for child_root in self.grant.evidence_roots:
            if not any(
                _contains(root_contains, parent_root, child_root)
                for parent_root in parent_grant.evidence_roots
            ):
                raise ChildGrantViolation(
                    ChildGrantViolationCodeV1.OUT_OF_SCOPE,
                    "child evidence root is outside the parent grant",
                )
        for index, left in enumerate(self.grant.evidence_roots):
            for right in self.grant.evidence_roots[index + 1 :]:
                if _contains(root_contains, left, right) or _contains(
                    root_contains,
                    right,
                    left,
                ):
                    raise ChildGrantViolation(
                        ChildGrantViolationCodeV1.OUT_OF_SCOPE,
                        "child evidence roots must not overlap",
                    )
        if not set(self.grant.tool_names) <= set(parent_grant.tool_names):
            raise ChildGrantViolation(
                ChildGrantViolationCodeV1.UNADMITTED_TOOL,
                "child tools exceed the parent registry",
            )
        if not set(self.grant.media_ids) <= set(parent_grant.media_ids):
            raise ChildGrantViolation(
                ChildGrantViolationCodeV1.UNADMITTED_MEDIA,
                "child media exceed the parent grant",
            )
        _require_limits_within(self.limits, parent_grant.limits)

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": "reviewTask",
            "taskId": self.task_id,
            "parentRunId": self.parent_run_id,
            "instruction": self.instruction,
            "grant": self.grant.to_json_obj(),
            "limits": self.limits.to_json_obj(),
            "ordinal": self.ordinal,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class ReviewTaskTerminalDraftV1:
    """One terminalization intent produced before durable receipt persistence."""

    review: TerminalReviewDraftV1
    failure_code: str | None = None

    def __post_init__(self) -> None:
        if type(self.review) is not TerminalReviewDraftV1:
            raise TypeError("task terminal draft must use TerminalReviewDraftV1")
        if self.failure_code is not None and (
            type(self.failure_code) is not str or _CODE.fullmatch(self.failure_code) is None
        ):
            raise ValueError("task terminal failure code is invalid")


@dataclass(frozen=True, slots=True)
class ReviewTaskTerminalV1:
    """Durable child terminal identity returned by an injected terminalizer."""

    task_id: str
    parent_run_id: str
    child_run_id: str
    grant_id: str
    grant_sha256: str
    review: TerminalReviewDraftV1
    event_head_sha256: str
    receipt_id: str
    failure_code: str | None = None

    def __post_init__(self) -> None:
        for field_name, value in (
            ("task_id", self.task_id),
            ("parent_run_id", self.parent_run_id),
            ("child_run_id", self.child_run_id),
            ("grant_id", self.grant_id),
            ("receipt_id", self.receipt_id),
        ):
            _require_identifier(value, field_name=field_name)
        _require_sha256(self.grant_sha256, field_name="grant_sha256")
        _require_sha256(self.event_head_sha256, field_name="event_head_sha256")
        if type(self.review) is not TerminalReviewDraftV1:
            raise TypeError("task terminal review must use TerminalReviewDraftV1")
        if self.failure_code is not None and (
            type(self.failure_code) is not str or _CODE.fullmatch(self.failure_code) is None
        ):
            raise ValueError("task terminal failure code is invalid")
        if (
            self.review.provider_failure_diagnostic is not None
            and self.failure_code != "bad_request"
        ):
            raise ValueError(
                "task terminal provider failure diagnostic requires bad_request failure code"
            )

    @classmethod
    def from_draft(
        cls,
        task: ReviewTaskSpecV1,
        *,
        child_run_id: str,
        draft: TerminalReviewDraftV1,
        event_head_sha256: str,
        receipt_id: str,
        failure_code: str | None = None,
    ) -> ReviewTaskTerminalV1:
        if type(task) is not ReviewTaskSpecV1:
            raise TypeError("task must use ReviewTaskSpecV1")
        return cls(
            task_id=task.task_id,
            parent_run_id=task.parent_run_id,
            child_run_id=child_run_id,
            grant_id=task.grant.grant_id,
            grant_sha256=task.grant.digest,
            review=draft,
            event_head_sha256=event_head_sha256,
            receipt_id=receipt_id,
            failure_code=failure_code,
        )

    @property
    def outcome(self) -> TerminalOutcomeV1:
        return self.review.outcome

    @property
    def answer(self) -> str | None:
        return self.review.answer

    @property
    def citations(self) -> tuple[CitationAdmissionV1, ...]:
        return self.review.citations

    @property
    def evidence_gap_codes(self) -> tuple[str, ...]:
        return self.review.evidence_gap_codes

    @property
    def inspected_count(self) -> int:
        return self.review.inspected_count

    @property
    def unreviewed_count(self) -> int:
        return self.review.unreviewed_count

    @property
    def coverage_state(self) -> CoverageStateV1:
        return self.review.coverage_state

    def to_json_obj(self) -> dict[str, JsonValue]:
        payload: dict[str, JsonValue] = {
            "taskId": self.task_id,
            "parentRunId": self.parent_run_id,
            "childRunId": self.child_run_id,
            "grantId": self.grant_id,
            "grantSha256": self.grant_sha256,
            "outcome": self.outcome.value,
            "answer": self.answer,
            "citations": [citation.to_json_obj() for citation in self.citations],
            "evidenceGapCodes": list(self.evidence_gap_codes),
            "inspectedCount": self.inspected_count,
            "unreviewedCount": self.unreviewed_count,
            "coverageState": self.coverage_state.value,
            "eventHeadSha256": self.event_head_sha256,
            "receiptId": self.receipt_id,
            "failureCode": self.failure_code,
        }
        if self.review.provider_failure_diagnostic is not None:
            payload["providerFailureDiagnostic"] = cast(
                JsonValue, self.review.provider_failure_diagnostic.to_json_obj()
            )
        return payload

    @property
    def digest(self) -> str:
        return canonical_json_sha256_v1(self.to_json_obj())


class TaskExecutionContextV1:
    """Cooperative child cancellation and deadline authority."""

    __slots__ = ("_cancel", "_parent_cancellation_check", "deadline_monotonic")

    def __init__(
        self,
        *,
        deadline_monotonic: float,
        parent_cancellation_check: Callable[[], bool],
    ) -> None:
        if (
            type(deadline_monotonic) not in (float, int)
            or not math.isfinite(deadline_monotonic)
            or deadline_monotonic < 0
        ):
            raise ValueError("task deadline must be non-negative monotonic time")
        if not callable(parent_cancellation_check):
            raise TypeError("parent cancellation check must be callable")
        self.deadline_monotonic = float(deadline_monotonic)
        self._parent_cancellation_check = parent_cancellation_check
        self._cancel = Event()

    def cancellation_requested(self) -> bool:
        if self._cancel.is_set():
            return True
        result = self._parent_cancellation_check()
        if type(result) is not bool:
            raise TypeError("cancellation_check must return a boolean")
        return result

    def cancel(self) -> None:
        self._cancel.set()

    def deadline_exceeded(self, monotonic_now: float) -> bool:
        return monotonic_now >= self.deadline_monotonic


class ReviewTaskRuntimeError(RuntimeError):
    """The scheduler could not reconcile a child through its terminalizer."""


class ReviewTaskRuntime:
    """Execute a validated child batch with bounded concurrency and terminalize every task."""

    __slots__ = (
        "_execute_task",
        "_monotonic_clock",
        "_parent_grant",
        "_parent_run_id",
        "_root_contains",
        "_terminalize",
    )

    def __init__(
        self,
        *,
        parent_run_id: str,
        parent_grant: StructuralGrantV1,
        root_contains: RootContainmentV1,
        execute_task: Callable[
            [ReviewTaskSpecV1, TaskExecutionContextV1],
            TerminalReviewDraftV1,
        ],
        terminalize: Callable[
            [ReviewTaskSpecV1, ReviewTaskTerminalDraftV1],
            ReviewTaskTerminalV1,
        ],
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        _require_identifier(parent_run_id, field_name="parent_run_id")
        if type(parent_grant) is not StructuralGrantV1:
            raise TypeError("parent_grant must use StructuralGrantV1")
        for name, value in (
            ("root_contains", root_contains),
            ("execute_task", execute_task),
            ("terminalize", terminalize),
            ("monotonic_clock", monotonic_clock),
        ):
            if not callable(value):
                raise TypeError(f"{name} must be callable")
        self._parent_run_id = parent_run_id
        self._parent_grant = parent_grant
        self._root_contains = root_contains
        self._execute_task = execute_task
        self._terminalize = terminalize
        self._monotonic_clock = monotonic_clock

    def execute(
        self,
        tasks: Sequence[ReviewTaskSpecV1],
        *,
        max_concurrency: int,
        cancellation_check: Callable[[], bool],
    ) -> tuple[ReviewTaskTerminalV1, ...]:
        if not callable(cancellation_check):
            raise TypeError("cancellation_check must be callable")
        admitted = validate_review_task_batch_v1(
            parent_run_id=self._parent_run_id,
            parent_grant=self._parent_grant,
            tasks=tasks,
            max_concurrency=max_concurrency,
            root_contains=self._root_contains,
        )
        if not admitted:
            return ()
        terminal_by_id: dict[str, ReviewTaskTerminalV1] = {}

        def terminalize_once(
            task: ReviewTaskSpecV1,
            intent: ReviewTaskTerminalDraftV1,
        ) -> None:
            if task.task_id in terminal_by_id:
                raise ReviewTaskRuntimeError("child task attempted duplicate terminalization")
            try:
                terminal = self._terminalize(task, intent)
            except Exception as error:
                raise ReviewTaskRuntimeError("child task terminalization failed") from error
            if (
                type(terminal) is not ReviewTaskTerminalV1
                or terminal.task_id != task.task_id
                or terminal.parent_run_id != task.parent_run_id
                or terminal.grant_id != task.grant.grant_id
                or terminal.grant_sha256 != task.grant.digest
                or terminal.outcome is not intent.review.outcome
                or terminal.failure_code != intent.failure_code
            ):
                raise ReviewTaskRuntimeError("child terminalizer returned inconsistent authority")
            terminal_by_id[task.task_id] = terminal

        if max_concurrency == 1:
            for task in admitted:
                if _cancellation_requested(cancellation_check):
                    terminalize_once(
                        task,
                        _failure_intent(
                            TerminalOutcomeV1.CANCELLED,
                            "parent_cancelled",
                        ),
                    )
                    continue
                started = self._monotonic_clock()
                context = TaskExecutionContextV1(
                    deadline_monotonic=started + (task.limits.deadline_ms / 1000.0),
                    parent_cancellation_check=cancellation_check,
                )
                try:
                    result = self._execute_task(task, context)
                except Exception:
                    intent = _failure_intent(
                        TerminalOutcomeV1.ENGINE_FAILED,
                        "worker_crash",
                    )
                else:
                    if _cancellation_requested(cancellation_check):
                        intent = _failure_intent(
                            TerminalOutcomeV1.CANCELLED,
                            "parent_cancelled",
                        )
                    elif context.deadline_exceeded(self._monotonic_clock()):
                        intent = _failure_intent(
                            TerminalOutcomeV1.BUDGET_EXHAUSTED,
                            "deadline_exceeded",
                        )
                    elif type(result) is not TerminalReviewDraftV1:
                        intent = _failure_intent(
                            TerminalOutcomeV1.ENGINE_FAILED,
                            "invalid_worker_result",
                        )
                    else:
                        intent = ReviewTaskTerminalDraftV1(result)
                terminalize_once(task, intent)
            return tuple(
                terminal_by_id[task.task_id]
                for task in sorted(admitted, key=lambda item: item.ordinal)
            )

        pending = list(admitted)
        active: dict[
            Future[TerminalReviewDraftV1],
            tuple[ReviewTaskSpecV1, TaskExecutionContextV1],
        ] = {}
        parent_cancelled = False
        with ThreadPoolExecutor(
            max_workers=max_concurrency, thread_name_prefix="sangrep-review"
        ) as pool:
            while pending or active:
                parent_cancelled = parent_cancelled or _cancellation_requested(cancellation_check)
                if parent_cancelled:
                    for _, context in active.values():
                        context.cancel()
                    while pending:
                        terminalize_once(
                            pending.pop(0),
                            _failure_intent(
                                TerminalOutcomeV1.CANCELLED,
                                "parent_cancelled",
                            ),
                        )
                while pending and not parent_cancelled and len(active) < max_concurrency:
                    task = pending.pop(0)
                    started = self._monotonic_clock()
                    context = TaskExecutionContextV1(
                        deadline_monotonic=started + (task.limits.deadline_ms / 1000.0),
                        parent_cancellation_check=cancellation_check,
                    )
                    active[pool.submit(self._execute_task, task, context)] = (task, context)
                if not active:
                    continue
                completed, _ = wait(tuple(active), timeout=0.01, return_when=FIRST_COMPLETED)
                if not completed:
                    now = self._monotonic_clock()
                    for _, context in active.values():
                        if context.deadline_exceeded(now):
                            context.cancel()
                    continue
                for future in completed:
                    task, context = active.pop(future)
                    parent_cancelled = parent_cancelled or _cancellation_requested(
                        cancellation_check
                    )
                    if parent_cancelled:
                        intent = _failure_intent(
                            TerminalOutcomeV1.CANCELLED,
                            "parent_cancelled",
                        )
                    elif context.deadline_exceeded(self._monotonic_clock()):
                        intent = _failure_intent(
                            TerminalOutcomeV1.BUDGET_EXHAUSTED,
                            "deadline_exceeded",
                        )
                    else:
                        try:
                            result = future.result()
                        except Exception:
                            intent = _failure_intent(
                                TerminalOutcomeV1.ENGINE_FAILED,
                                "worker_crash",
                            )
                        else:
                            if type(result) is not TerminalReviewDraftV1:
                                intent = _failure_intent(
                                    TerminalOutcomeV1.ENGINE_FAILED,
                                    "invalid_worker_result",
                                )
                            else:
                                intent = ReviewTaskTerminalDraftV1(result)
                    terminalize_once(task, intent)
        return tuple(
            terminal_by_id[task.task_id] for task in sorted(admitted, key=lambda x: x.ordinal)
        )


def validate_review_task_batch_v1(
    *,
    parent_run_id: str,
    parent_grant: StructuralGrantV1,
    tasks: Sequence[ReviewTaskSpecV1],
    max_concurrency: int,
    root_contains: RootContainmentV1,
) -> tuple[ReviewTaskSpecV1, ...]:
    """Freeze one direct-child batch within parent count, concurrency, and total budgets."""

    _require_identifier(parent_run_id, field_name="parent_run_id")
    if type(parent_grant) is not StructuralGrantV1:
        raise TypeError("parent_grant must use StructuralGrantV1")
    if isinstance(tasks, str | bytes):
        raise TypeError("tasks must be a review-task sequence")
    frozen = tuple(tasks)
    if any(type(task) is not ReviewTaskSpecV1 for task in frozen):
        raise TypeError("tasks contains an invalid review task")
    if type(max_concurrency) is not int or max_concurrency < 0:
        raise ChildGrantViolation(
            ChildGrantViolationCodeV1.BUDGET_EXCEEDED,
            "child concurrency must be a non-negative integer",
        )
    if not frozen:
        if max_concurrency != 0:
            raise ChildGrantViolation(
                ChildGrantViolationCodeV1.BUDGET_EXCEEDED,
                "empty child-task batches require zero concurrency",
            )
        return frozen
    if (
        len(frozen) > parent_grant.limits.max_child_tasks
        or parent_grant.limits.max_child_tasks == 0
    ):
        raise ChildGrantViolation(
            ChildGrantViolationCodeV1.BUDGET_EXCEEDED,
            "child-task count exceeds the parent budget",
        )
    if (
        max_concurrency == 0
        or max_concurrency > parent_grant.limits.max_concurrency
        or max_concurrency > len(frozen)
    ):
        raise ChildGrantViolation(
            ChildGrantViolationCodeV1.BUDGET_EXCEEDED,
            "child concurrency exceeds the parent budget",
        )
    task_ids = tuple(task.task_id for task in frozen)
    ordinals = tuple(task.ordinal for task in frozen)
    if len(set(task_ids)) != len(task_ids) or len(set(ordinals)) != len(ordinals):
        raise ChildGrantViolation(
            ChildGrantViolationCodeV1.DUPLICATE_TASK,
            "child task identities and ordinals must be unique",
        )
    if len({task.grant.grant_id for task in frozen}) != len(frozen):
        raise ChildGrantViolation(
            ChildGrantViolationCodeV1.DUPLICATE_TASK,
            "child task grants must be unique for durable run reconciliation",
        )
    if tuple(sorted(ordinals)) != tuple(range(len(frozen))):
        raise ChildGrantViolation(
            ChildGrantViolationCodeV1.INVALID_TASK,
            "child task ordinals must be gap-free from zero",
        )
    for task in frozen:
        if task.parent_run_id != parent_run_id:
            raise ChildGrantViolation(
                ChildGrantViolationCodeV1.CROSS_RUN,
                "child task uses another parent run",
            )
        task.validate_under(parent_grant, root_contains=root_contains)
    for field_name in ("max_iterations", "max_tool_calls", "max_total_tokens"):
        child_total = sum(getattr(task.limits, field_name) for task in frozen)
        if child_total > getattr(parent_grant.limits, field_name):
            raise ChildGrantViolation(
                ChildGrantViolationCodeV1.BUDGET_EXCEEDED,
                f"allocated child {field_name} exceeds the parent budget",
            )
    return frozen


def _require_limits_within(child: ReviewLimitsV1, parent: ReviewLimitsV1) -> None:
    for field_name in (
        "max_iterations",
        "max_tool_calls",
        "max_total_tokens",
        "deadline_ms",
        "max_child_tasks",
        "max_concurrency",
    ):
        if getattr(child, field_name) > getattr(parent, field_name):
            raise ChildGrantViolation(
                ChildGrantViolationCodeV1.BUDGET_EXCEEDED,
                f"child {field_name} exceeds the parent limits",
            )


def _contains(
    root_contains: RootContainmentV1,
    parent: EvidenceRootRefV1,
    child: EvidenceRootRefV1,
) -> bool:
    if parent.evidence_version_id != child.evidence_version_id:
        return False
    try:
        result = root_contains(parent, child)
    except Exception as error:
        raise ChildGrantViolation(
            ChildGrantViolationCodeV1.OUT_OF_SCOPE,
            "child root containment could not be established",
        ) from error
    if type(result) is not bool:
        raise TypeError("root_contains must return a boolean")
    return result


def _failure_intent(
    outcome: TerminalOutcomeV1,
    failure_code: str,
) -> ReviewTaskTerminalDraftV1:
    return ReviewTaskTerminalDraftV1(
        TerminalReviewDraftV1(
            outcome=outcome,
            answer=None,
            citations=(),
            evidence_gap_codes=(),
            inspected_count=0,
            unreviewed_count=1,
            coverage_state=CoverageStateV1.PARTIAL,
            clarification_question_id=None,
            provider_call_state=ProviderCallStateV1.NOT_REQUESTED,
        ),
        failure_code=failure_code,
    )


def _cancellation_requested(cancellation_check: Callable[[], bool]) -> bool:
    try:
        result = cancellation_check()
    except Exception as error:
        raise ReviewTaskRuntimeError("parent cancellation check failed") from error
    if type(result) is not bool:
        raise ReviewTaskRuntimeError("parent cancellation check returned a non-boolean")
    return result


def _require_identifier(value: object, *, field_name: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ChildGrantViolation(
            ChildGrantViolationCodeV1.INVALID_TASK,
            f"{field_name} must be a bounded identifier",
        )
    return value


def _require_sha256(value: object, *, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be lowercase SHA-256")
    return value
