"""Provider-neutral adaptation of the retained V1 send-reservation algorithm.

Resolve terminal exchange, reconcile captured output, validate authority, reserve
atomically with a second authority check, then allow one physical send. This port
retains no production storage, routing/pricing policy, credential or live transport.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock
from typing import Protocol

from sangrep_contracts import require_sha256

from sangrep_harness.wire import FrozenJsonObjectV1, freeze_json_object_v1


class ProviderSendOutcomeUnknown(RuntimeError):
    """A send was reserved and must never be repeated to discover its outcome."""


class ProviderExchangeFailed(RuntimeError):
    """A recorded transport failure, without adapter exception text or context."""


@dataclass(frozen=True, slots=True)
class ExchangeRecordV1:
    authority: str
    state: str
    payload: FrozenJsonObjectV1 | None = None


class ExchangeStoreV1(Protocol):
    """Trusted atomic repository; implement durable storage separately if required.

    Reservations must survive all interrupted/failed send and persistence paths.
    ``reserve`` performs ``validate`` and compare-and-insert in one critical section.
    Captures are immutable and may only finalize once. Terminal values must be read
    consistently with the exact request/route/grant authority digest.
    """

    def get(self, key: str, authority: str) -> ExchangeRecordV1 | None: ...
    def finalize(self, key: str, authority: str) -> ExchangeRecordV1 | None: ...
    def reserve(self, key: str, authority: str, validate: Callable[[], None]) -> bool: ...
    def capture(self, key: str, authority: str, payload: FrozenJsonObjectV1) -> None: ...
    def fail(self, key: str, authority: str) -> None: ...


class InMemoryExchangeStoreV1:
    """Thread-safe same-process reference repository; restart loses its state.

    This is intentionally not a crash-safe durable adapter. Reuse the same instance
    for retries of a logical send. It contains frozen payloads, never exception text.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._reservations: dict[str, str] = {}
        self._captures: dict[str, FrozenJsonObjectV1] = {}
        self._terminals: dict[str, ExchangeRecordV1] = {}

    def _require(self, key: str, authority: str) -> None:
        require_sha256(authority, field_name="exchange-authority")
        if type(key) is not str or not key or len(key) > 256:
            raise ValueError("exchange-authority-invalid")
        if key in self._reservations and self._reservations[key] != authority:
            raise ValueError("exchange-authority-mismatch")

    def get(self, key: str, authority: str) -> ExchangeRecordV1 | None:
        with self._lock:
            self._require(key, authority)
            return self._terminals.get(key)

    def get_capture(self, key: str, authority: str) -> FrozenJsonObjectV1 | None:
        with self._lock:
            self._require(key, authority)
            return self._captures.get(key)

    def finalize(self, key: str, authority: str) -> ExchangeRecordV1 | None:
        with self._lock:
            self._require(key, authority)
            if key not in self._terminals and key in self._captures:
                self._terminals[key] = ExchangeRecordV1(authority, "completed", self._captures[key])
            return self._terminals.get(key)

    def reserve(self, key: str, authority: str, validate: Callable[[], None]) -> bool:
        with self._lock:
            self._require(key, authority)
            if key in self._reservations:
                return False
            validate()
            self._reservations[key] = authority
            return True

    def capture(self, key: str, authority: str, payload: FrozenJsonObjectV1) -> None:
        with self._lock:
            self._require(key, authority)
            if key not in self._reservations or key in self._terminals:
                raise ValueError("exchange-capture-invalid")
            if key in self._captures and self._captures[key] != payload:
                raise ValueError("exchange-capture-conflict")
            if type(payload) is not FrozenJsonObjectV1:
                raise ValueError("exchange-capture-invalid")
            self._captures[key] = payload

    def fail(self, key: str, authority: str) -> None:
        with self._lock:
            self._require(key, authority)
            if key not in self._reservations or key in self._captures or key in self._terminals:
                raise ValueError("exchange-terminal-conflict")
            self._terminals[key] = ExchangeRecordV1(authority, "failed")


class ProviderExchangeGatewayV1:
    """Enforce the retained reserve-before-send ordering through explicit ports."""

    def __init__(self, repository: ExchangeStoreV1) -> None:
        if any(
            not callable(getattr(repository, name, None))
            for name in ("get", "finalize", "reserve", "capture", "fail")
        ):
            raise ValueError("exchange-store-incomplete")
        self.repository = repository

    @staticmethod
    def _response(record: ExchangeRecordV1, authority: str) -> FrozenJsonObjectV1:
        if record.authority != authority:
            raise ValueError("exchange-authority-mismatch")
        if record.state == "failed":
            raise ProviderExchangeFailed("provider-exchange-failed")
        if record.state != "completed" or record.payload is None:
            raise ProviderSendOutcomeUnknown("provider-outcome-unknown")
        return record.payload

    def complete(
        self,
        key: str,
        authority: str,
        validate: Callable[[], None],
        send: Callable[[], object],
    ) -> FrozenJsonObjectV1:
        """Return the frozen first result or refuse; never retry physical transport.

        ``authority`` commits to the grant, provider protocol and canonical request.
        The caller supplies a validator against its current authority. Failure after
        reservation retains the reservation, including interrupted calls and failed
        capture/finalization. Exception payloads are never recorded or surfaced.
        """
        existing = self.repository.get(key, authority)
        if existing is not None:
            return self._response(existing, authority)
        captured = self.repository.finalize(key, authority)
        if captured is not None:
            return self._response(captured, authority)
        validate()
        if not self.repository.reserve(key, authority, validate):
            existing = self.repository.get(key, authority)
            if existing is not None:
                return self._response(existing, authority)
            raise ProviderSendOutcomeUnknown("provider-outcome-unknown")
        failed = False
        interrupted = False
        payload: FrozenJsonObjectV1 | None = None
        try:
            payload = freeze_json_object_v1(send())
        except Exception:
            failed = True
        except BaseException:
            interrupted = True
        if failed:
            try:
                self.repository.fail(key, authority)
            except BaseException:
                interrupted = True
            if not interrupted:
                raise ProviderExchangeFailed("provider-exchange-failed")
        if interrupted:
            raise ProviderSendOutcomeUnknown("provider-outcome-unknown")
        assert payload is not None
        persisted: ExchangeRecordV1 | None = None
        try:
            self.repository.capture(key, authority, payload)
            persisted = self.repository.finalize(key, authority)
        except BaseException:
            pass
        if persisted is None:
            raise ProviderSendOutcomeUnknown("provider-outcome-unknown")
        return self._response(persisted, authority)
