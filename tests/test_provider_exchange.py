"""Logical sends use one reservation even when transport or persistence fails."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest


def _runtime():
    from sangrep_harness.providers import exchange

    return exchange


def test_two_contenders_send_once():
    runtime = _runtime()
    entered, release = Event(), Event()
    calls = []
    store = runtime.InMemoryExchangeStoreV1()
    gateway = runtime.ProviderExchangeGatewayV1(store)

    def send():
        calls.append(1)
        entered.set()
        assert release.wait(2)
        return {"value": "synthetic"}

    def validate():
        return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        winner = pool.submit(gateway.complete, "turn-1", "a" * 64, validate, send)
        assert entered.wait(2)
        with pytest.raises(runtime.ProviderSendOutcomeUnknown):
            gateway.complete("turn-1", "a" * 64, validate, send)
        release.set()
        first = winner.result()
    assert gateway.complete("turn-1", "a" * 64, validate, send) == first
    assert len(calls) == 1


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_failed_or_interrupted_transport_never_resends(failure):
    runtime = _runtime()
    calls = []
    gateway = runtime.ProviderExchangeGatewayV1(runtime.InMemoryExchangeStoreV1())

    def send():
        calls.append(1)
        raise failure("synthetic private diagnostic")

    for _ in range(2):
        with pytest.raises(
            (runtime.ProviderExchangeFailed, runtime.ProviderSendOutcomeUnknown)
        ) as error:
            gateway.complete("turn-1", "a" * 64, lambda: None, send)
        assert "synthetic private diagnostic" not in str(error.value)
        assert error.value.__context__ is None
    assert len(calls) == 1


def test_authority_is_revalidated_at_reservation():
    runtime = _runtime()
    calls = []
    checks = []

    def validate():
        checks.append(1)
        if len(checks) == 2:
            raise ValueError("authority-changed")

    gateway = runtime.ProviderExchangeGatewayV1(runtime.InMemoryExchangeStoreV1())
    with pytest.raises(ValueError, match="authority-changed"):
        gateway.complete("turn-1", "a" * 64, validate, lambda: calls.append(1))
    assert calls == []


def test_persistence_failure_recovers_capture_without_resend():
    runtime = _runtime()

    class FailingStore(runtime.InMemoryExchangeStoreV1):
        def finalize(self, key, authority):
            if self.get_capture(key, authority) is not None and not getattr(self, "failed", False):
                self.failed = True
                raise OSError("synthetic persistence failure")
            return super().finalize(key, authority)

    calls = []
    gateway = runtime.ProviderExchangeGatewayV1(FailingStore())

    def send():
        calls.append(1)
        return {"value": "synthetic"}

    with pytest.raises(runtime.ProviderSendOutcomeUnknown):
        gateway.complete("turn-1", "a" * 64, lambda: None, send)
    assert gateway.complete("turn-1", "a" * 64, lambda: None, send).to_json_obj() == {
        "value": "synthetic"
    }
    assert len(calls) == 1


def test_protocol_or_request_substitution_is_refused():
    runtime = _runtime()
    gateway = runtime.ProviderExchangeGatewayV1(runtime.InMemoryExchangeStoreV1())
    gateway.complete("turn-1", "a" * 64, lambda: None, lambda: {"value": "synthetic"})
    with pytest.raises(ValueError, match="exchange-authority"):
        gateway.complete("turn-1", "b" * 64, lambda: None, lambda: {"value": "different"})


def test_incomplete_store_port_is_refused_before_a_send():
    runtime = _runtime()
    with pytest.raises(ValueError, match="exchange-store-incomplete"):
        runtime.ProviderExchangeGatewayV1(object())


def test_interrupted_capture_is_sanitized_and_recovers_without_resend():
    runtime = _runtime()

    class InterruptedStore(runtime.InMemoryExchangeStoreV1):
        def capture(self, key, authority, payload):
            super().capture(key, authority, payload)
            raise KeyboardInterrupt("synthetic private persistence diagnostic")

    gateway = runtime.ProviderExchangeGatewayV1(InterruptedStore())
    calls = []

    def send():
        calls.append(1)
        return {"value": "synthetic"}

    caught = None
    try:
        gateway.complete("turn-1", "a" * 64, lambda: None, send)
    except BaseException as error:
        caught = error
    assert isinstance(caught, runtime.ProviderSendOutcomeUnknown)
    assert "synthetic private persistence diagnostic" not in str(caught)
    assert gateway.complete("turn-1", "a" * 64, lambda: None, send).to_json_obj() == {
        "value": "synthetic"
    }
    assert len(calls) == 1


def test_typed_provider_failure_has_one_terminal_and_zero_resend():
    from sangrep_harness.providers.base import ProviderCallError

    runtime = _runtime()
    store = runtime.InMemoryExchangeStoreV1()
    gateway = runtime.ProviderExchangeGatewayV1(store)
    calls = []

    def send():
        calls.append(1)
        raise ProviderCallError("synthetic internal provider diagnostic")

    for _ in range(2):
        with pytest.raises(runtime.ProviderExchangeFailed) as refusal:
            gateway.complete("typed-failure", "a" * 64, lambda: None, send)
        assert "synthetic internal provider diagnostic" not in str(refusal.value)
        assert refusal.value.__context__ is None
    terminal = store.get("typed-failure", "a" * 64)
    assert terminal.state == "failed"
    assert terminal.payload is None
    assert len(calls) == 1
