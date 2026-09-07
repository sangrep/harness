# Gaps, failure and retry

```bash
python examples/gap.py
python examples/failure.py
python examples/retry.py
```

A gap has `outcome: evidence_gap`, no answer or citations, and an explicit
`insufficient_evidence` code. Missing evidence does not prove an event never happened.
An answer line without admitted citations gets one repair opportunity. If it still
fails, the engine returns no answer and `engine_failed`.

Provider exceptions become a typed failure without raw exception text. A logical
send follows the retained ordering: terminal lookup, captured-result reconciliation,
current authority validation, atomic reservation with revalidation, then one send.
A lost reservation never retries transport to discover the outcome. Captured output
can be finalized later; failed persistence retains the reservation.

Reuse `InMemoryExchangeStoreV1` for logical sends and `InMemoryRunRepositoryV1` for
whole-run retries in the same process. A completed run returns its original terminal
receipt without repeating provider or tool execution. A started, nonterminal run is
refused until conservatively recovered. `recover_nonterminal_runs` never calls a
provider or tool and records an unknown provider outcome when a request had started.

These repositories lose state when the process exits. They do not provide durable
crash/reopen guarantees. A durable implementation must atomically implement the
explicit ports and pass separate populated-state and crash/failure tests.

The retained task orchestrator prepares child run-start events before workers may
act. A previously prepared batch recovers through terminal bindings and parent
reconciliation, never by running workers again.
