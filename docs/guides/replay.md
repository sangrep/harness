# Replay a cited result

```bash
python examples/replay.py
```

`ReplayProviderV1` accepts immutable `ReplayTurnV1` records. Each contains the exact
semantic request SHA-256 and a normalized bounded response. It checks ordering,
request identity, exhaustion and unused records. It preserves the recorded provider
name and token counts, enabling identical terminal results, events and receipts.

Request identity binds the model identifier, policy, rendered conversation, tool
schemas and remaining budgets. The elapsed wall-clock timeout is excluded because
it is scheduling state; replay remains subject to the current run deadline.

Event-page replay is a separate retained capability in `sangrep_harness.replay`.
It validates ordered event chains and cursor/page commitments through a repository
port. It is not a provider replay or a permission to repeat tool effects.

Only synthetic transcripts belong in this repository. Real transcripts can contain
source evidence and prompts and need the caller's own retention and access policy.
