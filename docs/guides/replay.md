# Replay a cited result

```bash
python examples/replay.py
```

`ReplayProviderV1` accepts immutable `ReplayTurnV1` records. Each contains the exact
semantic request SHA-256 and a normalized bounded response. It checks ordering,
request identity, exhaustion and unused records. It preserves the recorded provider
name and token counts, enabling identical terminal results, events and receipts.

Request identity binds the immutable task and grant, including evidence identity,
selected roots, admitted tools and all declared limits, as well as the model,
policy, conversation, tool schemas and remaining counters. The trusted structural
loop supplies the mandatory `review_authority_sha256` commitment. A first-turn gap
cannot be replayed under different evidence or limits before any tools have run.

Elapsed timeout and the process clock origin are excluded because they are
scheduling state. The declared deadline duration remains bound to authority.
Replay remains subject to the current run deadline. Earlier development transcripts
without the authority-bound request identity are incompatible and must be regenerated;
there is no permissive fallback for an unbound headless request.

Event-page replay is a separate retained capability in `sangrep_harness.replay`.
It validates ordered event chains and cursor/page commitments through a repository
port. It is not a provider replay or a permission to repeat tool effects.

Only synthetic transcripts belong in this repository. Real transcripts can contain
source evidence and prompts and need the caller's own retention and access policy.
