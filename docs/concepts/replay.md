# Determinism and replay

Fake providers exercise the same engine boundary as other providers, with scripted
responses and no live model traffic. Replay makes a recorded sequence available to
that boundary again. A replay must stay bound to the request sequence and authority
it records; it must not silently continue with different evidence or extra calls.

Run identity, evidence digests, request ordering and budgets are inputs to
reproducibility. Tests compare deterministic outcomes and receipts, including the
failure path. Real-provider sampling, network behavior and semantic quality are
not qualified by fake or replay tests.

Fixtures in this repository are synthetic. Real transcripts may contain evidence
or sensitive prompts; inspect and sanitize them before storing or sharing them.
