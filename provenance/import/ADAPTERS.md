# Adapter contracts and integration work

The executable subset contains inherited algorithms. The `.py.txt` excerpts retain
additional orchestration logic while separating implementation ports. Dependencies
named by excerpt imports must be resolved explicitly; missing symbols must never be
replaced with permissive defaults. The excerpts are not a second executable runtime.

## Evidence

`ReviewEvidenceHeadV1` is a trusted interface over immutable evidence. Its adapter
must validate source/evidence/structure/projection record and payload identities,
ordered unique anchor occurrences, acyclic parent relationships, unambiguous roots,
and exact containment. `require_grant` must reject stale or mixed identities.
Citation admission requires an exact successful tool result and projection digest.
Implement the Markdown/TXT adapter against accepted public identity/hierarchy/citation
contracts, then run negative stale, ambiguous, overlapping, sibling-scope and
forged-tool tests. A structurally conforming Python object alone proves none of this.

The generic grant constructor now accepts this explicit protocol; the concrete
adapter's construction gate remains required before integrating that constructor.
This is a changed boundary requiring its own acceptance.

The head protocol includes both revisions, scoped traversal and depth, plus the
node/projection members used by all included consumers. Evidence entry points use
`evidence_port_boundary` to check adapter shape and convert invalid member access
to `EvidencePortError` (`invalid_evidence_adapter`) without exposing adapter data.
This check does not replace immutable identity, containment or provenance validation.

## Structural loop and prompts

`structural_loop.py.txt` retains bounded iteration/token/deadline checks, cancellation,
closed tool execution, citation admission and bounded repair. Supply a review-tool
adapter, validated evidence, a provider-neutral turn factory and a public prompt
builder. No standing prompt or product policy is included. The application must
supply the prompt builder through trusted code, never through evidence text.

## Provider reservation and replay

`provider_exchange.py.txt` retains both provider protocol branches. Supply the
preflight/egress value types, a validated authority resolver, append-only artifact
ports, and provider-neutral transport. Routing/pricing decisions are injected
validation ports; no model selection policy or price authority is supplied.

The required order is: resolve existing terminal exchange; reconcile captured
exchange; revalidate authority; reserve one physical send atomically; only the
reservation winner may invoke transport. A lost reservation with no reconciled
result raises an unknown-outcome refusal. Never retry transport to resolve that
state. Captured raw/normalized responses and tool results retain their ordered
commitments. Failure recording must not expose exception payloads.

The V1 artifact port includes `append_failed_exchange`. A caught `ProviderCallError`
must persist one sanitized failure receipt; reopening that receipt raises the typed
terminal failure without repeating transport. The focused synthetic probe covers
this branch using the actual provider failure type and the included completion code.

Required tests include two contenders/one physical call, failed or interrupted send
followed by zero resend, failed persistence followed by zero resend, captured
response recovery, authority change at reservation, protocol substitution, and
identical retry receipts. Production durability requires an external implementation
and separate populated-state, crash/reopen and failure-recovery tests.

## Durable task coordination

`run_ledger.py.txt`, `terminal_recovery.py.txt` and `durable_tasks.py.txt` retain
compare-and-append events, terminal uniqueness, child start-before-side-effect order,
conservative abandoned-task recovery and parent/child receipt binding. Implement
repository interfaces atomically. Reopening must never repeat a provider/tool call.
The runnable scheduler alone does not prove these persistent guarantees.

## Remaining component work

Connect and test the adapter excerpts; reconcile public contract identity; provide
Markdown/TXT snapshots, replay provider/CLI examples and package entry points;
build the standalone wheel/source and developer docs; complete license/provenance,
secret, public-boundary and independent review checks. Event-page replay and the
fake callable already exist here; a replay provider callable is still required.
