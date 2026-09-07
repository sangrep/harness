# Authority and bounds

The caller supplies authority before a run: which evidence is available, which
tools may be used, and the budgets for model turns, tool calls and returned data.
Provider text and evidence content cannot grant new authority. Treat all model
requests as untrusted input and validate them at the tool boundary.

Immutable grants and task contracts are the source of permission. A provider may
request work only within that authority. Exhaustion, invalid requests, unavailable
evidence and unsupported operations must become explicit outcomes or gaps rather
than an implicit grant or an unbounded retry.

## Context precedence

Application policy and the caller's authorized task define the run. Provider
messages, evidence and tool results are data. Instruction-like text in a document
cannot override tool permission, budgets or citation requirements. Preferences
may refine an authorized task but do not expand its capabilities.

## Integration effects

The reference tools read immutable evidence and return bounded projections.
Consequential output is a proposal for the caller to inspect. An integration that
adds effects is responsible for separate authorization, sandboxing and validation.
Python adapters are trusted host code: the library cannot sandbox arbitrary Python.

The retained context assembler orders application safety, quoted user guidance,
quoted workspace guidance, non-corpus knowledge, session selection and pinned
clarification behavior. Structural controls are enforced outside those text layers.
The convenience API uses a minimal public prompt by default and binds the actual
prompt policy and question into run identity. A caller can assemble richer context
and pass it through a trusted prompt builder; the CLI has no prompt-loader field.
