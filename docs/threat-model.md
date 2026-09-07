# Threat model

## Assets and trust boundaries

The assets are source integrity, bounded resource use, authority, cited provenance
and the confidentiality of inputs. The caller and Python adapter implementations
are trusted host code. Documents, provider output, tool arguments, replay files
and CLI input are untrusted data. Package artifacts and build dependencies are a
supply-chain boundary.

| Threat | Required control | Limit |
| --- | --- | --- |
| Document instructions attempt to expand permission | Immutable caller grants and validated tools | Does not prove model reasoning is unaffected |
| Provider requests arbitrary paths or tools | No ambient model filesystem authority; allowlisted adapter interface | Host Python adapters need separate review |
| Unbounded loops or output | Turn, call and output budgets; bounded repair | Hard process isolation belongs to the caller |
| Fabricated or stale support | Admission, version/projection binding and containment | Citation validity is not semantic entailment |
| Changed source after admission | Immutable snapshot bytes and digest identity | Snapshot ingestion must itself be trusted |
| Replay mismatch | Recorded request/response binding and explicit failure | Replay data may contain sensitive material |
| Diagnostics leak inputs | Safe public outcomes and explicit local handling | Callers must protect their own logs |
| Dependency substitution | Exact contracts archive and wheel digests | Digest agreement is not a legal or security audit |

## Non-goals

The library does not provide a system sandbox, persistent vault, credential
manager, rich-document parser, product authorization or licensing service. It does
not sign or publish artifacts. No test result here authorizes consequential action.

Report vulnerabilities through the repository's [security policy](https://github.com/sangrep/harness/security/policy).
