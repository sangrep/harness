# Evidence and provider adapters

An adapter is trusted Python code injected by the caller. Evidence and provider
output cannot select or construct one. The reference
[`CatalogAdapter` example](https://github.com/sangrep/harness/blob/master/examples/custom_evidence_adapter.py)
turns an explicitly selected in-memory text record into a validated snapshot:

```bash
python examples/custom_evidence_adapter.py
```

Use `snapshot_text_v1` for byte sources and `snapshot_file_v1` for an explicit host
file selection. `text_evidence_head_v1` rebuilds the entire snapshot to validate
source, evidence, structure and projection identities before minting a grant.

For another evidence profile, implement the complete `ports.ReviewEvidenceHeadV1`
interface. Construction must validate public records, ordered unique occurrences,
acyclic parents, payload digests and exact containment. `require_grant` must reject
stale/mixed identities and overlapping roots. Protocol conformance checks only the
interface; it does not validate evidence. The low-level structural loop accepts a
trusted complete port. The convenience API validates the reference text profile.

The retained tools are `list_scope`, `outline`, `read_nodes`, `search` and
`query_blocks`. Tool names and arguments are closed, results are bounded, and only
successful results can admit citations. Regex filtering uses a restricted subset
without grouping, repetition or backreferences.

A provider is an `AgentModelCallable` receiving `AgentModelRequest`. The headless
adapter requires bounded `AgentModelResponse` values with integer token usage.
The structural loop sets `AgentModelRequest.review_authority_sha256` from the
immutable task/grant/evidence and configured limits. Headless request identity
rejects a missing or malformed commitment. Generic provider adapters may still use
the request type without this headless-only field.
Opaque continuations, images and live transport are outside this profile. Inherited
provider protocol/egress value types remain available for separately reviewed
integrations; they do not enable network access.

The prompt builder is a separate trusted callable. The default public policy
requires tool admission and citations and treats document instructions as data.
Replacing the prompt does not change engine grants or budgets.
