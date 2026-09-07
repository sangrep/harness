# Evaluation and limitations

Use deterministic fake and replay providers to test mechanics: authority,
resource bounds, tools, admission, containment, repair, context precedence,
events, outcomes and receipts. Adversarial inputs should include fabricated
citations, stale identity, instruction-like evidence, unknown tools, budget
exhaustion, malformed requests and mismatched replay.

Safety regressions begin with a failing probe that demonstrates the missing
boundary. During construction run that probe and its directly affected neighbors.
At the frozen head run one focused acceptance batch with lint, formatting, typing,
package/CLI, docs, license/provenance, secret and public-boundary checks. Repeat only
when a change or failure justifies it.

The synthetic corpus is not an accuracy benchmark. Mechanical citation validation
must not be described as semantic entailment. Live-model quality, latency, pricing,
provider qualification, large-corpus performance, product integration and
rich-document support remain untested unless a separate evaluation explicitly
records them.

A check report identifies the tested commit and artifact digests. Local results
are local evidence; the PR check is CI evidence. Neither is a release approval.
