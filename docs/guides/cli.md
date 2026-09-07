# Headless JSON and JSONL

`run` reads one JSON object from stdin. `run --jsonl` accepts up to 128 records,
one per line. Each record is at most 2 MiB and is processed independently. Invalid
input emits a small `harnessError` with `errorCode: invalid_request`; it does not echo
input, a filesystem path or an exception. Oversized records stop the stream.

```json
{
  "schemaVersion": 1,
  "question": "Quote the access rule.",
  "evidence": {"relativePath": "rules.txt", "text": "Only observers enter.\n"},
  "provider": "cited"
}
```

Required fields are exactly `schemaVersion`, `question`, `evidence` and `provider`.
Optional fields are `includeTranscript` and `transcript`. Unknown fields, duplicate
JSON members, malformed Unicode, non-finite numbers and incompatible versions are
rejected. `evidence` is inline text with a safe label. It never causes a path lookup.

| Provider value | Effect |
| --- | --- |
| `cited` | Deterministic fake provider quotes real tool-returned paragraphs |
| `gap` | Exercises tools, then returns an explicit insufficient-evidence gap |
| `failure` | Produces a sanitized provider-failure outcome |
| `replay` | Requires a bounded transcript and exact request commitments |

Set `includeTranscript: true` to receive normalized provider turns for replay. Treat
transcripts as evidence-bearing data. To replay, submit the same question/evidence
with `provider: replay` and that transcript. Changing a request or adding unused
turns is refused. Transcript output is opt-in and is separate from the public receipt.

`review PATH --question TEXT` opens one explicitly caller-selected local file. It
rejects symlinks, non-regular files, detected changes during reading, unsupported
suffixes and oversized data. No CLI field loads Python code, tools or credentials.

Exit status is 0 for completed/gap review, 1 for provider/engine/budget failure, and
2 for invalid input. JSONL returns the highest encountered status. The CLI uses the
fixed reference budgets; Python callers may supply `ReviewLimitsV1`.
