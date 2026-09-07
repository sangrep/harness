# Hosted publication audit

`scripts/audit-public-hosted-metadata` is a read-only, authenticated pre-publication
check. It inventories the exact private repository and emits a digest receipt only
when its supported surfaces are complete and public-boundary checks pass. It does
not enable Pages, deploy, change visibility or remove hosted data. The recovery is
tracked in [Issue #5](https://github.com/sangrep/harness/issues/5), under
[Issue #1](https://github.com/sangrep/harness/issues/1).

```bash
python scripts/audit-public-hosted-metadata \
  --repository sangrep/harness \
  --digest-output work/hosted-publication-receipt.json
```

## Inspected scope

- Authenticated GitHub REST metadata is paginated. Pull-request review threads and
  their comments, discussions, comments and replies use checked GraphQL cursors;
  malformed or repeated cursors block completeness.
- An isolated Git mirror scans all advertised refs and the PR head/base/merge
  roots returned by the API. It inspects reachable commit metadata, file paths and
  every distinct file version, including deleted files and nondefault branches.
  Shallow history, unsupported Git modes, unavailable roots and budget overruns
  block the audit. The boundary-policy file retains the existing narrow exemption
  for its own restricted-pattern definitions; secret scanning still applies.
- Every workflow attempt inventories all job pages and downloads its logs. Skipped
  runs are inspected when logs exist. A missing log is recorded as uninspected
  only when the attempt and every job/step explicitly report skipped execution;
  missing execution logs otherwise block the audit.
- Nonexpired Actions artifacts are downloaded by their authenticated IDs and
  checked against any API-provided digest. Supported release assets are downloaded
  and checked as well. Original-byte digests remain in receipts.
- Nested ZIPs, wheels, tar files and tar-gzip archives are inspected without
  extracting members to disk. Each outer archive is limited to 64 MiB input,
  128 MiB total expanded content, 10,000 members and four nested levels. Paths,
  links, duplicate members, nonempty directories, comments, unknown binary files
  and prohibited file types remain checked. ZIP local records, central records and
  the footer must account for the envelope; preambles, trailers, gaps and truncated
  original names are refused. ZIP extra fields are currently refused. TAR header
  fields are scanned, decoded framing counts against the expansion budget, and
  termination padding must be zero. Gzip wrappers permit no unaccounted trailer.
- ZIP member decoding supports stored and deflate data only. Every member,
  including a directory's empty payload, must match its declared size and CRC;
  deflate must reach EOF and consume its entire accounted compressed range.
  Other compression methods are refused. The output limit is admitted before
  decoding, and decoding is capped at the declared size plus one overflow byte.
- TAR supports ordinary GNU long names and PAX path, ownership, time and comment
  metadata. PAX `size` overrides, sparse keys, duplicate keys within a header and
  unrecognized extensions are refused during raw framing inspection, before opening the TAR
  reader. Each parsed ordinary member must match the accounted size, type and
  data offset; its bytes are sliced from that bounded raw span. Unmatched raw
  members are refused. Prepaid framing never permits extra interpreted output.
- Workflow-log projection recognizes only the established GitHub runner roots,
  rejects parent traversal and lookalikes, and preserves secret scanning. The
  timestamped setup-uv cache-glob message has a specific comma-list normalization;
  arbitrary comma-separated content gets no extra path exception. Artifacts and
  repository files never receive the runner-path projection.

Cache coverage remains authenticated metadata only; cache payloads are not
downloaded by this tool. Nonempty package inventories and expired/unavailable
artifact content are refused. Unknown payload formats do not become successful
empty inventories. These bounds deliberately avoid a general package or metadata
ingestion system.

## Attestation authority

Attestation absence requires successful, paginated, authenticated
[repository enumeration](https://docs.github.com/en/rest/orgs/attestations#list-attestation-repositories)
that does not contain this repository's identity. A 404, authentication failure or
malformed response is an authority failure, never an empty inventory.

If the repository is listed, the tool queries
[attestations for known subject digests](https://docs.github.com/en/rest/repos/attestations#list-attestations),
including observed archive and member digests. That endpoint does not enumerate all
historical subjects, so such a response does not establish exhaustive subject
coverage. The tool refuses publication authority for that case. This is a
supported/refused-case boundary, not a claim that unattached attestations exist.

[GitHub's feature-availability documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
can inform an endpoint investigation; current feature availability alone does not
prove historical absence. Account configuration is not included in audit receipts.
The maintainer must resolve unavailable authority separately; there is no bypass,
plan change or implied publication approval in this tool.

## Evidence and nonclaims

Focused tests use synthetic metadata, real temporary Git histories and bounded
archive fixtures. They do not create live receipt authority. Successful local
archive/log probes are diagnostic evidence; the maintainer still performs the
final live inventory, review/CI/branch snapshot and measured Pages/public
acceptance. A blocked audit does not produce a new passing receipt.

The runner-path helper is narrowly adapted from an immutable accepted Sangrep
Contracts revision. `provenance/hosted-audit-reuse-v1.json`,
the retained upstream notice and Apache-2.0 text account for that source. Runtime
contract consumption and the component's licensing terms are unchanged.
