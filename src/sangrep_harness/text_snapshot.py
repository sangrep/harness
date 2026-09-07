"""Immutable UTF-8 Markdown/TXT evidence backed by versioned public contracts.

Only caller-selected files are opened. Providers receive snapshots through adapters,
never paths. Markdown structure recognizes ATX headings outside fenced code; this is
text evidence, not a CommonMark renderer. Offsets count decoded Unicode characters.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

import sangrep_contracts as c

MAX_SOURCE_BYTES = 1024 * 1024
MAX_SOURCE_LINES = 4096
PROFILE = "harness.text.v1"
PROFILE_SHA = hashlib.sha256(b"UTF-8;ATX-headings;fenced-code;line-leaves;v1").hexdigest()
_HEADING = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


@dataclass(frozen=True, slots=True)
class TextSnapshotV1:
    """A fully materialized source snapshot; fields contain no live file handles.

    ``nodes`` and ``projections`` use matching order and occurrence identities.
    Source bytes and projected text remain fixed after ingestion. The root covers
    the complete text; section nodes cover their heading and descendant lines.
    """

    source_bytes: bytes
    text: str
    relative_path: str
    source: c.SourceObjectVersionV1
    evidence: c.EvidenceVersionV1
    structure: c.StructureRevisionV1
    projection: c.ProjectionRevisionV1
    nodes: tuple[c.EvidenceNodeV1, ...]
    projections: tuple[c.ProjectedNodeV1, ...]


@dataclass(frozen=True, slots=True)
class _Entry:
    kind: str
    start: int
    end: int
    parent: int | None
    title: str | None = None


def _entries(lines: list[str], *, markdown: bool) -> list[_Entry]:
    entries = [_Entry("root", 0, len(lines), None)]
    headings: dict[int, tuple[int, str]] = {}
    fence: str | None = None
    if markdown:
        for index, line in enumerate(lines):
            match = _FENCE.match(line)
            if match:
                marker, remainder = match.groups()
                if fence is None:
                    fence = marker
                elif marker[0] == fence[0] and len(marker) >= len(fence) and not remainder.strip():
                    fence = None
                continue
            heading = _HEADING.match(line) if fence is None else None
            if heading:
                headings[index] = (len(heading[1]), heading[2])
    stack: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        if index in headings:
            level, title = headings[index]
            while stack and stack[-1][0] >= level:
                stack.pop()
            end = next(
                (i for i, (depth, _) in headings.items() if i > index and depth <= level),
                len(lines),
            )
            parent = stack[-1][1] if stack else 0
            entries.append(_Entry("section", index, end, parent, title))
            stack.append((level, len(entries) - 1))
        if line.strip():
            parent = stack[-1][1] if stack else 0
            kind = "heading" if index in headings else "paragraph"
            entries.append(_Entry(kind, index, index + 1, parent))
    return entries


def snapshot_text_v1(content: bytes, *, relative_path: str) -> TextSnapshotV1:
    """Admit at most 1 MiB/4096 lines of UTF-8 text from caller-owned bytes.

    The label must be safe and relative, ending in ``.md`` or ``.txt``. A UTF-8 BOM
    is removed from the text projection but retained in source bytes and digest.
    Invalid encoding, NUL bytes, unsupported formats and excess bounds raise a
    safe ``ValueError``. This function performs no filesystem or network I/O.
    """
    try:
        c.require_safe_relative_path_label_v1(relative_path, is_root=False)
        if Path(relative_path).suffix.lower() not in {".md", ".txt"}:
            raise ValueError
        if type(content) is not bytes or len(content) > MAX_SOURCE_BYTES or b"\x00" in content:
            raise ValueError
        text = content.decode("utf-8-sig")
        lines = text.splitlines(keepends=True)
        if len(lines) > MAX_SOURCE_LINES:
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("text-snapshot-input-invalid") from None
    content_sha = hashlib.sha256(content).hexdigest()
    source_id = "source:" + c.canonical_json_sha256(relative_path)
    source_version_id = "version:" + c.canonical_json_sha256([source_id, content_sha])
    evidence_id = "evidence:" + c.canonical_json_sha256([source_version_id, PROFILE_SHA])
    structure_id = "structure:" + c.canonical_json_sha256([evidence_id, PROFILE_SHA])
    projection_id = "projection:" + c.canonical_json_sha256([structure_id, PROFILE_SHA])
    source = c.SourceObjectVersionV1(
        source_id,
        source_version_id,
        c.SourceObjectKindV1.FILE,
        len(content),
        content_sha,
        "text/markdown" if relative_path.lower().endswith(".md") else "text/plain",
        c.CustodyStateV1.EPHEMERAL,
    )
    entries = _entries(lines, markdown=relative_path.lower().endswith(".md"))
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    anchors = ["anchor:" + c.canonical_json_sha256([structure_id, i]) for i in range(len(entries))]
    occurrences = [f"occurrence:{i}" for i in range(len(entries))]
    nodes: list[c.EvidenceNodeV1] = []
    projections: list[c.ProjectedNodeV1] = []
    for index, entry in enumerate(entries):
        payload = text[offsets[entry.start] : offsets[entry.end]]
        locator = c.TextFileLocatorV1(
            source_version_id,
            relative_path,
            entry.start + 1,
            max(entry.start + 1, entry.end),
            offsets[entry.start],
            offsets[entry.end],
        )
        wire: dict[str, c.JsonValue] = {
            "schemaVersion": 1,
            "kind": "evidenceNode",
            "evidenceVersionId": evidence_id,
            "structureRevisionId": structure_id,
            "rootAnchorId": anchors[0],
            "anchorId": anchors[index],
            "occurrenceId": occurrences[index],
            "parentAnchorId": anchors[entry.parent] if entry.parent is not None else None,
            "parentOccurrenceId": occurrences[entry.parent] if entry.parent is not None else None,
            "containmentKind": "physical",
            "ordinal": index,
            "nodeKind": entry.kind,
            "title": entry.title,
            "structuralContent": {
                "startLine": entry.start + 1,
                "endLine": max(entry.start + 1, entry.end),
            },
            "sourceLocator": locator.to_json_obj(),
            "coverageState": "complete",
            "warningCodes": [],
            "omissionCodes": [],
        }
        wire["canonicalNodeSha256"] = c.canonical_json_sha256(wire)
        nodes.append(c.EvidenceNodeV1.from_json_obj(wire))
        projections.append(
            c.ProjectedNodeV1(
                projection_id,
                structure_id,
                anchors[index],
                occurrences[index],
                c.ProjectionPayloadKindV1.TEXT,
                c.freeze_json_value_v1(payload),
                c.ProjectionInclusionStateV1.INCLUDED,
                c.CitableStateV1.CITABLE if payload.strip() else c.CitableStateV1.NOT_CITABLE,
                c.canonical_json_sha256(payload),
            )
        )
    graph_sha = c.canonical_json_sha256([node.canonical_node_sha256 for node in nodes])
    payload_sha = c.canonical_json_sha256([node.projected_payload_sha256 for node in projections])
    evidence = c.EvidenceVersionV1(
        evidence_id,
        (source_version_id,),
        PROFILE,
        PROFILE_SHA,
        c.EvidenceCoverageStateV1.COMPLETE,
        (),
        (),
        c.canonical_json_sha256([graph_sha, payload_sha]),
    )
    structure = c.StructureRevisionV1(structure_id, evidence_id, PROFILE, PROFILE_SHA, graph_sha)
    projection = c.ProjectionRevisionV1(
        projection_id, structure_id, PROFILE, "1", PROFILE_SHA, payload_sha
    )
    return TextSnapshotV1(
        content,
        text,
        relative_path,
        source,
        evidence,
        structure,
        projection,
        tuple(nodes),
        tuple(projections),
    )


def snapshot_file_v1(path: Path, *, relative_path: str | None = None) -> TextSnapshotV1:
    """Read one caller-selected regular file once, without writing source bytes.

    Reject symlinks, non-regular files, oversized input and detected changes during
    reading. The path is consumed only here and never appears in the snapshot or
    exception. Callers authorize filesystem selection; models cannot call this API.
    """
    try:
        if path.is_symlink():
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SOURCE_BYTES:
                raise ValueError
            content = stream.read(MAX_SOURCE_BYTES + 1)
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise ValueError
        return snapshot_text_v1(content, relative_path=relative_path or path.name)
    except (OSError, ValueError):
        raise ValueError("text-snapshot-input-invalid") from None
