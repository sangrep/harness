"""Bounded JSON/JSONL process boundary and caller-selected file review."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import BinaryIO

from sangrep_harness.api import review_snapshot_v1
from sangrep_harness.providers.extractive import ExtractiveFakeProviderV1
from sangrep_harness.providers.replay_provider import ReplayProviderV1, ReplayTurnV1
from sangrep_harness.text_snapshot import snapshot_file_v1, snapshot_text_v1
from sangrep_harness.wire import freeze_json_object_v1

MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_JSONL_RECORDS = 128


def _pairs(values: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate-member")
        result[key] = value
    return result


def _decode(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("input-budget")
    value = json.loads(raw, object_pairs_hook=_pairs)
    freeze_json_object_v1(value)
    if not isinstance(value, dict):
        raise ValueError("request-object-required")
    return value


def review_request_v1(request: dict[str, object]) -> dict[str, object]:
    """Validate one exact request and return a proposal with optional explicit replay data.

    Request evidence contains inline text and a safe relative label, never a path
    to open. Only the ``review`` subcommand accepts a caller-selected filesystem path.
    No input field selects executable tools, Python adapters, prompts or credentials.
    """
    required = {"schemaVersion", "question", "evidence", "provider"}
    optional = {"transcript", "includeTranscript"}
    if set(request) - required - optional or not required <= set(request):
        raise ValueError("request-fields")
    if type(request["schemaVersion"]) is not int or request["schemaVersion"] != 1:
        raise ValueError("request-version")
    evidence = request["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {"relativePath", "text"}:
        raise ValueError("request-evidence")
    label, text = evidence["relativePath"], evidence["text"]
    question, mode = request["question"], request["provider"]
    include_transcript = request.get("includeTranscript", False)
    if (
        type(label) is not str
        or type(text) is not str
        or type(question) is not str
        or type(mode) is not str
        or type(include_transcript) is not bool
    ):
        raise ValueError("request-types")
    snapshot = snapshot_text_v1(text.encode("utf-8"), relative_path=label)
    if mode == "replay":
        raw_turns = request.get("transcript")
        if type(raw_turns) is not list or not 0 < len(raw_turns) <= 128:
            raise ValueError("request-transcript")
        turns = []
        for item in raw_turns:
            if (
                type(item) is not dict
                or set(item) != {"requestSha256", "response"}
                or type(item["requestSha256"]) is not str
            ):
                raise ValueError("request-transcript")
            turns.append(
                ReplayTurnV1(item["requestSha256"], freeze_json_object_v1(item["response"]))
            )
        provider = ReplayProviderV1(tuple(turns))
        result = review_snapshot_v1(snapshot, question=question, provider=provider)
        provider.require_exhausted()
    else:
        if "transcript" in request:
            raise ValueError("unexpected-transcript")
        result = review_snapshot_v1(
            snapshot, question=question, provider=ExtractiveFakeProviderV1(mode)
        )
    payload: dict[str, object] = dict(result.to_json_obj())
    if include_transcript:
        payload["transcript"] = [turn.to_json_obj() for turn in result.transcript]
    return payload


def _emit(value: object) -> None:
    print(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def _error() -> None:
    _emit({"schemaVersion": 1, "kind": "harnessError", "errorCode": "invalid_request"})


def _run(stream: BinaryIO, *, jsonl: bool) -> int:
    status = 0
    for _ in range(MAX_JSONL_RECORDS if jsonl else 1):
        raw = (
            stream.readline(MAX_REQUEST_BYTES + 1) if jsonl else stream.read(MAX_REQUEST_BYTES + 1)
        )
        if not raw and jsonl:
            return status
        try:
            payload = review_request_v1(_decode(raw))
        except (ValueError, TypeError, RecursionError, UnicodeError, KeyError):
            _error()
            status = 2
            if len(raw) > MAX_REQUEST_BYTES:
                return status
        else:
            _emit(payload)
            if payload["outcome"] in {"provider_failed", "engine_failed", "budget_exhausted"}:
                status = max(status, 1)
    if jsonl and stream.read(1):
        _error()
        return 2
    return status


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Exit 0: completed/gap; 1: failed review; 2: invalid input."""
    parser = argparse.ArgumentParser(description="Bounded cited Markdown/TXT evidence review")
    parser.add_argument("--version", action="version", version="sangrep-harness 0.1.0.dev0")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Read one JSON request or bounded JSONL from stdin")
    run.add_argument("--jsonl", action="store_true", help="At most 128 requests, one per line")
    review = commands.add_parser("review", help="Review one explicitly selected local file")
    review.add_argument("source", type=Path)
    review.add_argument("--question", required=True)
    review.add_argument("--provider", choices=("cited", "gap", "failure"), default="cited")
    args = parser.parse_args(argv)
    if args.command == "run":
        return _run(sys.stdin.buffer, jsonl=args.jsonl)
    try:
        snapshot = snapshot_file_v1(args.source)
        result = review_snapshot_v1(
            snapshot, question=args.question, provider=ExtractiveFakeProviderV1(args.provider)
        )
    except (ValueError, TypeError, OSError):
        _error()
        return 2
    payload = result.to_json_obj()
    _emit(payload)
    return (
        1 if payload["outcome"] in {"provider_failed", "engine_failed", "budget_exhausted"} else 0
    )
