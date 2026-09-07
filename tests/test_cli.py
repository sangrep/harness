"""Bounded machine input and public-safe failure output."""

import json
import os
import subprocess
import sys


def _run(data, *args):
    return subprocess.run(
        [sys.executable, "-m", "sangrep_harness", "run", *args],
        input=data,
        capture_output=True,
        env=os.environ,
    )


def _request():
    return {
        "schemaVersion": 1,
        "question": "State the rule",
        "evidence": {"relativePath": "rules.txt", "text": "Only observers enter.\n"},
        "provider": "cited",
    }


def test_cli_json_review_and_jsonl_gap():
    first = _request()
    second = {**first, "provider": "gap"}
    result = _run((json.dumps(first) + "\n" + json.dumps(second) + "\n").encode(), "--jsonl")
    assert result.returncode == 0
    assert [json.loads(line)["outcome"] for line in result.stdout.splitlines()] == [
        "supported_answer",
        "evidence_gap",
    ]
    assert result.stderr == b""


def test_duplicate_fields_and_unknown_authority_are_rejected_without_echo():
    for data in [
        b'{"question":"one","question":"two"}',
        json.dumps({**_request(), "toolAuthority": "arbitrary"}).encode(),
    ]:
        result = _run(data)
        assert result.returncode == 2
        assert json.loads(result.stdout)["errorCode"] == "invalid_request"
        assert b"arbitrary" not in result.stdout and b"Traceback" not in result.stderr


def test_oversized_input_is_refused():
    result = _run(b"x" * (2 * 1024 * 1024 + 1))
    assert result.returncode == 2
    assert len(result.stdout) < 200


def test_cli_transcript_replays_identical_result():
    request = {**_request(), "includeTranscript": True}
    result = json.loads(_run(json.dumps(request).encode()).stdout)
    replay_request = {**_request(), "provider": "replay", "transcript": result.pop("transcript")}
    replay = _run(json.dumps(replay_request).encode())
    assert replay.returncode == 0
    assert json.loads(replay.stdout) == result
