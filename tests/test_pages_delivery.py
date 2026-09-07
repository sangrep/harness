"""Manual Pages delivery rejects source drift and unapproved destinations offline."""

import importlib.util
import json
import os
import subprocess
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
PAGE_URL = "https://sangrep.github.io/harness/"


@pytest.fixture
def preflight(monkeypatch):
    loader = SourceFileLoader("pages_source", str(ROOT / "scripts/check-pages-source"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    for key, value in {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": "sangrep/harness",
        "GITHUB_REF": "refs/heads/master",
        "GITHUB_SHA": SHA,
        "REVIEWED_SOURCE_SHA": SHA,
    }.items():
        monkeypatch.setenv(key, value)
    return module


def responses(monkeypatch, preflight, *, checkout=SHA, branch=None, pages=None):
    payloads = {
        "git": checkout + "\n",
        "repos/sangrep/harness/git/ref/heads/master": json.dumps(
            {"object": {"sha": SHA}} if branch is None else branch
        ),
        "repos/sangrep/harness/pages": json.dumps(
            {
                "build_type": "workflow",
                "html_url": PAGE_URL,
                "cname": None,
                "https_enforced": True,
            }
            if pages is None
            else pages
        ),
    }
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        assert kwargs["check"] and kwargs["capture_output"] and kwargs["text"]
        if args == ["git", "rev-parse", "HEAD"]:
            assert kwargs["cwd"] == ROOT
            result = payloads["git"]
        else:
            assert args[:2] == ["gh", "api"] and len(args) == 3
            result = payloads[args[2]]
        return subprocess.CompletedProcess(args, 0, stdout=result)

    monkeypatch.setattr(preflight.subprocess, "run", run)
    return payloads, calls


def test_accepted_master_and_default_destination_use_read_only_calls(
    preflight, monkeypatch, capsys
):
    _, calls = responses(monkeypatch, preflight)
    assert preflight.main() == 0
    assert len(calls) == 3
    assert capsys.readouterr().out.endswith(f"source_sha={SHA}\n")


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_EVENT_NAME", "push"),
        ("GITHUB_REPOSITORY", "example/harness"),
        ("GITHUB_REF", "refs/heads/topic"),
        ("GITHUB_REF", "refs/tags/v1"),
        ("GITHUB_SHA", "b" * 40),
        ("REVIEWED_SOURCE_SHA", ""),
        ("REVIEWED_SOURCE_SHA", "a" * 39),
        ("REVIEWED_SOURCE_SHA", SHA + "\n"),
    ],
)
def test_bad_dispatch_stops_before_io(preflight, monkeypatch, key, value, capsys):
    _, calls = responses(monkeypatch, preflight)
    monkeypatch.setenv(key, value)
    assert preflight.main() == 1
    assert calls == []
    assert capsys.readouterr().err == "pages-preflight: blocked source-or-destination\n"


@pytest.mark.parametrize(
    "change",
    [
        {"checkout": "b" * 40},
        {"branch": {"object": {"sha": "b" * 40}}},
        {"branch": {"object": None}},
        {"branch": []},
        {"pages": []},
        {"pages": {}},
        {"pages": {"build_type": "legacy"}},
    ],
)
def test_source_drift_or_malformed_api_blocks(preflight, monkeypatch, change):
    responses(monkeypatch, preflight, **change)
    assert preflight.main() == 1


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("build_type", "legacy"),
        ("html_url", "https://example.com/"),
        ("cname", "example.com"),
        ("https_enforced", False),
        ("https_enforced", "true"),
        ("cname", "missing"),
    ],
)
def test_destination_requires_explicit_approved_values(preflight, monkeypatch, key, value):
    payloads, _ = responses(monkeypatch, preflight)
    endpoint = "repos/sangrep/harness/pages"
    pages = json.loads(payloads[endpoint])
    if value == "missing":
        del pages[key]
    else:
        pages[key] = value
    payloads[endpoint] = json.dumps(pages)
    assert preflight.main() == 1


@pytest.mark.parametrize("failure", ["disabled", "invalid-json"])
def test_api_failure_does_not_print_response(preflight, monkeypatch, capsys, failure):
    def run(args, **kwargs):
        if args[0] == "git":
            return subprocess.CompletedProcess(args, 0, stdout=SHA)
        if args[-1] == "repos/sangrep/harness/git/ref/heads/master":
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps({"object": {"sha": SHA}}))
        assert args == ["gh", "api", "repos/sangrep/harness/pages"]
        if failure == "disabled":
            raise subprocess.CalledProcessError(
                1, args, stderr="synthetic response must stay hidden"
            )
        return subprocess.CompletedProcess(args, 0, stdout="synthetic response must stay hidden")

    monkeypatch.setattr(preflight.subprocess, "run", run)
    assert preflight.main() == 1
    assert capsys.readouterr() == ("", "pages-preflight: blocked source-or-destination\n")


def test_workflow_has_no_automatic_trigger_or_build_deployment_authority():
    workflow = yaml.load((ROOT / ".github/workflows/pages.yml").read_text(), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {}
    build, deploy = workflow["jobs"]["build"], workflow["jobs"]["deploy"]
    assert build["permissions"] == {"contents": "read", "pages": "read"}
    assert deploy["permissions"] == {"contents": "read", "pages": "write", "id-token": "write"}
    assert deploy["needs"] == "build"
    assert deploy["environment"]["name"] == "github-pages"
    for job in (build, deploy):
        assert job["if"] == (
            "github.event_name == 'workflow_dispatch' && "
            "github.repository == 'sangrep/harness' && github.ref == 'refs/heads/master'"
        )
        assert job["steps"][0]["with"] == {
            "ref": "${{ github.sha }}",
            "persist-credentials": "false",
        }
        assert job["steps"][1]["run"] == "python3 -I scripts/check-pages-source"
        assert job["steps"][1]["env"]["REVIEWED_SOURCE_SHA"] == "${{ inputs.source_sha }}"
    assert build["steps"][-1]["with"] == {"path": "work/docs-site", "retention-days": "1"}
    assert "./scripts/check-gitleaks --docs-artifact" in build["steps"][-2]["run"]
    assert deploy["steps"][2]["with"] == {"artifact_name": "github-pages", "preview": "false"}


@pytest.mark.parametrize("artifact_exists", [True, False])
def test_docs_secret_scan_uses_fixed_artifact_in_manual_job(tmp_path, artifact_exists):
    scanner = tmp_path / "scanner"
    scanner.write_text(
        '#!/bin/sh\nif [ "$1" = version ]; then echo 8.30.1; exit 0; fi\n'
        'printf "%s\\n" "$@" > scanned-arguments\n'
    )
    scanner.chmod(0o700)
    if artifact_exists:
        output = tmp_path / "work/docs-site"
        output.mkdir(parents=True)
        (output / "index.html").write_text("<p>Synthetic docs</p>")
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/check-gitleaks"), "--docs-artifact"],
        cwd=tmp_path,
        env={
            **os.environ,
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "SANGREP_GITLEAKS_TEST_MODE": "true",
            "SANGREP_GITLEAKS_TEST_BIN": str(scanner),
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == (0 if artifact_exists else 1)
    if artifact_exists:
        assert (tmp_path / "scanned-arguments").read_text().splitlines() == [
            "dir",
            "--redact=100",
            "--no-banner",
            "--no-color",
            "--log-level=error",
            "--",
            "work/docs-site",
        ]
    else:
        assert result.stderr == "secret-scan: blocked category=docs-artifact-unavailable\n"
        assert not (tmp_path / "scanned-arguments").exists()
