"""Offline hosted-audit recovery probes use synthetic metadata and archive bytes."""

import importlib.util
import io
import json
import stat
import subprocess
import sys
import tarfile
import zipfile
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def audit(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    loader = SourceFileLoader(
        "hosted_recovery_audit", str(ROOT / "scripts/audit-public-hosted-metadata")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    loader.exec_module(module)
    return module


def zip_bytes(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)
    return stream.getvalue()


def test_existing_artifact_with_authoritative_empty_attestation_inventory(audit, monkeypatch):
    payload = zip_bytes({"example.txt": b"Synthetic component preview"})
    repository = {
        "id": 1,
        "full_name": "sangrep/harness",
        "private": True,
        "default_branch": "master",
    }
    monkeypatch.setattr(
        audit,
        "_object",
        lambda endpoint, **kw: repository if endpoint == "repos/sangrep/harness" else None,
    )
    monkeypatch.setattr(audit, "_collect_discussions", lambda *args: ([], []))
    monkeypatch.setattr(audit, "_json", lambda *args, **kw: [])
    monkeypatch.setattr(audit, "_gh", lambda *args, **kw: payload)
    monkeypatch.setattr(
        audit, "_collect_git_history", lambda *args: ([], {"commits": 1, "blobs": 1})
    )

    def inventory(endpoint, **kwargs):
        if endpoint == "repos/sangrep/harness/actions/artifacts?per_page=100":
            return [{"id": 7, "expired": False}]
        return []

    monkeypatch.setattr(audit, "_list", inventory)
    result, findings = audit.collect_live_inventory("sangrep/harness")
    assert findings == []
    assert result["surfaces"]["artifacts"][0]["contentReceipt"]["entries"]


def test_nested_wheel_content_is_inspected(audit):
    wheel = zip_bytes({"example/__init__.py": b'"""Synthetic public module."""\n'})
    findings, receipt = audit._scan_zip(zip_bytes({"example.whl": wheel}), source="artifact:7")
    assert findings == []
    assert receipt["entries"][0]["children"][0]["sha256"]


def test_runner_root_is_projected_only_in_workflow_logs(audit):
    runner = b"/" + b"home/runner/work/harness/harness/src/example.py"
    payload = zip_bytes({"1_job/1_step.txt": runner})
    findings, _ = audit._scan_zip(payload, source="workflow-log:7")
    assert findings == []
    artifact_findings, _ = audit._scan_zip(payload, source="artifact:7")
    assert {finding.category for finding in artifact_findings} == {"local-absolute-path"}


def test_setup_uv_glob_list_projects_only_checkout_roots_in_its_log_context(audit):
    root = b"/" + b"home/runner/work/harness/harness"
    globs = root + b"/**/*requirements*.txt," + root + b"/**/pyproject.toml"
    context = b"2026-09-07T10:47:38.8472618Z Searching files using cache dependency glob: "
    findings, _ = audit._scan_zip(zip_bytes({"step.txt": context + globs}), source="workflow-log:1")
    assert findings == []
    other, _ = audit._scan_zip(
        zip_bytes({"step.txt": b"unrecognized: " + globs}), source="workflow-log:1"
    )
    assert {finding.category for finding in other} == {"local-absolute-path"}
    bad_globs = globs + b",/" + b"Users/person/private.txt"
    bad, _ = audit._scan_zip(zip_bytes({"step.txt": context + bad_globs}), source="workflow-log:1")
    assert {finding.category for finding in bad} == {"local-absolute-path"}


@pytest.mark.parametrize(
    "name", ["../escape.txt", "/absolute.txt", "safe/../../escape.txt", "C:\\bad.txt"]
)
def test_archive_traversal_is_refused(audit, name):
    with pytest.raises(audit.HostedAuditError):
        audit._scan_zip(zip_bytes({name: b"synthetic"}), source="artifact:1")


def test_archive_symlink_is_refused(audit):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        member = zipfile.ZipInfo("link.txt")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, "target.txt")
    with pytest.raises(audit.HostedAuditError):
        audit._scan_zip(stream.getvalue(), source="artifact:1")


@pytest.mark.parametrize(
    "suffix", [b"/../../person/private.txt", b"-private/file.txt", b".private/file.txt"]
)
def test_runner_projection_keeps_escape_and_lookalike_paths_blocked(audit, suffix):
    path = b"/" + b"home/runner/work/_temp" + suffix
    findings, _ = audit._scan_zip(zip_bytes({"step.txt": path}), source="workflow-log:1")
    assert {finding.category for finding in findings} == {"local-absolute-path"}


def test_nested_wheel_does_not_hide_sensitive_payload(audit):
    marker = b"ghp_" + b"a" * 24
    findings, _ = audit._scan_zip(
        zip_bytes({"a.whl": zip_bytes({"data.txt": marker})}), source="artifact:1"
    )
    assert {finding.category for finding in findings} == {"github-token"}
    assert marker.decode() not in str(findings)


def test_unrecognized_binary_is_not_ignored(audit):
    findings, _ = audit._scan_zip(
        zip_bytes({"payload.bin": b"unknown\x00payload"}), source="artifact:1"
    )
    assert {finding.category for finding in findings} == {"unrecognized-binary"}


def test_nested_archives_share_depth_and_size_limits(audit, monkeypatch):
    import hosted_audit_content as content

    payload = b"payload"
    for _ in range(content.MAX_DEPTH + 2):
        payload = zip_bytes({"nested.zip": payload})
    with pytest.raises(audit.HostedAuditError):
        audit._scan_zip(payload, source="artifact:1")

    payload = zip_bytes({"a.zip": zip_bytes({"a.txt": b"x" * 128}), "b.txt": b"y" * 128})
    monkeypatch.setattr(content, "MAX_EXPANDED_BYTES", 200)
    with pytest.raises(audit.HostedAuditError):
        audit._scan_zip(payload, source="artifact:1")


def test_nested_pages_tar_accepts_only_empty_root_directory(audit):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        root = tarfile.TarInfo(".")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        member = tarfile.TarInfo("./index.html")
        member.size = 4
        archive.addfile(member, io.BytesIO(b"docs"))
    findings, receipt = audit._scan_zip(
        zip_bytes({"artifact.tar.gz": stream.getvalue()}), source="artifact:1"
    )
    assert findings == []
    assert len(receipt["entries"][0]["children"]) == 1


def test_nonempty_archive_directory_is_not_ignored(audit):
    with pytest.raises(audit.HostedAuditError):
        audit._scan_zip(zip_bytes({"directory/": b"hidden payload"}), source="artifact:1")


def test_archive_comments_are_scanned(audit):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.comment = b"ghp_" + b"a" * 24
        archive.writestr("safe.txt", "Public")
    findings, _ = audit._scan_zip(stream.getvalue(), source="artifact:1")
    assert {finding.category for finding in findings} == {"github-token"}


def test_unknown_zip_extra_fields_are_refused(audit):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        member = zipfile.ZipInfo("safe.txt")
        member.extra = b"\xff\xff\x02\x00xx"
        archive.writestr(member, b"safe")
    with pytest.raises(audit.HostedAuditError):
        audit._scan_zip(stream.getvalue(), source="artifact:1")


def test_attestation_404_is_not_absence(audit, monkeypatch):
    def unavailable(*args, **kwargs):
        raise audit.HostedAuditError("GitHub hosted surface could not be inventoried")

    monkeypatch.setattr(audit, "_list", unavailable)
    with pytest.raises(audit.HostedAuditError, match="attestation-enumeration-unavailable"):
        audit._collect_attestations("sangrep/harness", 1, [])


@pytest.mark.parametrize(
    "rows", [[{}], [{"id": True, "name": "harness"}], [{"id": 1, "name": "different"}]]
)
def test_malformed_attestation_repository_inventory_is_not_absence(audit, monkeypatch, rows):
    monkeypatch.setattr(audit, "_list", lambda *args, **kw: rows)
    with pytest.raises(audit.HostedAuditError):
        audit._collect_attestations("sangrep/harness", 1, [])


def test_present_attestations_query_subjects_without_claiming_exhaustive_coverage(
    audit, monkeypatch
):
    calls = []

    def inventory(endpoint, **kw):
        calls.append(endpoint)
        if endpoint.startswith("orgs/"):
            return [{"id": 1, "name": "harness"}]
        return []

    monkeypatch.setattr(audit, "_list", inventory)
    result = audit._collect_attestations("sangrep/harness", 1, ["a" * 64])
    assert any("attestations/sha256:" + "a" * 64 in endpoint for endpoint in calls)
    assert result["complete"] is False
    assert result["reason"] == "unbounded-subject-inventory"


def test_rest_collection_keeps_all_pages(audit, monkeypatch):
    monkeypatch.setattr(
        audit,
        "_gh",
        lambda *args, **kw: json.dumps([{"jobs": [{"id": 1}]}, {"jobs": [{"id": 2}]}]).encode(),
    )
    assert audit._list("synthetic/jobs", collection_key="jobs") == [{"id": 1}, {"id": 2}]


def test_git_history_includes_deleted_files_and_nondefault_branches(audit, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        return subprocess.run(
            ["git", "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.com", *args],
            cwd=repo,
            check=True,
            capture_output=True,
        ).stdout

    git("init", "-b", "master")
    (repo / "safe.txt").write_text("Synthetic public component")
    git("add", ".")
    git("commit", "-m", "Initial")
    git("checkout", "-b", "topic")
    (repo / "old.txt").write_text("ghp_" + "a" * 24)
    git("add", ".")
    git("commit", "-m", "Synthetic prior file")
    git("rm", "old.txt")
    git("commit", "-m", "Remove prior file")
    git("checkout", "master")
    findings, receipt = audit._scan_git_repository(repo)
    assert {finding.category for finding in findings} == {"github-token"}
    assert receipt["commits"] == 3

    git("tag", "-a", "v1", "-m", "ghp_" + "b" * 24)
    tagged_findings, tagged_receipt = audit._scan_git_repository(repo)
    assert len([f for f in tagged_findings if f.category == "github-token"]) == 2
    assert tagged_receipt["annotatedTags"] == 1


def test_graphql_connection_scans_every_page(audit, monkeypatch):
    pages = iter(
        [
            {
                "data": {
                    "node": {
                        "items": {
                            "nodes": [{"id": "one"}],
                            "pageInfo": {"hasNextPage": True, "endCursor": "next"},
                        }
                    }
                }
            },
            {
                "data": {
                    "node": {
                        "items": {
                            "nodes": [{"id": "two"}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            },
        ]
    )

    def response(arguments, **kwargs):
        page = next(pages)
        if page["data"]["node"]["items"]["nodes"][0]["id"] == "two":
            assert "cursor=next" in arguments
        return page

    monkeypatch.setattr(audit, "_json", response)
    assert audit._connection("query", {}, ("data", "node", "items")) == [
        {"id": "one"},
        {"id": "two"},
    ]


@pytest.mark.parametrize(
    "page_info",
    [{"hasNextPage": True, "endCursor": None}, {"hasNextPage": "false", "endCursor": None}],
)
def test_invalid_pagination_cannot_claim_completeness(audit, monkeypatch, page_info):
    monkeypatch.setattr(
        audit, "_json", lambda *a, **kw: {"data": {"nodes": [], "pageInfo": page_info}}
    )
    with pytest.raises(audit.HostedAuditError):
        audit._connection("query", {}, ("data",))


def test_skipped_jobs_without_execution_record_unavailable_logs_honestly(audit, monkeypatch):
    monkeypatch.setattr(
        audit,
        "_list",
        lambda *a, **kw: [{"id": 9, "status": "completed", "conclusion": "skipped", "steps": []}],
    )

    def unavailable(arguments, **kwargs):
        assert kwargs["allow_absent"] is True
        return b""

    monkeypatch.setattr(audit, "_gh", unavailable)
    jobs, logs, findings = audit._collect_workflow_run(
        "sangrep/harness",
        {"id": 7, "status": "completed", "conclusion": "skipped", "run_attempt": 1},
    )
    assert findings == []
    assert len(jobs) == 1
    assert logs[0]["state"] == "unavailable-skipped-jobs"
    assert logs[0]["contentInspected"] is False


def test_executed_jobs_do_not_treat_missing_logs_as_skipped(audit, monkeypatch):
    monkeypatch.setattr(
        audit,
        "_list",
        lambda *a, **kw: [{"id": 9, "status": "completed", "conclusion": "success", "steps": []}],
    )
    monkeypatch.setattr(audit, "_gh", lambda *a, **kw: b"")
    with pytest.raises(audit.HostedAuditError):
        audit._collect_workflow_run(
            "sangrep/harness",
            {"id": 7, "status": "completed", "conclusion": "success", "run_attempt": 1},
        )


def test_all_run_attempts_and_available_skipped_logs_are_inspected(audit, monkeypatch):
    run = {"id": 7, "status": "completed", "conclusion": "skipped", "run_attempt": 2}
    monkeypatch.setattr(audit, "_object", lambda *a, **kw: {**run, "run_attempt": 1})
    monkeypatch.setattr(
        audit,
        "_list",
        lambda *a, **kw: [{"id": 9, "status": "completed", "conclusion": "skipped", "steps": []}],
    )
    observed = []

    def logs(arguments, **kwargs):
        observed.append(arguments[1])
        return zip_bytes({"step.txt": b"ghp_" + b"a" * 24})

    monkeypatch.setattr(audit, "_gh", logs)
    jobs, records, findings = audit._collect_workflow_run("sangrep/harness", run)
    assert len(jobs) == 2
    assert [record["attempt"] for record in records] == [1, 2]
    assert all(record["contentInspected"] for record in records)
    assert {finding.category for finding in findings} == {"github-token"}
    assert observed == [
        "repos/sangrep/harness/actions/runs/7/attempts/1/logs",
        "repos/sangrep/harness/actions/runs/7/attempts/2/logs",
    ]
