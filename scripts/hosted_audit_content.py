"""Bounded inspection of hosted archives; archive members are never extracted to disk.

Runner-path projection is adapted from Sangrep Contracts under Apache-2.0.
See provenance/hosted-audit-reuse-v1.json and LICENSES/Apache-2.0.txt.
"""

from __future__ import annotations

import hashlib
import io
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

from public_boundary_policy import Finding, scan_bytes

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 10000
MAX_DEPTH = 4


class ContentAuditError(RuntimeError):
    pass


@dataclass
class ArchiveBudget:
    expanded: int = 0
    members: int = 0

    def admit(self, size: int) -> None:
        self.members += 1
        self.expanded += size
        if size < 0 or self.expanded > MAX_EXPANDED_BYTES or self.members > MAX_MEMBERS:
            raise ContentAuditError("archive-budget-exceeded")


def project_runner_paths(data: bytes, *, repository: str) -> bytes:
    # setup-uv emits comma-delimited checkout glob lists. Only this exact
    # timestamped message permits a delimiter to become a token boundary.
    glob_line = re.compile(
        rb"(?m)^(?P<prefix>\d{4}-\d{2}-\d{2}T[0-9:.]+Z "
        rb"Searching files using cache dependency glob: )(?P<globs>[^\r\n]*)$"
    )
    data = glob_line.sub(
        lambda match: match.group("prefix") + b", ".join(match.group("globs").split(b",")),
        data,
    )
    _, repository_name = repository.split("/", maxsplit=1)
    runner_home = b"/" + b"home" + b"/" + b"runner" + b"/"
    dependabot_home = b"/" + b"home" + b"/" + b"dependabot" + b"/"
    replacements = (
        (runner_home + f"work/{repository_name}/{repository_name}".encode(), b"repository-root"),
        (runner_home + b"work/_temp", b"github-runner-temp"),
        (runner_home + b".local", b"github-runner-local"),
        (dependabot_home + b"dependabot-updater", b"dependabot-updater-root"),
    )
    left_boundary = (
        rb"(?P<prefix>(?:^|[\s\x00])"
        rb"(?:['\"(]|[A-Za-z_][A-Za-z0-9_]*=['\"]|file://|(?i:includeif)\.gitdir:)?"
        rb")"
    )
    boundary = rb"(?=$|/|[\s\x00]|['\")]+(?=$|[\s\x00]))"
    for root, replacement in replacements:
        pattern = re.compile(left_boundary + re.escape(root) + boundary)

        def replace(match, value=replacement, current=data):
            remainder = re.split(rb"[\s\x00'\"<>)]", current[match.end() :], maxsplit=1)[0]
            if b".." in remainder.split(b"/"):
                return match.group(0)
            return match.group("prefix") + value

        data = pattern.sub(replace, data)
    return data


def _member_path(name: str, seen: set[str]) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or ":" in path.parts[0]
        or path.as_posix() in seen
    ):
        raise ContentAuditError("archive-path-invalid")
    seen.add(path.as_posix())
    return path


def scan_archive(
    payload: bytes,
    *,
    source: str,
    name: str = "artifact.zip",
    log_repository: str | None = None,
    budget: ArchiveBudget | None = None,
    depth: int = 0,
) -> tuple[list[Finding], dict]:
    if len(payload) > MAX_ARCHIVE_BYTES or depth > MAX_DEPTH:
        raise ContentAuditError("archive-budget-exceeded")
    budget = budget if budget is not None else ArchiveBudget()
    findings: list[Finding] = []
    entries: list[dict] = []
    seen: set[str] = set()

    def inspect(member_name: str, size: int, read, *, directory: bool = False) -> None:
        if directory and size:
            raise ContentAuditError("archive-directory-payload")
        if directory and member_name in {".", "./"}:
            if "." in seen:
                raise ContentAuditError("archive-path-invalid")
            seen.add(".")
            budget.admit(0)
            return
        path = _member_path(member_name, seen)
        budget.admit(size)
        entry_source = f"{source}:{member_name}"
        findings.extend(scan_bytes(member_name.encode(), source=f"{entry_source}:path"))
        if directory:
            return
        data = read()
        if len(data) != size:
            raise ContentAuditError("archive-member-size-mismatch")
        receipt = {
            "pathDigest": hashlib.sha256(member_name.encode()).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
        archive_name = member_name.lower().endswith((".zip", ".whl", ".tar", ".tar.gz", ".tgz"))
        if archive_name and log_repository is None:
            children_findings, children = scan_archive(
                data, source=entry_source, name=member_name, budget=budget, depth=depth + 1
            )
            findings.extend(children_findings)
            receipt["children"] = children["entries"]
        else:
            scanned = data
            suffix = path.suffix
            if log_repository is not None:
                if suffix not in {".txt", ".log"}:
                    raise ContentAuditError("workflow-log-member-unsupported")
                scanned = project_runner_paths(data, repository=log_repository)
                suffix = ".txt"
            findings.extend(scan_bytes(scanned, source=entry_source, suffix=suffix))
        entries.append(receipt)

    try:
        if name.lower().endswith((".zip", ".whl")):
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                findings.extend(scan_bytes(archive.comment, source=source + ":archive-comment"))
                for member in archive.infolist():
                    findings.extend(scan_bytes(member.comment, source=source + ":member-comment"))
                    kind = stat.S_IFMT(member.external_attr >> 16)
                    if (
                        kind not in {0, stat.S_IFREG, stat.S_IFDIR}
                        or member.flag_bits & 1
                        or member.extra
                    ):
                        raise ContentAuditError("archive-member-unsupported")
                    inspect(
                        member.filename,
                        member.file_size,
                        lambda selected=member: archive.read(selected),
                        directory=member.is_dir(),
                    )
        elif name.lower().endswith((".tar", ".tar.gz", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r|*") as archive:
                for member in archive:
                    for key, value in member.pax_headers.items():
                        findings.extend(
                            scan_bytes(f"{key}={value}".encode(), source=source + ":pax")
                        )
                    if not member.isfile() and not member.isdir():
                        raise ContentAuditError("archive-member-unsupported")

                    def read(selected=member):
                        stream = archive.extractfile(selected)
                        if stream is None:
                            raise ContentAuditError("archive-member-unreadable")
                        return stream.read(selected.size + 1)

                    inspect(member.name, member.size, read, directory=member.isdir())
        else:
            raise ContentAuditError("archive-format-unsupported")
    except (
        zipfile.BadZipFile,
        tarfile.TarError,
        OSError,
        EOFError,
        RuntimeError,
        ValueError,
    ) as error:
        if isinstance(error, ContentAuditError):
            raise
        raise ContentAuditError("archive-content-invalid") from error
    return findings, {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "entries": entries,
    }
