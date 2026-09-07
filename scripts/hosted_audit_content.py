"""Bounded inspection of hosted archives; archive members are never extracted to disk.

Runner-path projection is adapted from Sangrep Contracts under Apache-2.0.
See provenance/hosted-audit-reuse-v1.json and LICENSES/Apache-2.0.txt.
"""

from __future__ import annotations

import hashlib
import io
import re
import stat
import struct
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath

from public_boundary_policy import Finding, scan_bytes, scan_text

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


def _zip_envelope(payload: bytes, archive: zipfile.ZipFile) -> None:
    """Require accounted local records, central records and a terminal ZIP footer."""
    entries = archive.infolist()
    footer = len(payload) - 22 - len(archive.comment)
    if footer < 0:
        raise ContentAuditError("archive-zip-envelope-invalid")
    signature, disk, directory_disk, disk_count, count, directory_size, directory, comment_size = (
        struct.unpack_from("<4s4H2IH", payload, footer)
    )
    if (
        signature != b"PK\x05\x06"
        or disk != 0
        or directory_disk != 0
        or disk_count != count
        or count != len(entries)
        or directory + directory_size != footer
        or comment_size != len(archive.comment)
    ):
        raise ContentAuditError("archive-zip-envelope-invalid")
    cursor = directory
    for member in entries:
        if member.orig_filename != member.filename or "\0" in member.orig_filename:
            raise ContentAuditError("archive-path-invalid")
        if payload[cursor : cursor + 4] != b"PK\x01\x02" or cursor + 46 > footer:
            raise ContentAuditError("archive-zip-envelope-invalid")
        name_size, extra_size, comment_size = struct.unpack_from("<3H", payload, cursor + 28)
        end = cursor + 46 + name_size + extra_size + comment_size
        original_name = member.orig_filename.encode(
            "utf-8" if member.flag_bits & 0x800 else "cp437"
        )
        if end > footer or payload[cursor + 46 : cursor + 46 + name_size] != original_name:
            raise ContentAuditError("archive-zip-envelope-invalid")
        cursor = end
    if cursor != footer:
        raise ContentAuditError("archive-zip-envelope-invalid")

    cursor = 0
    for member in sorted(entries, key=lambda item: item.header_offset):
        if member.header_offset != cursor or cursor + 30 > directory:
            raise ContentAuditError("archive-zip-envelope-invalid")
        fields = struct.unpack_from("<4s5H3I2H", payload, cursor)
        signature, _, flags, method, _, _, crc, compressed, expanded, name_size, extra_size = fields
        name_end = cursor + 30 + name_size
        original_name = member.orig_filename.encode("utf-8" if flags & 0x800 else "cp437")
        if (
            signature != b"PK\x03\x04"
            or flags != member.flag_bits
            or method != member.compress_type
            or extra_size != 0
            or name_end > directory
            or payload[cursor + 30 : name_end] != original_name
        ):
            raise ContentAuditError("archive-zip-envelope-invalid")
        expected = (member.CRC, member.compress_size, member.file_size)
        if (crc, compressed, expanded) != expected and not (
            flags & 8
            and all(
                actual in {0, wanted}
                for actual, wanted in zip((crc, compressed, expanded), expected, strict=True)
            )
        ):
            raise ContentAuditError("archive-zip-envelope-invalid")
        cursor = name_end + member.compress_size
        if cursor > directory:
            raise ContentAuditError("archive-zip-envelope-invalid")
        if flags & 8:
            if cursor + 12 <= directory and struct.unpack_from("<3I", payload, cursor) == expected:
                cursor += 12
            elif (
                cursor + 16 <= directory
                and payload[cursor : cursor + 4] == b"PK\x07\x08"
                and struct.unpack_from("<3I", payload, cursor + 4) == expected
            ):
                cursor += 16
            else:
                raise ContentAuditError("archive-zip-envelope-invalid")
    if cursor != directory:
        raise ContentAuditError("archive-zip-envelope-invalid")


def _zip_member(payload: bytes, member: zipfile.ZipInfo) -> bytes:
    """Decode exactly the accounted range, without ZipExtFile's truncation behavior."""
    name_size, extra_size = struct.unpack_from("<2H", payload, member.header_offset + 26)
    start = member.header_offset + 30 + name_size + extra_size
    compressed = memoryview(payload)[start : start + member.compress_size]
    if len(compressed) != member.compress_size:
        raise ContentAuditError("archive-zip-member-invalid")
    if member.compress_type == zipfile.ZIP_STORED:
        if member.compress_size != member.file_size:
            raise ContentAuditError("archive-zip-member-invalid")
        data = bytes(compressed)
    elif member.compress_type == zipfile.ZIP_DEFLATED:
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        data = decoder.decompress(compressed, member.file_size + 1)
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ContentAuditError("archive-zip-member-invalid")
    else:
        raise ContentAuditError("archive-compression-unsupported")
    if len(data) != member.file_size or zlib.crc32(data) != member.CRC:
        raise ContentAuditError("archive-zip-member-invalid")
    return data


def _pax_metadata(metadata: bytes) -> None:
    """Allow ordinary metadata/path records, not payload reinterpretation."""
    allowed = {
        b"path",
        b"linkpath",
        b"uname",
        b"gname",
        b"uid",
        b"gid",
        b"mtime",
        b"atime",
        b"ctime",
        b"comment",
    }
    position = 0
    seen: set[bytes] = set()
    while position < len(metadata):
        space = metadata.find(b" ", position)
        length_text = metadata[position:space]
        if space < 0 or not length_text.isdigit():
            raise ContentAuditError("archive-tar-metadata-unsupported")
        end = position + int(length_text)
        if end > len(metadata) or end <= space + 2 or metadata[end - 1 : end] != b"\n":
            raise ContentAuditError("archive-tar-metadata-unsupported")
        record = metadata[space + 1 : end - 1]
        key, separator, _ = record.partition(b"=")
        if not separator or key not in allowed or key in seen:
            raise ContentAuditError("archive-tar-metadata-unsupported")
        seen.add(key)
        position = end


def _tar_envelope(
    payload: bytes, *, source: str, name: str, budget: ArchiveBudget
) -> tuple[bytes, list[Finding], dict[int, tuple[int, bytes]]]:
    findings: list[Finding] = []
    available = MAX_EXPANDED_BYTES - budget.expanded
    if name.lower().endswith((".tar.gz", ".tgz")):
        if len(payload) < 10 or payload[:3] != b"\x1f\x8b\x08" or payload[3] & 0xE4:
            raise ContentAuditError("archive-gzip-envelope-invalid")
        position = 10
        for flag in (8, 16):
            if payload[3] & flag:
                end = payload.find(b"\0", position)
                if end < 0:
                    raise ContentAuditError("archive-gzip-envelope-invalid")
                findings.extend(
                    scan_bytes(payload[position:end], source=f"{source}:gzip-metadata:{flag}")
                )
                position = end + 1
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        data = decoder.decompress(payload, max(1, available + 1))
        if len(data) > available:
            raise ContentAuditError("archive-budget-exceeded")
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ContentAuditError("archive-gzip-envelope-invalid")
    else:
        data = payload
    if len(data) > available:
        raise ContentAuditError("archive-budget-exceeded")
    # Reserve all decoded TAR bytes, including framing and padding. Member data
    # below is prepaid; nested archives must still admit their own decoded bytes.
    budget.expanded += len(data)
    position = 0
    members = budget.members
    framing: dict[int, tuple[int, bytes]] = {}
    metadata_types = {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME}
    while position + 512 <= len(data):
        header = data[position : position + 512]
        if not any(header):
            if len(data) - position < 1024 or len(data) % 512 or any(data[position:]):
                raise ContentAuditError("archive-tar-envelope-invalid")
            return data, findings, framing
        member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
        members += 1
        if members > MAX_MEMBERS or member.size < 0:
            raise ContentAuditError("archive-budget-exceeded")
        findings.extend(scan_text(header.decode("utf-8"), source=f"{source}:tar-header:{position}"))
        for field in ("name", "linkname", "uname", "gname"):
            findings.extend(
                scan_bytes(
                    getattr(member, field).encode("utf-8"),
                    source=f"{source}:tar-header:{position}:{field}",
                )
            )
        start = position + 512
        end = start + member.size
        following = start + ((member.size + 511) // 512) * 512
        if following > len(data) or any(data[end:following]):
            raise ContentAuditError("archive-tar-envelope-invalid")
        if member.type in metadata_types:
            budget.admit(0)
            metadata = data[start:end]
            if member.type == tarfile.GNUTYPE_LONGNAME:
                metadata = metadata.rstrip(b"\0")
            else:
                _pax_metadata(metadata)
            findings.extend(scan_bytes(metadata, source=f"{source}:tar-metadata:{position}"))
        elif member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
            raise ContentAuditError("archive-member-unsupported")
        else:
            framing[start] = (member.size, member.type)
        position = following
    raise ContentAuditError("archive-tar-envelope-invalid")


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

    def inspect(
        member_name: str, size: int, read, *, directory: bool = False, prepaid: bool = False
    ) -> None:
        if directory and size:
            raise ContentAuditError("archive-directory-payload")
        if directory and member_name in {".", "./"}:
            if "." in seen:
                raise ContentAuditError("archive-path-invalid")
            seen.add(".")
            budget.admit(0)
            if not prepaid:
                read()
            return
        path = _member_path(member_name, seen)
        budget.admit(0 if prepaid else size)
        entry_source = f"{source}:{member_name}"
        findings.extend(scan_bytes(member_name.encode(), source=f"{entry_source}:path"))
        if directory:
            if not prepaid:
                read()
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
                _zip_envelope(payload, archive)
                findings.extend(scan_bytes(archive.comment, source=source + ":archive-comment"))
                for member in archive.infolist():
                    findings.extend(scan_bytes(member.comment, source=source + ":member-comment"))
                    kind = stat.S_IFMT(member.external_attr >> 16)
                    if (
                        kind not in {0, stat.S_IFREG, stat.S_IFDIR}
                        or member.flag_bits & 1
                        or member.extra
                        or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    ):
                        raise ContentAuditError("archive-member-unsupported")
                    inspect(
                        member.filename,
                        member.file_size,
                        lambda selected=member: _zip_member(payload, selected),
                        directory=member.is_dir(),
                    )
        elif name.lower().endswith((".tar", ".tar.gz", ".tgz")):
            data, envelope_findings, framing = _tar_envelope(
                payload, source=source, name=name, budget=budget
            )
            findings.extend(envelope_findings)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                for member in archive:
                    if member.sparse is not None:
                        raise ContentAuditError("archive-tar-metadata-unsupported")
                    if (
                        member.size < 0
                        or member.size > MAX_EXPANDED_BYTES
                        or member.offset_data < 0
                        or member.offset_data + member.size > len(data)
                    ):
                        raise ContentAuditError("archive-budget-exceeded")
                    if framing.pop(member.offset_data, None) != (member.size, member.type):
                        raise ContentAuditError("archive-tar-member-mismatch")
                    for key, value in member.pax_headers.items():
                        findings.extend(
                            scan_bytes(f"{key}={value}".encode(), source=source + ":pax")
                        )
                    if not member.isfile() and not member.isdir():
                        raise ContentAuditError("archive-member-unsupported")

                    def read(selected=member):
                        return data[selected.offset_data : selected.offset_data + selected.size]

                    inspect(member.name, member.size, read, directory=member.isdir(), prepaid=True)
            if framing:
                raise ContentAuditError("archive-tar-member-mismatch")
        else:
            raise ContentAuditError("archive-format-unsupported")
    except (
        zipfile.BadZipFile,
        tarfile.TarError,
        OSError,
        EOFError,
        RuntimeError,
        ValueError,
        struct.error,
        zlib.error,
    ) as error:
        if isinstance(error, ContentAuditError):
            raise
        raise ContentAuditError("archive-content-invalid") from error
    return findings, {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "entries": entries,
    }
