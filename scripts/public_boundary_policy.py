from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import NamedTuple

MAX_SCANNED_BYTES = 8 * 1024 * 1024
GENERATED_OUTPUT_ROOTS = (
    "artifacts",
    "build",
    "coverage",
    "dist",
    "generated",
    "out",
    "reports",
)
ALLOWED_BINARY_SUFFIXES = {
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".mp4",
    ".png",
    ".webm",
    ".webp",
}
PROHIBITED_SUFFIXES = {
    ".crash",
    ".db",
    ".dmp",
    ".env",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".sangrep",
    ".sqlite",
    ".sqlite3",
}


class Finding(NamedTuple):
    category: str
    record_id: str

    def render(self) -> str:
        return f"category={self.category} record={self.record_id}"


def opaque_record_id(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]


def generated_output_paths(repository_root: Path = Path(".")) -> tuple[str, ...]:
    paths: set[str] = set()

    def fail(error: OSError) -> None:
        raise error

    for root_name in GENERATED_OUTPUT_ROOTS:
        root = repository_root / root_name
        if root.is_symlink() or root.is_file():
            paths.add(root.relative_to(repository_root).as_posix())
            continue
        if not root.exists():
            continue
        if not root.is_dir():
            paths.add(root.relative_to(repository_root).as_posix())
            continue
        for directory, directory_names, file_names in os.walk(
            root,
            topdown=True,
            onerror=fail,
            followlinks=False,
        ):
            directory_path = Path(directory)
            for name in tuple(directory_names):
                child = directory_path / name
                if child.is_symlink():
                    paths.add(child.relative_to(repository_root).as_posix())
                    directory_names.remove(name)
            for name in file_names:
                child = directory_path / name
                paths.add(child.relative_to(repository_root).as_posix())
    return tuple(sorted(paths))


RESTRICTED_RULES = (
    (
        "private-repository",
        re.compile(
            r"(?:https?://github\.com/)?sangrep/(?:sangrep|monolith-archive|workbench|packs|cloud|evals|handbook)(?:[/#\s]|\Z)",
            re.IGNORECASE,
        ),
    ),
    ("project-node-id", re.compile(r"\bPVT(?:I|F|SSF|V)?_[A-Za-z0-9_-]+\b")),
    (
        "private-task-id",
        re.compile(r"\b(?:client-new-thread|codex-task|worktree-id):[A-Za-z0-9_-]+\b", re.I),
    ),
    (
        "local-absolute-path",
        re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\Users\\)[^\s\x00]+"),
    ),
    (
        "private-tracker-field",
        re.compile(
            r"\b(?:Active task|Claim boundary|Product gate|Component release|"
            r"Sub-issues progress)\b",
            re.I,
        ),
    ),
    (
        "private-provider-metadata",
        re.compile(
            r"\b(?:provider workspace id|provider session id|sealed answer key|"
            r"private pricing authority)\b",
            re.I,
        ),
    ),
    (
        "custody-selector",
        re.compile(
            r"\b(?:custody selector|keychain selector|signing selector)\b|"
            r"\b(?:macos[-_]?keychain|keychain|windows[-_]?credential[-_]?manager|"
            r"sangrep[-_]?(?:custody|signing|pack[-_]?signing)[a-z0-9+.-]*):/{1,3}"
            r"[^\s\"'<>]+|"
            r"\b[a-z][a-z0-9+.-]*(?:keychain|credential[-_]?manager)[a-z0-9+.-]*:/{1,3}"
            r"[^\s\"'<>]+|"
            r"\b[a-z][a-z0-9+.-]*:/{1,3}[^\s\"'<>]*(?:keychain|"
            r"credential[-_]?manager)[^\s\"'<>]*",
            re.I,
        ),
    ),
)

SECRET_RULES = (
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("openai-token", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "private-key-material",
        re.compile(r"-----BEGIN (?:OPENSSH |EC |RSA )?PRIVATE KEY-----"),
    ),
)


def scan_text(text: str, *, source: str, include_restricted: bool = True) -> list[Finding]:
    record_id = opaque_record_id(source)
    findings: list[Finding] = []
    rules = SECRET_RULES + (RESTRICTED_RULES if include_restricted else ())
    for category, pattern in rules:
        if pattern.search(text):
            findings.append(Finding(category=category, record_id=record_id))
    return findings


def _valid_media(data: bytes, suffix: str) -> bool:
    if suffix == ".gif":
        return (
            len(data) >= 13
            and data[:6] in {b"GIF87a", b"GIF89a"}
            and int.from_bytes(data[6:8], "little") > 0
            and int.from_bytes(data[8:10], "little") > 0
        )
    if suffix == ".ico":
        return (
            len(data) >= 6
            and data[:4] == b"\x00\x00\x01\x00"
            and int.from_bytes(data[4:6], "little") > 0
        )
    if suffix in {".jpeg", ".jpg"}:
        return len(data) >= 4 and data.startswith(b"\xff\xd8\xff") and data.endswith(b"\xff\xd9")
    if suffix == ".mp4":
        if len(data) < 12 or data[4:8] != b"ftyp":
            return False
        first_box_bytes = int.from_bytes(data[:4], "big")
        return 8 <= first_box_bytes <= len(data)
    if suffix == ".png":
        return (
            len(data) >= 45
            and data.startswith(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
            and int.from_bytes(data[16:20], "big") > 0
            and int.from_bytes(data[20:24], "big") > 0
            and data[-12:-8] == b"\x00\x00\x00\x00"
            and data[-8:-4] == b"IEND"
        )
    if suffix == ".webm":
        return len(data) >= 4 and data.startswith(b"\x1aE\xdf\xa3")
    if suffix == ".webp":
        return (
            len(data) >= 12
            and data[:4] == b"RIFF"
            and data[8:12] == b"WEBP"
            and int.from_bytes(data[4:8], "little") + 8 == len(data)
        )
    return False


def scan_bytes(
    data: bytes,
    *,
    source: str,
    suffix: str = "",
    include_restricted: bool = True,
) -> list[Finding]:
    record_id = opaque_record_id(source)
    normalized_suffix = suffix.lower()
    if len(data) > MAX_SCANNED_BYTES:
        return [Finding(category="file-over-size-budget", record_id=record_id)]
    if normalized_suffix in PROHIBITED_SUFFIXES:
        return [Finding(category="prohibited-file-type", record_id=record_id)]
    if normalized_suffix in ALLOWED_BINARY_SUFFIXES:
        findings = scan_text(
            data.decode("utf-8", errors="ignore"),
            source=source,
            include_restricted=include_restricted,
        )
        if not _valid_media(data, normalized_suffix):
            findings.append(Finding(category="invalid-media", record_id=record_id))
        return findings
    if b"\x00" in data:
        return [Finding(category="unrecognized-binary", record_id=record_id)]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [Finding(category="non-utf8-text", record_id=record_id)]
    return scan_text(text, source=source, include_restricted=include_restricted)


def scan_path(path: Path, *, source: str, include_restricted: bool = True) -> list[Finding]:
    findings = scan_text(source, source=f"{source}:path", include_restricted=True)
    if path.is_symlink():
        findings.append(Finding(category="symlink", record_id=opaque_record_id(source)))
        return findings
    try:
        data = path.read_bytes()
    except OSError:
        findings.append(Finding(category="unreadable-file", record_id=opaque_record_id(source)))
        return findings
    findings.extend(
        scan_bytes(
            data,
            source=source,
            suffix=path.suffix,
            include_restricted=include_restricted,
        )
    )
    return findings


def canonical_inventory_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"
