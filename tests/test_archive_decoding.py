"""Small decoder/framing regression cases from the archive recheck."""

import io
import struct
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import hosted_audit_content as content  # noqa: E402


def deflated_zip(*, directory=False):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("safe/" if directory else "safe.txt", b"" if directory else b"Public")
    return stream.getvalue()


def pax_tar(headers, body):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("safe.bin")
        member.size = len(body)
        member.pax_headers = headers
        archive.addfile(member, io.BytesIO(body))
    return stream.getvalue()


@pytest.mark.parametrize("directory_member", [False, True])
def test_recheck_deflate_unused_declared_range_is_refused(directory_member):
    marker = b"ghp_" + b"a" * 24
    original = deflated_zip(directory=directory_member)
    footer = original.rfind(b"PK\x05\x06")
    directory = struct.unpack_from("<I", original, footer + 16)[0]
    compressed = struct.unpack_from("<I", original, 18)[0]
    payload = bytearray(original[:directory] + marker + original[directory:])
    struct.pack_into("<I", payload, 18, compressed + len(marker))
    struct.pack_into("<I", payload, directory + len(marker) + 20, compressed + len(marker))
    struct.pack_into("<I", payload, footer + len(marker) + 16, directory + len(marker))
    with pytest.raises(content.ContentAuditError):
        content.scan_archive(bytes(payload), source="recheck-unused-deflate")


def test_recheck_pax_size_cannot_hide_accounted_body():
    payload = pax_tar({"size": "0"}, b"ghp_" + b"a" * 24)
    with pytest.raises(content.ContentAuditError):
        content.scan_archive(payload, source="recheck-pax-size", name="a.tar")


def test_recheck_sparse_output_is_refused_under_small_cap(monkeypatch):
    monkeypatch.setattr(content, "MAX_EXPANDED_BYTES", 20000)
    payload = pax_tar({"GNU.sparse.map": "0,1", "GNU.sparse.size": "65536"}, b"x")
    with pytest.raises(content.ContentAuditError):
        content.scan_archive(payload, source="recheck-sparse", name="a.tar")


@pytest.mark.parametrize(
    "headers", [{"size": "0"}, {"GNU.sparse.map": "0,1", "GNU.sparse.size": "65536"}]
)
def test_unsupported_pax_is_refused_before_tar_reader_is_opened(monkeypatch, headers):
    payload = pax_tar(headers, b"x")

    def forbidden(*args, **kwargs):
        pytest.fail("Unsupported metadata reached the TAR reader")

    monkeypatch.setattr(tarfile, "open", forbidden)
    with pytest.raises(content.ContentAuditError, match="archive-tar-metadata-unsupported"):
        content.scan_archive(payload, source="metadata-before-reader", name="a.tar")


def replace_compressed(original, compressed):
    footer = original.rfind(b"PK\x05\x06")
    directory = struct.unpack_from("<I", original, footer + 16)[0]
    name_size, extra_size = struct.unpack_from("<2H", original, 26)
    start = 30 + name_size + extra_size
    new_directory = start + len(compressed)
    delta = new_directory - directory
    payload = bytearray(original[:start] + compressed + original[directory:])
    struct.pack_into("<I", payload, 18, len(compressed))
    struct.pack_into("<I", payload, new_directory + 20, len(compressed))
    struct.pack_into("<I", payload, footer + delta + 16, new_directory)
    return bytes(payload)


@pytest.mark.parametrize("case", ["no-eof", "output-over-declared-size", "crc-mismatch"])
def test_zip_decoder_checks_eof_size_and_crc(case):
    original = deflated_zip()
    body = b"Public!" if case == "output-over-declared-size" else b"Secret"
    encoder = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    compressed = encoder.compress(body) + encoder.flush()
    if case == "no-eof":
        start = 30 + len(b"safe.txt")
        size = struct.unpack_from("<I", original, 18)[0]
        compressed = original[start : start + size - 1]
    with pytest.raises(content.ContentAuditError, match="archive-zip-member-invalid"):
        content.scan_archive(replace_compressed(original, compressed), source="decoder-control")


def test_zip_other_compression_is_refused():
    payload = bytearray(deflated_zip())
    footer = payload.rfind(b"PK\x05\x06")
    directory = struct.unpack_from("<I", payload, footer + 16)[0]
    struct.pack_into("<H", payload, 8, zipfile.ZIP_BZIP2)
    struct.pack_into("<H", payload, directory + 10, zipfile.ZIP_BZIP2)
    with pytest.raises(content.ContentAuditError):
        content.scan_archive(bytes(payload), source="unsupported-compression")


@pytest.mark.parametrize("change", ["size", "offset", "missing-member"])
def test_effective_tar_members_must_match_raw_framing(monkeypatch, change):
    payload = pax_tar({}, b"Public")
    member = tarfile.TarInfo("safe.bin")
    member.size, member.offset_data = 6, 512
    if change == "size":
        member.size = 0
    if change == "offset":
        member.offset_data = 1024

    class Reader:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def __iter__(self):
            return iter([] if change == "missing-member" else [member])

    monkeypatch.setattr(tarfile, "open", lambda **kwargs: Reader())
    with pytest.raises(content.ContentAuditError, match="archive-tar-member-mismatch"):
        content.scan_archive(payload, source="effective-framing", name="a.tar")
