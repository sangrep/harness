"""Dependency substitution must fail before any installation or build."""

import importlib.util
import io
import tarfile
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest


@pytest.fixture
def bootstrap():
    path = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap-contracts"
    if not path.exists():
        pytest.fail("contracts verifier is absent")
    loader = SourceFileLoader("bootstrap_contracts", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_rejects_substituted_wheel(bootstrap, tmp_path):
    wheel = tmp_path / "substituted.whl"
    wheel.write_bytes(b"synthetic substituted artifact")
    with pytest.raises(ValueError, match="artifact-identity"):
        bootstrap.verify_artifact(wheel, "0" * 64, 12)


@pytest.mark.parametrize("name", ["../escape.py", "/escape.py", "source/../../escape.py"])
def test_rejects_source_archive_traversal(bootstrap, tmp_path, name):
    archive = tmp_path / "source.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        member = tarfile.TarInfo(name)
        member.size = 1
        stream.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="archive-boundary"):
        bootstrap.extract_source(archive, tmp_path / "unpacked", "source")
    assert not (tmp_path / "escape.py").exists()


def test_rejects_source_symlink(bootstrap, tmp_path):
    archive = tmp_path / "source.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        member = tarfile.TarInfo("source/link")
        member.type = tarfile.SYMTYPE
        member.linkname = "../escape"
        stream.addfile(member)
    with pytest.raises(ValueError, match="archive-boundary"):
        bootstrap.extract_source(archive, tmp_path / "unpacked", "source")
