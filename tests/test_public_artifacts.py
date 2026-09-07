"""Generated preview outputs are part of the public information boundary."""

import importlib.util
import sys
from pathlib import Path


def _policy():
    script = Path(__file__).resolve().parents[1] / "scripts/public_boundary_policy.py"
    spec = importlib.util.spec_from_file_location("harness_public_boundary", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_generated_docs_are_in_the_scanned_inventory(tmp_path):
    policy = _policy()
    path = tmp_path / "work/docs-site/index.html"
    path.parent.mkdir(parents=True)
    path.write_text("Synthetic preview")
    assert "work/docs-site/index.html" in policy.generated_output_paths(tmp_path)


def test_unpacked_package_is_in_the_scanned_inventory(tmp_path):
    policy = _policy()
    path = tmp_path / "work/package-content/sangrep_harness/example.py"
    path.parent.mkdir(parents=True)
    path.write_text("# Synthetic package member")
    assert path.relative_to(tmp_path).as_posix() in policy.generated_output_paths(tmp_path)


def test_unknown_binary_output_is_rejected():
    policy = _policy()
    findings = policy.scan_bytes(b"synthetic\x00payload", source="synthetic-preview")
    assert [finding.category for finding in findings] == ["unrecognized-binary"]


def test_sensitive_preview_findings_do_not_echo_input():
    policy = _policy()
    marker = "gh" + "p_" + "SYNTHETIC" * 5
    findings = policy.scan_bytes(marker.encode(), source="synthetic-preview")
    assert [finding.category for finding in findings] == ["github-token"]
    assert marker not in str(findings)
