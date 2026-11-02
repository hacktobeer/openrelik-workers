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
"""End-to-end integration tests for Linux Persistence Analyzer Orchestrator."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from src.utils.linux_analyzer import (
    LinuxAnalyzer,
    LinuxPersistenceAnalyzer,
    analyze_linux_target,
    run_linux_persistence_analysis,
)
from src.utils.models import AnalysisTarget, RiskLevel


@pytest.fixture
def mock_linux_fs(tmp_path: Path) -> Path:
    """Create a multi-artifact mock Linux root filesystem.

    Args:
        tmp_path: Temporary directory path provided by pytest.

    Returns:
        Path to the initialized mock Linux root directory.
    """
    # 1. System metadata
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True, exist_ok=True)
    (etc_dir / "hostname").write_text("cloud-prod-web-01\n", encoding="utf-8")
    (etc_dir / "os-release").write_text(
        'NAME="Ubuntu"\nVERSION="24.04 LTS (Noble Numbat)"\nID=ubuntu\n',
        encoding="utf-8",
    )

    # 2. Systemd cross-boundary service (FINDING-001)
    systemd_dir = etc_dir / "systemd" / "system"
    systemd_dir.mkdir(parents=True, exist_ok=True)
    svc_content = """[Unit]
Description=Nginx Service Helper
After=network.target

[Service]
ExecStart=/home/www-data/.local/bin/helper_daemon --background
User=root
Restart=always

[Install]
WantedBy=multi-user.target
"""
    (systemd_dir / "nginx-helper.service").write_text(svc_content, encoding="utf-8")

    # 3. User shell profile base64 injection (FINDING-002)
    deploy_home = tmp_path / "home" / "deploy"
    deploy_home.mkdir(parents=True, exist_ok=True)
    bashrc_content = (
        "# Append to end of .bashrc\necho 'ZXhhbXBsZSBjb21tYW5k' | base64 -d | sh\n"
    )
    (deploy_home / ".bashrc").write_text(bashrc_content, encoding="utf-8")

    # 4. Root SSH authorized key
    root_ssh_dir = tmp_path / "root" / ".ssh"
    root_ssh_dir.mkdir(parents=True, exist_ok=True)
    ssh_key_content = (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG5z5l5m+X3u3j3k1l2m3n4o5p6q7r8s9t0u1v2w3x4y"
        " backdoor-root@attacker\n"
    )
    (root_ssh_dir / "authorized_keys").write_text(ssh_key_content, encoding="utf-8")

    # 5. Cron job
    cron_d_dir = etc_dir / "cron.d"
    cron_d_dir.mkdir(parents=True, exist_ok=True)
    cron_content = "0 2 * * * root /usr/local/bin/backup.sh\n"
    (cron_d_dir / "daily-backup").write_text(cron_content, encoding="utf-8")

    # 6. Dynamic linker preload
    (etc_dir / "ld.so.preload").write_text("/lib/librootkit.so\n", encoding="utf-8")

    # 7. Sudoers drop-in
    sudoers_dir = etc_dir / "sudoers.d"
    sudoers_dir.mkdir(parents=True, exist_ok=True)
    (sudoers_dir / "deploy-admin").write_text(
        "deploy ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8"
    )

    # 8. XDG autostart desktop entry pointing to user home
    autostart_dir = etc_dir / "xdg" / "autostart"
    autostart_dir.mkdir(parents=True, exist_ok=True)
    desktop_content = """[Desktop Entry]
Type=Application
Name=BadApp
Exec=/home/deploy/bin/autostart.sh
"""
    (autostart_dir / "badapp.desktop").write_text(desktop_content, encoding="utf-8")

    # 9. SysV rc.local active payload
    rc_local_content = "#!/bin/sh -e\n/opt/startup_metric.sh\nexit 0\n"
    (etc_dir / "rc.local").write_text(rc_local_content, encoding="utf-8")

    return tmp_path


def test_end_to_end_analysis_root_filesystem(mock_linux_fs):
    """Test full analysis against mock Linux filesystem root."""
    target = AnalysisTarget(root_path=str(mock_linux_fs))

    meta, findings = run_linux_persistence_analysis([target])

    # Verify ReportMeta
    assert meta.os == "linux"
    assert meta.hostname == "cloud-prod-web-01"
    assert meta.total_findings == len(findings)
    assert meta.analysis_timestamp.endswith("Z")
    assert "T" in meta.analysis_timestamp

    # Verify findings are scored and ranked
    assert len(findings) >= 6
    assert all(f.id.startswith("FINDING-") for f in findings)
    assert [f.id for f in findings] == [
        f"FINDING-{i:03d}" for i in range(1, len(findings) + 1)
    ]

    # 1. Verify FINDING-001: Systemd cross-boundary service
    systemd_findings = [
        f for f in findings if f.path == "/etc/systemd/system/nginx-helper.service"
    ]
    assert len(systemd_findings) == 1
    f_sysd = systemd_findings[0]
    assert f_sysd.category == "cross_boundary_systemd"
    assert f_sysd.risk_level == RiskLevel.CRITICAL
    assert f_sysd.technique_id == "T1543.002"
    assert f_sysd.details.get("service_name") == "nginx-helper.service"
    assert (
        f_sysd.details.get("target_binary_path")
        == "/home/www-data/.local/bin/helper_daemon"
    )
    assert f_sysd.details.get("target_binary_owner") == "www-data"
    assert "SYSTEM_SERVICE_POINTS_TO_USER_HOME" in f_sysd.details.get("flags", [])
    assert "NON_ROOT_USER_PATH" in f_sysd.details.get("flags", [])

    # 2. Verify FINDING-002: Shell profile base64 injection
    bashrc_findings = [f for f in findings if f.path == "/home/deploy/.bashrc"]
    assert len(bashrc_findings) == 1
    f_bash = bashrc_findings[0]
    assert f_bash.category == "shell_rc_injection"
    assert f_bash.risk_level == RiskLevel.HIGH
    assert f_bash.technique_id == "T1546.004"
    assert f_bash.details.get("user") == "deploy"
    flags = f_bash.details.get("flags", [])
    assert "BASE64_PAYLOAD" in flags
    assert "OBFUSCATED_COMMAND" in flags
    assert f_bash.decoded_payload == "example command"

    # 3. Verify Dynamic Linker Preload
    preload_findings = [f for f in findings if f.path == "/etc/ld.so.preload"]
    assert len(preload_findings) == 1
    f_preload = preload_findings[0]
    assert f_preload.risk_level == RiskLevel.CRITICAL
    assert f_preload.technique_id == "T1574.006"

    # 4. Verify Sudoers NOPASSWD
    sudoers_findings = [f for f in findings if "deploy-admin" in f.path]
    assert len(sudoers_findings) == 1
    f_sudo = sudoers_findings[0]
    assert f_sudo.risk_level == RiskLevel.HIGH
    assert f_sudo.technique_id == "T1548.003"
    assert "SUDOERS_NOPASSWD" in f_sudo.details.get("flags", [])

    # 5. Verify Autostart cross-boundary entry
    autostart_findings = [f for f in findings if "badapp.desktop" in f.path]
    assert len(autostart_findings) == 1
    f_auto = autostart_findings[0]
    assert f_auto.risk_level == RiskLevel.CRITICAL
    assert f_auto.technique_id == "T1547.013"

    # 6. Verify Root SSH Key
    ssh_findings = [f for f in findings if f.path == "/root/.ssh/authorized_keys"]
    assert len(ssh_findings) == 1
    f_ssh = ssh_findings[0]
    assert f_ssh.risk_level == RiskLevel.MEDIUM
    assert f_ssh.technique_id == "T1098.004"


def test_end_to_end_virtual_paths_target(tmp_path):
    """Test analysis using virtual paths mapping without a single root directory."""
    svc_file = tmp_path / "svc.service"
    svc_file.write_text(
        "[Service]\nExecStart=/home/user/agent\nUser=root\n", encoding="utf-8"
    )

    bashrc_file = tmp_path / "bashrc"
    bashrc_file.write_text("export PROMPT_COMMAND='history -a'\n", encoding="utf-8")

    hostname_file = tmp_path / "hostname"
    hostname_file.write_text("virtual-node-99\n", encoding="utf-8")

    target = AnalysisTarget(
        virtual_paths={
            "/etc/hostname": str(hostname_file),
            "/etc/systemd/system/svc.service": str(svc_file),
            "/home/user/.bashrc": str(bashrc_file),
        }
    )

    meta, findings = run_linux_persistence_analysis([target])

    assert meta.hostname == "virtual-node-99"
    assert meta.os == "linux"
    assert len(findings) >= 2


def test_min_risk_level_filtering(mock_linux_fs):
    """Test filtering findings by minimum risk level threshold."""
    target = AnalysisTarget(root_path=str(mock_linux_fs))

    # All findings
    meta_all, findings_all = run_linux_persistence_analysis([target])
    total_count = len(findings_all)
    assert total_count >= 6
    assert meta_all.total_findings == total_count

    # Filter by CRITICAL
    meta_crit, findings_crit = run_linux_persistence_analysis(
        [target], min_risk_level=RiskLevel.CRITICAL
    )
    assert len(findings_crit) < total_count
    assert all(f.risk_level == RiskLevel.CRITICAL for f in findings_crit)
    assert meta_crit.total_findings == len(findings_crit)
    # Check renumbering
    assert [f.id for f in findings_crit] == [
        f"FINDING-{i:03d}" for i in range(1, len(findings_crit) + 1)
    ]

    # Filter by string 'HIGH'
    meta_high, findings_high = run_linux_persistence_analysis(
        [target], min_risk_level="HIGH"
    )
    assert len(findings_high) >= len(findings_crit)
    assert all(
        f.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH) for f in findings_high
    )
    assert meta_high.total_findings == len(findings_high)

    # Filter by string 'medium' (case insensitive)
    meta_med, findings_med = run_linux_persistence_analysis(
        [target], min_risk_level="medium"
    )
    assert len(findings_med) >= len(findings_high)
    assert all(
        f.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM)
        for f in findings_med
    )
    assert meta_med.total_findings == len(findings_med)

    # Filter by invalid string should ignore and return all
    meta_inv, findings_inv = run_linux_persistence_analysis(
        [target], min_risk_level="NOT_A_VALID_LEVEL"
    )
    assert len(findings_inv) == total_count
    assert meta_inv.total_findings == total_count


def test_parser_error_handling_resilience(mock_linux_fs, caplog):
    """Test that a failure in one parser does not abort subsequent parsers."""
    target = AnalysisTarget(root_path=str(mock_linux_fs))

    # Mock analyze_cron to raise an unexpected exception
    with mock.patch(
        "src.utils.linux_analyzer.analyze_cron",
        side_effect=RuntimeError("Simulated cron parser failure"),
    ):
        findings = analyze_linux_target(target)

    # Other parsers (systemd, shell profiles, ssh, ld_preload) should still succeed
    assert len(findings) > 0
    assert any(f.category == "cross_boundary_systemd" for f in findings)
    assert any(f.category == "shell_rc_injection" for f in findings)
    assert "Error executing parser 'cron'" in caplog.text


def test_cross_boundary_error_handling_resilience(mock_linux_fs, caplog):
    """Test that a failure in cross-boundary correlation does not crash analysis."""
    target = AnalysisTarget(root_path=str(mock_linux_fs))

    with mock.patch(
        "src.utils.linux_analyzer.analyze_cross_boundary",
        side_effect=RuntimeError("Simulated cross-boundary failure"),
    ):
        findings = analyze_linux_target(target)

    # Pre-existing findings from parsers should still be returned
    assert len(findings) > 0
    assert "Error executing cross-boundary analysis" in caplog.text


def test_multi_target_hostname_and_os_detection(tmp_path):
    """Test that the first non-unknown hostname is selected across multiple targets."""
    t1_dir = tmp_path / "t1"
    t1_dir.mkdir()
    (t1_dir / "hostname").write_text("unknown\n", encoding="utf-8")

    t2_dir = tmp_path / "t2"
    t2_dir.mkdir()
    (t2_dir / "hostname").write_text("first-valid-host\n", encoding="utf-8")

    t3_dir = tmp_path / "t3"
    t3_dir.mkdir()
    (t3_dir / "hostname").write_text("second-valid-host\n", encoding="utf-8")

    target1 = AnalysisTarget(virtual_paths={"/etc/hostname": str(t1_dir / "hostname")})
    target2 = AnalysisTarget(virtual_paths={"/etc/hostname": str(t2_dir / "hostname")})
    target3 = AnalysisTarget(virtual_paths={"/etc/hostname": str(t3_dir / "hostname")})

    meta, findings = run_linux_persistence_analysis([target1, target2, target3])

    assert meta.hostname == "first-valid-host"
    assert meta.os == "linux"
    assert len(findings) == 0


def test_empty_targets_handling():
    """Test handling of empty targets list."""
    meta, findings = run_linux_persistence_analysis([])

    assert meta.os == "linux"
    assert meta.hostname == "unknown"
    assert meta.total_findings == 0
    assert findings == []


def test_linux_persistence_analyzer_class(mock_linux_fs):
    """Test LinuxPersistenceAnalyzer and LinuxAnalyzer class interfaces."""
    target = AnalysisTarget(root_path=str(mock_linux_fs))

    # Test analyze_target
    analyzer = LinuxPersistenceAnalyzer()
    findings1 = analyzer.analyze_target(target)
    assert len(findings1) > 0

    # Test analyze_targets
    meta, findings2 = analyzer.analyze_targets([target], min_risk_level=RiskLevel.HIGH)
    assert meta.hostname == "cloud-prod-web-01"
    assert len(findings2) > 0

    # Test default target analyze()
    analyzer_with_target = LinuxPersistenceAnalyzer(target=target)
    findings3 = analyzer_with_target.analyze()
    assert len(findings3) == len(findings1)

    # Test passing target to analyze()
    findings4 = analyzer.analyze(target=target)
    assert len(findings4) == len(findings1)

    # Test analyze() without target raises ValueError
    with pytest.raises(ValueError, match="No target provided"):
        LinuxPersistenceAnalyzer().analyze()

    # Test LinuxAnalyzer alias
    assert LinuxAnalyzer is LinuxPersistenceAnalyzer
    alias_analyzer = LinuxAnalyzer(target=target)
    assert len(alias_analyzer.analyze()) == len(findings1)
