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
"""Unit tests for the Linux Cross-Boundary Correlation Module."""

from __future__ import annotations

from src.utils.linux_cross_boundary import (
    LinuxCrossBoundaryAnalyzer,
    analyze_cross_boundary,
    extract_temp_path,
    extract_user_home_path,
    is_system_config_path,
)
from src.utils.models import AnalysisTarget, Finding, RiskLevel


def test_is_system_config_path():
    """Test is_system_config_path identifies system vs user configuration paths."""
    assert is_system_config_path("/etc/systemd/system/nginx.service")
    assert is_system_config_path("/lib/systemd/system/app.service")
    assert is_system_config_path("/usr/lib/systemd/system/dbus.service")
    assert is_system_config_path("/var/spool/cron/crontabs/root")
    assert is_system_config_path("/etc/crontab")
    assert is_system_config_path("/etc/rc.local")

    # User paths should be rejected
    assert not is_system_config_path("/home/alice/.config/systemd/user/test.service")
    assert not is_system_config_path("/root/.bashrc")
    assert not is_system_config_path("")


def test_extract_user_home_path():
    """Test extracting user home paths and usernames from command text."""
    # Unquoted
    res = extract_user_home_path("/home/www-data/.local/bin/helper_daemon --background")
    assert res is not None
    assert res[0] == "/home/www-data/.local/bin/helper_daemon"
    assert res[1] == "www-data"

    # Quoted
    res_q = extract_user_home_path("'/home/john_doe/my binary' -v")
    assert res_q is not None
    assert res_q[0] == "/home/john_doe/my binary"
    assert res_q[1] == "john_doe"

    # None
    assert extract_user_home_path("/usr/bin/python3 script.py") is None


def test_extract_temp_path():
    """Test extracting temporary directory paths from command text."""
    res = extract_temp_path("ExecStart=/tmp/.hidden/miner --daemon")
    assert res == "/tmp/.hidden/miner"

    res_shm = extract_temp_path("/dev/shm/payload.sh 2>&1")
    assert res_shm == "/dev/shm/payload.sh"

    res_q = extract_temp_path("'/var/tmp/staged script.sh'")
    assert res_q == "/var/tmp/staged script.sh"

    assert extract_temp_path("/usr/local/bin/agent") is None


def test_enrich_systemd_cross_boundary_finding_001():
    """Verify Section 4.1 FINDING-001 enrichment."""
    raw = (
        "[Service]\n"
        "ExecStart=/home/www-data/.local/bin/helper_daemon --background\n"
        "User=root\n"
    )
    finding = Finding(
        category="systemd_service",
        path="/etc/systemd/system/nginx-helper.service",
        details={
            "service_name": "nginx-helper.service",
            "exec_start": "/home/www-data/.local/bin/helper_daemon --background",
        },
        raw_content=raw,
    )

    results = analyze_cross_boundary(
        target=AnalysisTarget(), existing_findings=[finding]
    )

    assert len(results) == 1
    enriched = results[0]
    assert enriched.category == "cross_boundary_systemd"
    assert enriched.risk_level == RiskLevel.CRITICAL
    assert enriched.technique_id == "T1543.002"
    assert (
        enriched.details["system_config_path"]
        == "/etc/systemd/system/nginx-helper.service"
    )
    assert (
        enriched.details["target_binary_path"]
        == "/home/www-data/.local/bin/helper_daemon"
    )
    assert enriched.details["target_binary_owner"] == "www-data"
    assert "SYSTEM_SERVICE_POINTS_TO_USER_HOME" in enriched.details["flags"]
    assert "NON_ROOT_USER_PATH" in enriched.details["flags"]


def test_enrich_cron_cross_boundary():
    """Test enriching cron jobs pointing to user home directories."""
    finding = Finding(
        category="cron_job",
        path="/etc/crontab",
        details={
            "command": "* * * * * root /home/alice/scripts/backup.sh",
        },
        raw_content="* * * * * root /home/alice/scripts/backup.sh\n",
    )

    results = analyze_cross_boundary(
        target=AnalysisTarget(), existing_findings=[finding]
    )

    assert len(results) == 1
    enriched = results[0]
    assert enriched.category == "cross_boundary_cron"
    assert enriched.risk_level == RiskLevel.CRITICAL
    assert enriched.technique_id == "T1053.003"
    assert enriched.details["system_config_path"] == "/etc/crontab"
    assert enriched.details["target_binary_path"] == "/home/alice/scripts/backup.sh"
    assert enriched.details["target_binary_owner"] == "alice"
    assert "CROSS_BOUNDARY_USER_HOME_EXECUTION" in enriched.details["flags"]
    assert "NON_ROOT_USER_PATH" in enriched.details["flags"]
    assert "SYSTEM_CRON_POINTS_TO_USER_HOME" in enriched.details["flags"]


def test_enrich_init_cross_boundary():
    """Test enriching init scripts pointing to user home directories."""
    finding = Finding(
        category="init_script",
        path="/etc/rc.local",
        details={"command": "/home/bob/startup.sh &"},
        raw_content="/home/bob/startup.sh &\nexit 0\n",
    )

    results = analyze_cross_boundary(
        target=AnalysisTarget(), existing_findings=[finding]
    )

    assert len(results) == 1
    enriched = results[0]
    assert enriched.category == "cross_boundary_init"
    assert enriched.risk_level == RiskLevel.CRITICAL
    assert enriched.details["target_binary_owner"] == "bob"
    assert "CROSS_BOUNDARY_USER_HOME_EXECUTION" in enriched.details["flags"]


def test_standalone_cross_boundary_detection_systemd(tmp_path):
    """Test detecting cross-boundary systemd units from target files."""
    service_file = tmp_path / "evil.service"
    service_file.write_text(
        "[Unit]\nDescription=Evil\n[Service]\nExecStart=/home/mallory/.config/backdoor --port 4444\n"
    )

    target = AnalysisTarget(
        virtual_paths={"/etc/systemd/system/evil.service": str(service_file)}
    )

    findings = analyze_cross_boundary(target=target, existing_findings=None)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "cross_boundary_systemd"
    assert finding.risk_level == RiskLevel.CRITICAL
    assert finding.path == "/etc/systemd/system/evil.service"
    assert finding.details["target_binary_owner"] == "mallory"
    assert finding.details["target_binary_path"] == "/home/mallory/.config/backdoor"
    assert "SYSTEM_SERVICE_POINTS_TO_USER_HOME" in finding.details["flags"]


def test_standalone_cross_boundary_detection_cron(tmp_path):
    """Test detecting cross-boundary cron jobs from target files."""
    cron_file = tmp_path / "my_cron"
    cron_file.write_text("0 2 * * * root /home/charlie/sync.py\n")

    target = AnalysisTarget(virtual_paths={"/etc/cron.d/my_cron": str(cron_file)})

    findings = analyze_cross_boundary(target=target)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "cross_boundary_cron"
    assert finding.risk_level == RiskLevel.CRITICAL
    assert finding.details["target_binary_owner"] == "charlie"
    assert finding.details["target_binary_path"] == "/home/charlie/sync.py"


def test_temp_path_cross_boundary_detection(tmp_path):
    """Test detecting system services executing out of temporary directories."""
    service_file = tmp_path / "tmp_runner.service"
    service_file.write_text("[Service]\nExecStart=/tmp/.miner/xmrig -o pool\n")

    target = AnalysisTarget(
        virtual_paths={"/etc/systemd/system/tmp_runner.service": str(service_file)}
    )

    findings = analyze_cross_boundary(target=target)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "cross_boundary_systemd"
    assert finding.risk_level == RiskLevel.CRITICAL
    assert finding.details["target_binary_path"] == "/tmp/.miner/xmrig"
    assert "SUSPICIOUS_PATH_TMP" in finding.details["flags"]
    assert "CROSS_BOUNDARY_TEMP_EXECUTION" in finding.details["flags"]


def test_user_service_not_promoted():
    """Test user-level systemd units are not promoted to cross-boundary CRITICAL."""
    finding = Finding(
        category="user_systemd_unit",
        path="/home/alice/.config/systemd/user/my_worker.service",
        details={
            "exec_start": "/home/alice/bin/worker",
        },
        raw_content="[Service]\nExecStart=/home/alice/bin/worker\n",
    )

    results = analyze_cross_boundary(
        target=AnalysisTarget(), existing_findings=[finding]
    )

    assert len(results) == 1
    assert results[0].category == "user_systemd_unit"
    assert results[0].risk_level != RiskLevel.CRITICAL


def test_non_cross_boundary_findings_preserved():
    """Test unrelated findings are preserved alongside cross-boundary enrichments."""
    f_cross = Finding(
        category="systemd_service",
        path="/etc/systemd/system/helper.service",
        details={"exec_start": "/home/www-data/daemon"},
    )
    f_shell = Finding(
        category="shell_rc_injection",
        path="/home/alice/.bashrc",
        risk_level=RiskLevel.HIGH,
        details={"flags": ["BASE64_PAYLOAD"]},
    )

    results = analyze_cross_boundary(
        target=AnalysisTarget(), existing_findings=[f_cross, f_shell]
    )

    assert len(results) == 2
    assert results[0].category == "cross_boundary_systemd"
    assert results[0].risk_level == RiskLevel.CRITICAL
    assert results[1].category == "shell_rc_injection"
    assert results[1].risk_level == RiskLevel.HIGH


def test_linux_cross_boundary_analyzer_class(tmp_path):
    """Test LinuxCrossBoundaryAnalyzer class methods analyze and correlate."""
    service_file = tmp_path / "test.service"
    service_file.write_text("[Service]\nExecStart=/home/testuser/bin/service\n")

    target = AnalysisTarget(
        virtual_paths={"/etc/systemd/system/test.service": str(service_file)}
    )

    analyzer = LinuxCrossBoundaryAnalyzer(target)
    findings = analyzer.analyze()

    assert len(findings) == 1
    assert findings[0].details["target_binary_owner"] == "testuser"

    # Test correlate method
    findings_correlate = analyzer.correlate()
    assert len(findings_correlate) == 1
