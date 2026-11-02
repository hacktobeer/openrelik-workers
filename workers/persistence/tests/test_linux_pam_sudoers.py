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
"""Unit tests for Linux sudoers and PAM persistence analyzer."""

from __future__ import annotations

from src.utils.linux_pam_sudoers import (
    LinuxPamSudoersParser,
    analyze_pam_sudoers,
)
from src.utils.models import AnalysisTarget, RiskLevel


def test_sudoers_nopasswd_all(tmp_path):
    """Test detection of NOPASSWD: ALL in /etc/sudoers."""
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)
    sudoers = etc_dir / "sudoers"
    sudoers.write_text(
        "# Sudoers file\nDefaults env_reset\nadmin ALL=(ALL) NOPASSWD: ALL\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "sudoers_privilege_persistence"
    assert f.technique_id == "T1548.003"
    assert f.risk_level == RiskLevel.HIGH
    assert f.path == "/etc/sudoers"
    assert "SUDOERS_NOPASSWD" in f.details["flags"]
    assert f.details["user"] == "admin"
    assert "NOPASSWD: ALL" in f.raw_content


def test_sudoers_user_home_execution(tmp_path):
    """Test detection of NOPASSWD rules executing scripts inside /home/*."""
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)
    sudoers = etc_dir / "sudoers"
    sudoers.write_text(
        "bob ALL=(root) NOPASSWD: /home/user/script.sh\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "sudoers_privilege_persistence"
    assert f.technique_id == "T1548.003"
    assert f.risk_level == RiskLevel.CRITICAL
    assert "SUDOERS_NOPASSWD" in f.details["flags"]
    assert "SYSTEM_SUDOERS_POINTS_TO_USER_HOME" in f.details["flags"]
    assert "NON_ROOT_USER_PATH" in f.details["flags"]
    assert f.details["target_binary_path"] == "/home/user/script.sh"


def test_sudoers_no_authenticate(tmp_path):
    """Test detection of !authenticate tag in sudoers rule and Defaults."""
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)
    sudoers = etc_dir / "sudoers"
    sudoers.write_text(
        "Defaults !authenticate\nalice ALL=(ALL) !authenticate, /bin/cat\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 2
    for f in findings:
        assert f.category == "sudoers_privilege_persistence"
        assert f.technique_id == "T1548.003"
        assert f.risk_level == RiskLevel.HIGH
        assert "SUDOERS_NO_AUTHENTICATE" in f.details["flags"]


def test_sudoers_env_keep_ld_preload(tmp_path):
    """Test detection of LD_PRELOAD preservation in Defaults env_keep."""
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)
    sudoers = etc_dir / "sudoers"
    sudoers.write_text(
        'Defaults env_keep += "LD_PRELOAD"\n',
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "sudoers_privilege_persistence"
    assert f.technique_id == "T1548.003"
    assert f.risk_level == RiskLevel.CRITICAL
    assert "SUDOERS_ENV_KEEP_LD_PRELOAD" in f.details["flags"]
    assert f.details["entry_type"] == "Defaults"


def test_sudoers_exec_from_tmp_and_dev_shm(tmp_path):
    """Test detection of sudo rules granting execution in /tmp or /dev/shm."""
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)
    sudoers = etc_dir / "sudoers"
    sudoers.write_text(
        "charlie ALL=(ALL) NOPASSWD: /tmp/test.sh\n"
        "attacker ALL=(ALL) /dev/shm/agent\n"
        "david ALL=(ALL) /var/tmp/run\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 3
    for f in findings:
        assert f.risk_level == RiskLevel.CRITICAL
        assert "EXEC_FROM_TMP_OR_DEV_SHM" in f.details["flags"]


def test_sudoers_d_directory(tmp_path):
    """Test parsing rules inside /etc/sudoers.d/* directory."""
    sudoers_d = tmp_path / "etc" / "sudoers.d"
    sudoers_d.mkdir(parents=True)
    dropin1 = sudoers_d / "01-custom"
    dropin1.write_text("user1 ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")
    dropin2 = sudoers_d / "02-deploy"
    dropin2.write_text(
        "deploy ALL=(root) NOPASSWD: /home/deploy/bin/start.sh\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 2
    paths = {f.path for f in findings}
    assert "/etc/sudoers.d/01-custom" in paths
    assert "/etc/sudoers.d/02-deploy" in paths


def test_sudoers_benign_configuration(tmp_path):
    """Test that standard benign sudoers rules do not generate false positives."""
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)
    sudoers = etc_dir / "sudoers"
    sudoers.write_text(
        "# /etc/sudoers\n"
        "Defaults env_reset\n"
        "Defaults mail_badpass\n"
        'Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n'
        "root ALL=(ALL:ALL) ALL\n"
        "%admin ALL=(ALL) ALL\n"
        "%sudo ALL=(ALL:ALL) ALL\n"
        "#includedir /etc/sudoers.d\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)
    assert len(findings) == 0


def test_sudoers_multiline_continuation(tmp_path):
    """Test handling of multiline sudoers entries with backslash continuation."""
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)
    sudoers = etc_dir / "sudoers"
    sudoers.write_text(
        "bob ALL=(root) \\\n"
        "    NOPASSWD: /home/user/script.sh\n"
        "Defaults \\\n"
        '    env_keep += "LD_PRELOAD"\n',
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 2
    flags_list = [f.details["flags"] for f in findings]
    assert any("SYSTEM_SUDOERS_POINTS_TO_USER_HOME" in fl for fl in flags_list)
    assert any("SUDOERS_ENV_KEEP_LD_PRELOAD" in fl for fl in flags_list)


def test_pam_exec_hook(tmp_path):
    """Test detection of pam_exec.so hook in /etc/pam.d/sshd."""
    pam_dir = tmp_path / "etc" / "pam.d"
    pam_dir.mkdir(parents=True)
    sshd = pam_dir / "sshd"
    sshd.write_text(
        "# PAM configuration for sshd\n"
        "auth optional pam_exec.so quiet /usr/local/bin/notify.sh\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "pam_module_persistence"
    assert f.technique_id == "T1556.003"
    assert f.risk_level == RiskLevel.HIGH
    assert f.path == "/etc/pam.d/sshd"
    assert "PAM_EXEC_HOOK" in f.details["flags"]
    assert f.details["service"] == "sshd"
    assert f.details["module_path"] == "pam_exec.so"


def test_pam_permit_auth_bypass(tmp_path):
    """Test detection of auth sufficient pam_permit.so authentication bypass."""
    pam_dir = tmp_path / "etc" / "pam.d"
    pam_dir.mkdir(parents=True)
    sshd = pam_dir / "sshd"
    sshd.write_text(
        "auth sufficient pam_permit.so\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "pam_module_persistence"
    assert f.technique_id == "T1556.003"
    assert f.risk_level == RiskLevel.CRITICAL
    assert "PAM_PERMIT_AUTH_BYPASS" in f.details["flags"]
    assert f.details["module_type"] == "auth"


def test_pam_permit_account_bypass(tmp_path):
    """Test detection of account pam_permit.so bypass in /etc/pam.d/su."""
    pam_dir = tmp_path / "etc" / "pam.d"
    pam_dir.mkdir(parents=True)
    su = pam_dir / "su"
    su.write_text(
        "account required pam_permit.so\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 1
    f = findings[0]
    assert "PAM_PERMIT_AUTH_BYPASS" in f.details["flags"]
    assert f.details["module_type"] == "account"


def test_pam_permit_session_not_bypass(tmp_path):
    """Test that session pam_permit.so is standard and not flagged as auth bypass."""
    pam_dir = tmp_path / "etc" / "pam.d"
    pam_dir.mkdir(parents=True)
    common_session = pam_dir / "common-session"
    common_session.write_text(
        "session required pam_permit.so\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)
    assert len(findings) == 0


def test_pam_module_in_user_home(tmp_path):
    """Test detection of PAM .so module referencing /home/*."""
    pam_dir = tmp_path / "etc" / "pam.d"
    pam_dir.mkdir(parents=True)
    sshd = pam_dir / "sshd"
    sshd.write_text(
        "auth required /home/attacker/backdoor_pam.so\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "pam_module_persistence"
    assert f.technique_id == "T1556.003"
    assert f.risk_level == RiskLevel.CRITICAL
    assert "SYSTEM_PAM_POINTS_TO_USER_HOME" in f.details["flags"]
    assert "NON_ROOT_USER_PATH" in f.details["flags"]
    assert f.details["target_binary_path"] == "/home/attacker/backdoor_pam.so"


def test_pam_exec_with_user_home_script(tmp_path):
    """Test detection of pam_exec.so executing a script inside /home/*."""
    pam_dir = tmp_path / "etc" / "pam.d"
    pam_dir.mkdir(parents=True)
    sshd = pam_dir / "sshd"
    sshd.write_text(
        "auth required pam_exec.so quiet /home/user/hook.sh\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.risk_level == RiskLevel.CRITICAL
    assert "PAM_EXEC_HOOK" in f.details["flags"]
    assert "SYSTEM_PAM_POINTS_TO_USER_HOME" in f.details["flags"]
    assert "NON_ROOT_USER_PATH" in f.details["flags"]
    assert f.details["target_binary_path"] == "/home/user/hook.sh"


def test_pam_module_in_tmp_and_hidden_path(tmp_path):
    """Test detection of PAM module referencing /tmp and hidden directory."""
    pam_dir = tmp_path / "etc" / "pam.d"
    pam_dir.mkdir(parents=True)
    sshd = pam_dir / "sshd"
    sshd.write_text(
        "auth required /tmp/.hidden/pam_evil.so\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.risk_level == RiskLevel.CRITICAL
    assert "EXEC_FROM_TMP_OR_DEV_SHM" in f.details["flags"]
    assert "HIDDEN_PATH_EXECUTION" in f.details["flags"]


def test_pam_bracketed_control_and_multiline(tmp_path):
    """Test parsing PAM lines with bracketed control and line continuation."""
    pam_dir = tmp_path / "etc" / "pam.d"
    pam_dir.mkdir(parents=True)
    login = pam_dir / "login"
    login.write_text(
        "auth [success=ok default=bad] \\\n    pam_exec.so /dev/shm/hook.sh\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.details["control"] == "[success=ok default=bad]"
    assert "PAM_EXEC_HOOK" in f.details["flags"]
    assert "EXEC_FROM_TMP_OR_DEV_SHM" in f.details["flags"]


def test_pam_benign_configuration(tmp_path):
    """Test that benign standard PAM configurations produce zero findings."""
    pam_dir = tmp_path / "etc" / "pam.d"
    pam_dir.mkdir(parents=True)
    sshd = pam_dir / "sshd"
    sshd.write_text(
        "# Standard Ubuntu /etc/pam.d/sshd\n"
        "@include common-auth\n"
        "account required pam_nologin.so\n"
        "@include common-account\n"
        "session [success=ok default=1] pam_env.so\n"
        "session required pam_limits.so\n"
        "@include common-session\n"
        "@include common-password\n",
        encoding="utf-8",
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_pam_sudoers(target)
    assert len(findings) == 0


def test_parser_class_and_virtual_paths(tmp_path):
    """Test LinuxPamSudoersParser class and virtual_paths mapping."""
    sudo_file = tmp_path / "sudoers_mock"
    sudo_file.write_text(
        "bob ALL=(root) NOPASSWD: /home/user/script.sh\n", encoding="utf-8"
    )
    pam_file = tmp_path / "sshd_mock"
    pam_file.write_text("auth sufficient pam_permit.so\n", encoding="utf-8")

    target = AnalysisTarget(
        virtual_paths={
            "/etc/sudoers": str(sudo_file),
            "/etc/pam.d/sshd": str(pam_file),
        }
    )

    # Test class parser
    findings_inst = LinuxPamSudoersParser(target).parse()
    findings_cls = LinuxPamSudoersParser.parse_target(target)
    findings_direct = LinuxPamSudoersParser.parse(target)

    assert len(findings_inst) == 2
    assert len(findings_cls) == 2
    assert len(findings_direct) == 2

    categories = {f.category for f in findings_inst}
    assert "sudoers_privilege_persistence" in categories
    assert "pam_module_persistence" in categories
