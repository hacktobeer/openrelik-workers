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
"""Unit tests for Linux Dynamic Linker Preloading parser (linux_ld_preload)."""

from __future__ import annotations

from src.utils.linux_ld_preload import (
    LinuxLdPreloadParser,
    analyze_ld_preload,
    is_hidden_path,
    is_untrusted_library_dir,
)
from src.utils.models import AnalysisTarget, RiskLevel


def test_is_hidden_path():
    """Test is_hidden_path detects hidden components across directories and files."""
    assert is_hidden_path("/dev/shm/.hidden.so") is True
    assert is_hidden_path("/.hidden/evil.so") is True
    assert is_hidden_path("/home/user/.local/share/evil.so") is True
    assert is_hidden_path("/lib/evil.so") is False
    assert is_hidden_path("/usr/local/lib") is False
    assert is_hidden_path("/etc/ld.so.conf") is False


def test_is_untrusted_library_dir():
    """Test is_untrusted_library_dir distinguishes standard from untrusted search directories."""
    # Standard paths should NOT be flagged
    assert is_untrusted_library_dir("/usr/local/lib") is False
    assert is_untrusted_library_dir("/usr/lib") is False
    assert is_untrusted_library_dir("/lib") is False
    assert is_untrusted_library_dir("/usr/local/lib/x86_64-linux-gnu") is False

    # Untrusted / user / temporary paths MUST be flagged
    assert is_untrusted_library_dir("/home/attacker/lib") is True
    assert is_untrusted_library_dir("/home/user/.local/lib") is True
    assert is_untrusted_library_dir("/tmp") is True
    assert is_untrusted_library_dir("/tmp/evil_libs") is True
    assert is_untrusted_library_dir("/var/tmp/lib") is True
    assert is_untrusted_library_dir("/dev/shm/hidden") is True
    assert is_untrusted_library_dir("/root/libs") is True
    assert is_untrusted_library_dir("/.hidden_dir") is True
    assert is_untrusted_library_dir("./relative_path") is True
    assert is_untrusted_library_dir("relative/path") is True
    assert is_untrusted_library_dir("") is False


def test_empty_target(tmp_path):
    """Test empty target produces no ld.so.preload findings."""
    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_ld_preload(target)
    assert findings == []


def test_ld_so_preload_empty_and_comments(tmp_path):
    """Test comments and empty lines in ld.so.preload produce no findings."""
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)
    preload = etc / "ld.so.preload"
    preload.write_text("# This is a comment\n; Another comment style\n   \n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_ld_preload(target)
    assert findings == []


def test_ld_so_preload_standard_lib_evil(tmp_path):
    """Test preloaded shared library in standard path flags as high risk."""
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)
    preload = etc / "ld.so.preload"
    preload.write_text("/lib/evil.so\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_ld_preload(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "ld_preload_hijack"
    assert f.technique_id == "T1574.006"
    assert f.risk_level == RiskLevel.HIGH
    assert f.path == "/etc/ld.so.preload"
    assert f.details["library_path"] == "/lib/evil.so"
    assert "LD_SO_PRELOAD_ENTRY" in f.details["flags"]
    assert "SYSTEM_LD_PRELOAD_POINTS_TO_USER_HOME" not in f.details["flags"]
    assert "EXEC_FROM_TMP_OR_DEV_SHM" not in f.details["flags"]
    assert "HIDDEN_PATH_EXECUTION" not in f.details["flags"]
    assert f.raw_content == "/lib/evil.so"


def test_ld_so_preload_dev_shm_hidden(tmp_path):
    """Test preloaded library located in /dev/shm hidden path flags as critical."""
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)
    preload = etc / "ld.so.preload"
    preload.write_text("/dev/shm/.hidden.so\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_ld_preload(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "ld_preload_hijack"
    assert f.technique_id == "T1574.006"
    assert f.risk_level == RiskLevel.CRITICAL
    assert f.path == "/etc/ld.so.preload"
    assert f.details["library_path"] == "/dev/shm/.hidden.so"
    assert "LD_SO_PRELOAD_ENTRY" in f.details["flags"]
    assert "EXEC_FROM_TMP_OR_DEV_SHM" in f.details["flags"]
    assert "HIDDEN_PATH_EXECUTION" in f.details["flags"]


def test_ld_so_preload_user_home(tmp_path):
    """Test preloaded library located in user home directory flags as critical."""
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)
    preload = etc / "ld.so.preload"
    preload.write_text("/home/attacker/hook.so\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_ld_preload(target)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "ld_preload_hijack"
    assert f.technique_id == "T1574.006"
    assert f.risk_level == RiskLevel.CRITICAL
    assert f.path == "/etc/ld.so.preload"
    assert f.details["library_path"] == "/home/attacker/hook.so"
    assert "LD_SO_PRELOAD_ENTRY" in f.details["flags"]
    assert "SYSTEM_LD_PRELOAD_POINTS_TO_USER_HOME" in f.details["flags"]
    assert "NON_ROOT_USER_PATH" in f.details["flags"]


def test_ld_so_preload_tmp_and_var_tmp(tmp_path):
    """Test preloaded libraries located in /tmp and /var/tmp flag as critical."""
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)
    preload = etc / "ld.so.preload"
    preload.write_text("/tmp/rootkit.so\n/var/tmp/agent.so\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_ld_preload(target)

    assert len(findings) == 2
    for f in findings:
        assert f.category == "ld_preload_hijack"
        assert f.risk_level == RiskLevel.CRITICAL
        assert "LD_SO_PRELOAD_ENTRY" in f.details["flags"]
        assert "EXEC_FROM_TMP_OR_DEV_SHM" in f.details["flags"]


def test_ld_so_preload_multiple_entries_single_line_and_inline_comments(tmp_path):
    """Test multiple preloaded libraries on single line with inline comments."""
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)
    preload = etc / "ld.so.preload"
    preload.write_text(
        "# Global preload file\n"
        "/lib/evil.so  /home/attacker/hook.so # preloaded hooks\n"
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_ld_preload(target)

    assert len(findings) == 2
    paths = [f.details["library_path"] for f in findings]
    assert "/lib/evil.so" in paths
    assert "/home/attacker/hook.so" in paths


def test_ld_so_conf_standard_vs_untrusted_paths(tmp_path):
    """Test ld.so.conf.d files flag untrusted library directories and ignore standard paths."""
    etc = tmp_path / "etc"
    conf_d = etc / "ld.so.conf.d"
    conf_d.mkdir(parents=True)

    # Standard configuration file
    standard_conf = conf_d / "standard.conf"
    standard_conf.write_text(
        "# Standard system paths\n"
        "/usr/local/lib\n"
        "/usr/local/lib/x86_64-linux-gnu\n"
        "/lib/x86_64-linux-gnu\n"
    )

    # Untrusted configuration file
    untrusted_conf = conf_d / "malicious.conf"
    untrusted_conf.write_text(
        "# Injected malicious library directories\n"
        "/home/attacker/lib\n"
        "/tmp/evil_libs\n"
        "/dev/shm/hidden\n"
        "/.hidden_lib\n"
        "/usr/local/lib\n"  # Standard path mixed in
    )

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_ld_preload(target)

    # Only untrusted paths in malicious.conf should be flagged (4 findings)
    assert len(findings) == 4
    for f in findings:
        assert f.category == "ld_so_conf_hijack"
        assert f.technique_id == "T1574.006"
        assert f.risk_level == RiskLevel.HIGH
        assert f.path == "/etc/ld.so.conf.d/malicious.conf"
        assert "LD_CONF_UNTRUSTED_PATH" in f.details["flags"]

    flagged_dirs = [f.details["directory"] for f in findings]
    assert "/home/attacker/lib" in flagged_dirs
    assert "/tmp/evil_libs" in flagged_dirs
    assert "/dev/shm/hidden" in flagged_dirs
    assert "/.hidden_lib" in flagged_dirs
    assert "/usr/local/lib" not in flagged_dirs


def test_ld_so_conf_with_include_directive(tmp_path):
    """Test include directives in ld.so.conf recursively parse included conf files."""
    etc = tmp_path / "etc"
    conf_d = etc / "ld.so.conf.d"
    conf_d.mkdir(parents=True)

    ld_so_conf = etc / "ld.so.conf"
    ld_so_conf.write_text("include /etc/ld.so.conf.d/*.conf\n/tmp/direct_untrusted\n")

    extra_conf = conf_d / "extra.conf"
    extra_conf.write_text("/home/user/custom_libs\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = analyze_ld_preload(target)

    assert len(findings) == 2
    paths = {f.path for f in findings}
    assert "/etc/ld.so.conf" in paths
    assert "/etc/ld.so.conf.d/extra.conf" in paths

    dirs = {f.details["directory"] for f in findings}
    assert "/tmp/direct_untrusted" in dirs
    assert "/home/user/custom_libs" in dirs


def test_analysis_target_virtual_paths_mode(tmp_path):
    """Test ld.so.preload and conf parsing under virtual path mapping mode."""
    preload_file = tmp_path / "custom_preload"
    preload_file.write_text("/dev/shm/.hidden.so\n")

    conf_file = tmp_path / "custom_conf"
    conf_file.write_text("/usr/local/lib\n/tmp/injected\n")

    target = AnalysisTarget(
        virtual_paths={
            "/etc/ld.so.preload": str(preload_file),
            "/etc/ld.so.conf": str(conf_file),
        }
    )

    findings = analyze_ld_preload(target)
    assert len(findings) == 2

    preload_findings = [f for f in findings if f.category == "ld_preload_hijack"]
    assert len(preload_findings) == 1
    assert preload_findings[0].risk_level == RiskLevel.CRITICAL
    assert "EXEC_FROM_TMP_OR_DEV_SHM" in preload_findings[0].details["flags"]
    assert "HIDDEN_PATH_EXECUTION" in preload_findings[0].details["flags"]

    conf_findings = [f for f in findings if f.category == "ld_so_conf_hijack"]
    assert len(conf_findings) == 1
    assert conf_findings[0].details["directory"] == "/tmp/injected"
    assert "LD_CONF_UNTRUSTED_PATH" in conf_findings[0].details["flags"]


def test_parser_class_interface(tmp_path):
    """Test LinuxLdPreloadParser class parse method."""
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)
    preload = etc / "ld.so.preload"
    preload.write_text("/lib/evil.so\n")

    target = AnalysisTarget(root_path=str(tmp_path))
    findings = LinuxLdPreloadParser.parse(target)

    assert len(findings) == 1
    assert findings[0].details["library_path"] == "/lib/evil.so"
