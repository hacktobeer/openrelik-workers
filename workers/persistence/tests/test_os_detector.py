# Copyright 2025 Google LLC
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
"""Unit tests for OS and hostname detector."""

from __future__ import annotations

from src.utils.models import AnalysisTarget
from src.utils.os_detector import build_analysis_context, detect_os_and_hostname


def test_detect_os_and_hostname_standard(tmp_path):
    """Verify hostname is parsed from /etc/hostname."""
    host_file = tmp_path / "hostname"
    host_file.write_text("cloud-prod-web-01\n")

    target = AnalysisTarget(
        virtual_paths={"/etc/hostname": str(host_file)},
    )
    os_name, hostname = detect_os_and_hostname(target)
    assert os_name == "linux"
    assert hostname == "cloud-prod-web-01"


def test_detect_os_and_hostname_with_comments_and_blank_lines(tmp_path):
    """Verify comments and blank lines are ignored when reading /etc/hostname."""
    host_file = tmp_path / "hostname"
    host_file.write_text(
        "\n\n# Configuration comment\n  db-node-primary  \nsecond-line\n"
    )

    target = AnalysisTarget(
        virtual_paths={"/etc/hostname": str(host_file)},
    )
    os_name, hostname = detect_os_and_hostname(target)
    assert os_name == "linux"
    assert hostname == "db-node-primary"


def test_detect_os_and_hostname_missing_hostname():
    """Verify default hostname 'unknown' when /etc/hostname is missing."""
    target = AnalysisTarget(virtual_paths={})
    os_name, hostname = detect_os_and_hostname(target)
    assert os_name == "linux"
    assert hostname == "unknown"


def test_detect_os_and_hostname_empty_hostname(tmp_path):
    """Verify default hostname 'unknown' when /etc/hostname has only spaces or comments."""
    host_file = tmp_path / "hostname"
    host_file.write_text("# only comments\n   \n")

    target = AnalysisTarget(virtual_paths={"/etc/hostname": str(host_file)})
    os_name, hostname = detect_os_and_hostname(target)
    assert os_name == "linux"
    assert hostname == "unknown"


def test_detect_os_release_files(tmp_path):
    """Verify OS identification from /etc/os-release and fallbacks."""
    os_rel = tmp_path / "os-release"
    os_rel.write_text('NAME="Ubuntu"\nVERSION="24.04 LTS"\nID=ubuntu\n')

    target_etc = AnalysisTarget(virtual_paths={"/etc/os-release": str(os_rel)})
    assert detect_os_and_hostname(target_etc)[0] == "linux"

    target_usr = AnalysisTarget(virtual_paths={"/usr/lib/os-release": str(os_rel)})
    assert detect_os_and_hostname(target_usr)[0] == "linux"

    target_lsb = AnalysisTarget(virtual_paths={"/etc/lsb-release": str(os_rel)})
    assert detect_os_and_hostname(target_lsb)[0] == "linux"


def test_detect_os_from_linux_paths(tmp_path):
    """Verify OS identification from virtual paths or root_path."""
    target_vpaths = AnalysisTarget(
        virtual_paths={"/etc/systemd/system/malicious.service": str(tmp_path)}
    )
    assert detect_os_and_hostname(target_vpaths)[0] == "linux"

    # Test root_path directory layout
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir()
    target_root = AnalysisTarget(root_path=str(tmp_path))
    assert detect_os_and_hostname(target_root)[0] == "linux"


def test_build_analysis_context(tmp_path):
    """Verify build_analysis_context creates an AnalysisContext with all properties."""
    host_file = tmp_path / "hostname"
    host_file.write_text("worker-node-42\n")

    target = AnalysisTarget(
        virtual_paths={"/etc/hostname": str(host_file)},
    )
    context = build_analysis_context(target)
    assert context.target is target
    assert context.os_name == "linux"
    assert context.hostname == "worker-node-42"
