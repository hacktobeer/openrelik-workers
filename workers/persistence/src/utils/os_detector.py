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
"""Operating System and Hostname detector for persistence analysis targets."""

from __future__ import annotations

from src.utils.models import AnalysisContext, AnalysisTarget


def detect_os_and_hostname(target: AnalysisTarget) -> tuple[str, str]:
    """Detect operating system name and hostname from an AnalysisTarget.

    Args:
        target: The target filesystem abstraction (mounted image or extracted files).

    Returns:
        A tuple of (os_name, hostname), e.g. ('linux', 'prod-web-01').
    """
    hostname = "unknown"
    hostname_content = target.read_text("/etc/hostname")
    if hostname_content:
        for line in hostname_content.splitlines():
            clean_line = line.strip()
            if clean_line and not clean_line.startswith("#"):
                hostname = clean_line
                break

    # Check os-release files or check Linux directory structure
    os_release = target.read_text("/etc/os-release")
    if not os_release:
        os_release = target.read_text("/usr/lib/os-release")
    if not os_release:
        os_release = target.read_text("/etc/lsb-release")

    # Persistence worker targets Linux artifacts; defaults to "linux"
    os_name = "linux"

    return os_name, hostname


def build_analysis_context(target: AnalysisTarget) -> AnalysisContext:
    """Build an AnalysisContext from an AnalysisTarget by detecting OS and hostname.

    Args:
        target: The target filesystem abstraction.

    Returns:
        An AnalysisContext populated with target, detected os_name, and hostname.
    """
    os_name, hostname = detect_os_and_hostname(target)
    return AnalysisContext(target=target, os_name=os_name, hostname=hostname)


__all__ = [
    "build_analysis_context",
    "detect_os_and_hostname",
]
