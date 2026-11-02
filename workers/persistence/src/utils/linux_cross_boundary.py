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
"""Linux cross-boundary correlation module.

Detects privilege boundary violations where system-level configurations
(systemd services, system crontabs, init scripts, PAM/sudoers, etc.) execute
binaries or scripts located in user home directories (/home/<user>/...) or
world-writable temporary paths (/tmp/..., /var/tmp/..., /dev/shm/...).
"""

from __future__ import annotations

import posixpath
import re
from typing import Any

from src.utils.models import AnalysisTarget, Finding, RiskLevel, normalize_virtual_path

# Regexes for extracting user home directory paths and owners
QUOTED_HOME_RE: re.Pattern[str] = re.compile(r"""['"](/home/([^/'"]+)/[^'"]+)['"]""")
UNQUOTED_HOME_RE: re.Pattern[str] = re.compile(r"""(/home/([^/\s"';`]+)/[^\s"';`]+)""")

# Regexes for extracting world-writable temporary directory paths
QUOTED_TEMP_RE: re.Pattern[str] = re.compile(
    r"""['"]((?:/tmp|/var/tmp|/dev/shm)/[^'"]+)['"]"""
)
UNQUOTED_TEMP_RE: re.Pattern[str] = re.compile(
    r"""((?:/tmp|/var/tmp|/dev/shm)(?:/[^\s"';`]+)?)"""
)

SYSTEM_CONFIG_PREFIXES: tuple[str, ...] = (
    "/etc/",
    "/lib/",
    "/usr/lib/",
    "/var/spool/cron/",
    "/var/cron/",
)

SYSTEM_CANDIDATE_GLOBS: list[str] = [
    "/etc/systemd/system/*.service",
    "/etc/systemd/system/**/*.service",
    "/lib/systemd/system/*.service",
    "/usr/lib/systemd/system/*.service",
    "/etc/crontab",
    "/etc/cron.d/*",
    "/etc/cron.daily/*",
    "/etc/cron.hourly/*",
    "/etc/cron.weekly/*",
    "/etc/cron.monthly/*",
    "/etc/anacrontab",
    "/var/spool/cron/*",
    "/var/spool/cron/crontabs/*",
    "/etc/rc.local",
    "/etc/init.d/*",
    "/etc/sudoers",
    "/etc/sudoers.d/*",
    "/etc/xdg/autostart/*.desktop",
]


def extract_user_home_path(text: str) -> tuple[str, str] | None:
    """Extract a (/home/<user>/<path>, <user>) tuple from text if present.

    Args:
        text: Text string (e.g. command line, config content) to inspect.

    Returns:
        Tuple of (full_path, username) if found, or None.
    """
    if not text or "/home/" not in text:
        return None

    # Check quoted paths first
    m_quoted = QUOTED_HOME_RE.search(text)
    if m_quoted:
        path = m_quoted.group(1).strip()
        user = m_quoted.group(2).strip()
        return path, user

    # Check unquoted paths
    m_unquoted = UNQUOTED_HOME_RE.search(text)
    if m_unquoted:
        path = m_unquoted.group(1).strip()
        while path and path[-1] in ".,:;)":
            path = path[:-1]
        user = m_unquoted.group(2).strip()
        return path, user

    return None


def extract_temp_path(text: str) -> str | None:
    """Extract a (/tmp/..., /var/tmp/..., or /dev/shm/...) path from text if present.

    Args:
        text: Text string to inspect for temporary directory paths.

    Returns:
        Extracted temporary path string if found, or None.
    """
    if not text:
        return None
    if not any(tp in text for tp in ("/tmp", "/var/tmp", "/dev/shm")):
        return None

    m_quoted = QUOTED_TEMP_RE.search(text)
    if m_quoted:
        return m_quoted.group(1).strip()

    m_unquoted = UNQUOTED_TEMP_RE.search(text)
    if m_unquoted:
        path = m_unquoted.group(1).strip()
        while path and path[-1] in ".,:;)":
            path = path[:-1]
        return path

    return None


def is_system_config_path(path: str) -> bool:
    """Check if virtual path represents a system-level configuration.

    Args:
        path: Virtual path string to test.

    Returns:
        True if the path represents a system-level location, False otherwise.
    """
    if not path:
        return False
    norm = normalize_virtual_path(path)
    if norm.startswith(("/home/", "/root/")):
        return False
    return any(norm.startswith(prefix) for prefix in SYSTEM_CONFIG_PREFIXES)


def _detect_config_type(path: str, category: str = "") -> tuple[str, str, bool, bool]:
    """Detect configuration type (category prefix, technique_id, is_systemd, is_cron).

    Args:
        path: Virtual configuration path.
        category: Existing finding category if available.

    Returns:
        Tuple of (promoted_category, technique_id, is_systemd, is_cron).
    """
    norm_path = normalize_virtual_path(path).lower()
    cat_lower = category.lower()

    if (
        "systemd" in cat_lower
        or "systemd" in norm_path
        or norm_path.endswith((".service", ".timer", ".socket"))
    ):
        return "cross_boundary_systemd", "T1543.002", True, False

    if "cron" in cat_lower or "cron" in norm_path or "anacron" in norm_path:
        return "cross_boundary_cron", "T1053.003", False, True

    if (
        "init" in cat_lower
        or "rc.local" in norm_path
        or "init.d" in norm_path
        or "/rc" in norm_path
    ):
        return "cross_boundary_init", "T1037.004", False, False

    if (
        "autostart" in cat_lower
        or norm_path.endswith(".desktop")
        or "autostart" in norm_path
    ):
        return "cross_boundary_autostart", "T1547.013", False, False

    base = category.replace("cross_boundary_", "") if category else "config"
    return f"cross_boundary_{base}", "T1543.002", False, False


def _ensure_flags(details: dict[str, Any], flags_to_add: list[str]) -> None:
    """Ensure specified flags are present in details['flags'].

    Args:
        details: Finding details dictionary to update.
        flags_to_add: List of flag strings to ensure are present.
    """
    raw_flags = details.setdefault("flags", [])
    if isinstance(raw_flags, str):
        flag_list = [raw_flags]
        details["flags"] = flag_list
    elif isinstance(raw_flags, list):
        flag_list = raw_flags
    else:
        flag_list = list(raw_flags)
        details["flags"] = flag_list

    for flag in flags_to_add:
        if flag not in flag_list:
            flag_list.append(flag)


def _search_finding_for_user_home(finding: Finding) -> tuple[str, str] | None:
    """Search finding details and raw_content for a user home path.

    Args:
        finding: The finding object to inspect.

    Returns:
        Tuple of (user_home_path, username) if found, or None.
    """
    # Check common detail fields first
    for key in (
        "target_binary_path",
        "exec_start",
        "exec",
        "command",
        "script",
        "working_directory",
    ):
        val = finding.details.get(key)
        if isinstance(val, str):
            res = extract_user_home_path(val)
            if res:
                return res

    # Check all detail string values
    for val in finding.details.values():
        if isinstance(val, str):
            res = extract_user_home_path(val)
            if res:
                return res

    # Check raw_content
    if finding.raw_content:
        res = extract_user_home_path(finding.raw_content)
        if res:
            return res

    return None


def _search_finding_for_temp_path(finding: Finding) -> str | None:
    """Search finding details and raw_content for a temp path.

    Args:
        finding: The finding object to inspect.

    Returns:
        Temporary path string if found, or None.
    """
    for key in (
        "target_binary_path",
        "exec_start",
        "exec",
        "command",
        "script",
        "working_directory",
    ):
        val = finding.details.get(key)
        if isinstance(val, str):
            res = extract_temp_path(val)
            if res:
                return res

    for val in finding.details.values():
        if isinstance(val, str):
            res = extract_temp_path(val)
            if res:
                return res

    if finding.raw_content:
        res = extract_temp_path(finding.raw_content)
        if res:
            return res

    return None


def _enrich_home_finding(finding: Finding, target_path: str, target_user: str) -> None:
    """Enrich an existing finding with cross-boundary user home attributes.

    Args:
        finding: The finding object to enrich in-place.
        target_path: Target binary or script path inside /home/<user>/*.
        target_user: Extracted username owning the target binary.
    """
    promoted_cat, default_technique, is_systemd, is_cron = _detect_config_type(
        finding.path, finding.category
    )
    finding.risk_level = RiskLevel.CRITICAL
    finding.category = promoted_cat
    if not finding.technique_id:
        finding.technique_id = default_technique

    finding.details["system_config_path"] = finding.path
    finding.details["target_binary_path"] = target_path
    finding.details["target_binary_owner"] = target_user

    if is_systemd:
        _ensure_flags(
            finding.details,
            ["SYSTEM_SERVICE_POINTS_TO_USER_HOME", "NON_ROOT_USER_PATH"],
        )
        if "service_name" not in finding.details and finding.path:
            finding.details["service_name"] = posixpath.basename(finding.path)
    else:
        flags_to_add = ["CROSS_BOUNDARY_USER_HOME_EXECUTION", "NON_ROOT_USER_PATH"]
        if is_cron:
            flags_to_add.append("SYSTEM_CRON_POINTS_TO_USER_HOME")
        _ensure_flags(finding.details, flags_to_add)


def _enrich_temp_finding(finding: Finding, temp_path: str) -> None:
    """Enrich an existing finding with cross-boundary temp path attributes.

    Args:
        finding: The finding object to enrich in-place.
        temp_path: Target binary or script path inside temporary directory.
    """
    promoted_cat, default_technique, is_systemd, is_cron = _detect_config_type(
        finding.path, finding.category
    )
    finding.risk_level = RiskLevel.CRITICAL
    finding.category = promoted_cat
    if not finding.technique_id:
        finding.technique_id = default_technique

    finding.details["system_config_path"] = finding.path
    finding.details["target_binary_path"] = temp_path

    if is_systemd:
        _ensure_flags(
            finding.details,
            ["SUSPICIOUS_PATH_TMP", "CROSS_BOUNDARY_TEMP_EXECUTION"],
        )
        if "service_name" not in finding.details and finding.path:
            finding.details["service_name"] = posixpath.basename(finding.path)
    elif is_cron:
        _ensure_flags(
            finding.details,
            ["CRON_EXECUTES_FROM_TMP", "CROSS_BOUNDARY_TEMP_EXECUTION"],
        )
    else:
        _ensure_flags(finding.details, ["CROSS_BOUNDARY_TEMP_EXECUTION"])


def _extract_exec_start_from_content(content: str) -> str | None:
    """Extract ExecStart directive value from systemd unit content.

    Args:
        content: Raw unit file text content.

    Returns:
        ExecStart value string if present, or None.
    """
    for line in content.splitlines():
        clean = line.strip()
        if clean.startswith("ExecStart="):
            return clean.split("=", 1)[1].strip()
    return None


def analyze_cross_boundary(
    target: AnalysisTarget | None = None,
    existing_findings: list[Finding] | None = None,
) -> list[Finding]:
    """Inspect and correlate cross-boundary persistence mechanisms.

    Examines existing findings from system configurations and scans target files
    for system-level services or tasks executing files in user home directories
    (/home/<username>/...) or temporary directories (/tmp, /var/tmp, /dev/shm).

    Args:
        target: The analysis target containing file access methods.
        existing_findings: Optional list of findings already generated by parsers.

    Returns:
        List of findings including enriched existing findings and newly
        discovered cross-boundary findings.
    """
    results: list[Finding] = list(existing_findings or [])
    handled_paths: set[str] = set()

    # 1. Inspect and enrich existing findings
    for finding in results:
        norm_path = normalize_virtual_path(finding.path)
        handled_paths.add(norm_path)

        if not is_system_config_path(norm_path):
            continue

        home_res = _search_finding_for_user_home(finding)
        if home_res:
            target_path, target_user = home_res
            _enrich_home_finding(finding, target_path, target_user)
            continue

        temp_res = _search_finding_for_temp_path(finding)
        if temp_res:
            _enrich_temp_finding(finding, temp_res)

    # 2. If target is provided, scan remaining system configuration files
    if target is not None:
        candidate_paths: set[str] = set()

        for pattern in SYSTEM_CANDIDATE_GLOBS:
            for vpath in target.glob(pattern):
                norm_v = normalize_virtual_path(vpath)
                if norm_v not in handled_paths:
                    candidate_paths.add(norm_v)

        # Include any mapped virtual paths residing in system configuration roots
        for vpath in getattr(target, "virtual_paths", {}):
            norm_v = normalize_virtual_path(vpath)
            if is_system_config_path(norm_v) and norm_v not in handled_paths:
                candidate_paths.add(norm_v)

        for vpath in sorted(candidate_paths):
            content = target.read_text(vpath)
            if not content:
                continue

            home_res = extract_user_home_path(content)
            if home_res:
                target_path, target_user = home_res
                promoted_cat, tech_id, is_systemd, is_cron = _detect_config_type(vpath)
                details: dict[str, Any] = {
                    "system_config_path": vpath,
                    "target_binary_path": target_path,
                    "target_binary_owner": target_user,
                    "flags": (
                        ["SYSTEM_SERVICE_POINTS_TO_USER_HOME", "NON_ROOT_USER_PATH"]
                        if is_systemd
                        else [
                            "CROSS_BOUNDARY_USER_HOME_EXECUTION",
                            "NON_ROOT_USER_PATH",
                        ]
                    ),
                }
                if is_systemd:
                    details["service_name"] = posixpath.basename(vpath)
                    exec_val = _extract_exec_start_from_content(content)
                    if exec_val:
                        details["exec_start"] = exec_val
                elif is_cron:
                    details["flags"].append("SYSTEM_CRON_POINTS_TO_USER_HOME")

                new_finding = Finding(
                    category=promoted_cat,
                    risk_level=RiskLevel.CRITICAL,
                    technique_id=tech_id,
                    path=vpath,
                    details=details,
                    raw_content=content,
                )
                results.append(new_finding)
                handled_paths.add(vpath)
                continue

            temp_res = extract_temp_path(content)
            if temp_res:
                promoted_cat, tech_id, is_systemd, is_cron = _detect_config_type(vpath)
                details = {
                    "system_config_path": vpath,
                    "target_binary_path": temp_res,
                    "flags": (
                        ["SUSPICIOUS_PATH_TMP", "CROSS_BOUNDARY_TEMP_EXECUTION"]
                        if is_systemd
                        else (
                            ["CRON_EXECUTES_FROM_TMP", "CROSS_BOUNDARY_TEMP_EXECUTION"]
                            if is_cron
                            else ["CROSS_BOUNDARY_TEMP_EXECUTION"]
                        )
                    ),
                }
                if is_systemd:
                    details["service_name"] = posixpath.basename(vpath)
                    exec_val = _extract_exec_start_from_content(content)
                    if exec_val:
                        details["exec_start"] = exec_val

                new_finding = Finding(
                    category=promoted_cat,
                    risk_level=RiskLevel.CRITICAL,
                    technique_id=tech_id,
                    path=vpath,
                    details=details,
                    raw_content=content,
                )
                results.append(new_finding)
                handled_paths.add(vpath)

    return results


class LinuxCrossBoundaryAnalyzer:
    """Class wrapper for cross-boundary persistence correlation."""

    def __init__(self, target: AnalysisTarget | None = None) -> None:
        """Initialize with an optional target.

        Args:
            target: Optional AnalysisTarget to associate with this instance.
        """
        self.target: AnalysisTarget | None = target

    def correlate(
        self,
        target: AnalysisTarget | None = None,
        existing_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Correlate existing findings or scan target for boundary violations.

        Args:
            target: Optional target override.
            existing_findings: Optional list of findings to correlate.

        Returns:
            List of findings including boundary violation enrichments.
        """
        tgt = target or self.target
        return analyze_cross_boundary(tgt, existing_findings)

    def analyze(self, existing_findings: list[Finding] | None = None) -> list[Finding]:
        """Analyze configured target for boundary violations.

        Args:
            existing_findings: Optional list of existing findings to correlate.

        Returns:
            List of findings with boundary violations analyzed.
        """
        return analyze_cross_boundary(self.target, existing_findings)


__all__ = [
    "LinuxCrossBoundaryAnalyzer",
    "analyze_cross_boundary",
    "extract_temp_path",
    "extract_user_home_path",
    "is_system_config_path",
]
