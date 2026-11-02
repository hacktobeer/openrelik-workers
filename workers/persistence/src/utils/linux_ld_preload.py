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
"""Linux Dynamic Linker Preloading (ld.so.preload & ld.so.conf.d) parser."""

from __future__ import annotations

from src.utils.models import AnalysisTarget, Finding, RiskLevel, normalize_virtual_path


def is_hidden_path(path: str) -> bool:
    """Check if any path component (directory or filename) is hidden (starts with a dot).

    Args:
        path: Filesystem path string to test.

    Returns:
        True if any path segment starts with a dot (excluding '.' and '..'), False otherwise.
    """
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    return any(part.startswith(".") and part not in (".", "..") for part in parts)


def is_untrusted_library_dir(path: str) -> bool:
    """Check if a library directory in ld.so.conf or ld.so.conf.d is untrusted or non-standard.

    Args:
        path: Library directory path string.

    Returns:
        True if the path is relative, hidden, or points to untrusted locations, False otherwise.
    """
    cleaned = path.strip()
    if not cleaned:
        return False

    # Relative paths are non-standard and dangerous in ld.so.conf
    if not cleaned.startswith("/"):
        return True

    norm = normalize_virtual_path(cleaned)

    # Hidden directories or paths (e.g. /.hidden, /usr/lib/.secret, /.)
    if is_hidden_path(norm) or "/." in cleaned:
        return True

    untrusted_prefixes = (
        "/home/",
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/root/",
        "/run/user/",
        "/run/shm/",
    )
    untrusted_exact = (
        "/home",
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/root",
    )

    return bool(norm in untrusted_exact or norm.startswith(untrusted_prefixes))


def _parse_ld_so_preload(target: AnalysisTarget) -> list[Finding]:
    """Parse /etc/ld.so.preload and flag preloaded shared objects.

    Args:
        target: Forensic analysis target.

    Returns:
        List of findings detected in /etc/ld.so.preload.
    """
    findings: list[Finding] = []
    preload_path = "/etc/ld.so.preload"

    if not target.exists(preload_path):
        return findings

    content = target.read_text(preload_path)
    if not content:
        return findings

    for line in content.splitlines():
        # Strip inline comments starting with '#' or ';'
        clean_line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not clean_line:
            continue

        # ld.so.preload contains whitespace-separated list of shared objects
        entries = clean_line.split()
        for entry in entries:
            entry_path = entry.strip()
            if not entry_path:
                continue

            norm_path = normalize_virtual_path(entry_path)
            flags = ["LD_SO_PRELOAD_ENTRY"]
            is_critical = False

            # Check if .so resides in /home/*
            if norm_path.startswith("/home/") or norm_path == "/home":
                flags.append("SYSTEM_LD_PRELOAD_POINTS_TO_USER_HOME")
                flags.append("NON_ROOT_USER_PATH")
                is_critical = True

            # Check if .so resides in /tmp, /var/tmp, /dev/shm
            if norm_path.startswith(
                ("/tmp/", "/var/tmp/", "/dev/shm/")
            ) or norm_path in ("/tmp", "/var/tmp", "/dev/shm"):
                flags.append("EXEC_FROM_TMP_OR_DEV_SHM")
                is_critical = True

            # Check if .so resides in a hidden path
            if is_hidden_path(norm_path) or "/." in entry_path:
                flags.append("HIDDEN_PATH_EXECUTION")
                is_critical = True

            risk_level = RiskLevel.CRITICAL if is_critical else RiskLevel.HIGH

            findings.append(
                Finding(
                    category="ld_preload_hijack",
                    risk_level=risk_level,
                    technique_id="T1574.006",
                    path=preload_path,
                    details={
                        "library_path": entry_path,
                        "target_path": entry_path,
                        "flags": flags,
                    },
                    raw_content=line.strip(),
                )
            )

    return findings


def _parse_ld_so_conf(target: AnalysisTarget) -> list[Finding]:
    """Parse /etc/ld.so.conf and /etc/ld.so.conf.d/* for untrusted library search paths.

    Args:
        target: Forensic analysis target.

    Returns:
        List of findings for untrusted search paths.
    """
    findings: list[Finding] = []

    # Queue of configuration files to parse
    to_scan: list[str] = []
    if target.exists("/etc/ld.so.conf"):
        to_scan.append("/etc/ld.so.conf")

    # Also discover all files directly under /etc/ld.so.conf.d/
    for conf_file in target.glob("/etc/ld.so.conf.d/*"):
        if conf_file not in to_scan:
            to_scan.append(conf_file)

    scanned_files: set[str] = set()

    while to_scan:
        current_file = to_scan.pop(0)
        if current_file in scanned_files:
            continue
        scanned_files.add(current_file)

        content = target.read_text(current_file)
        if not content:
            continue

        for line in content.splitlines():
            clean_line = line.split("#", 1)[0].split(";", 1)[0].strip()
            if not clean_line:
                continue

            # Handle include directives (e.g. include /etc/ld.so.conf.d/*.conf)
            if clean_line.startswith(("include ", "include\t")):
                inc_pattern = clean_line.split(None, 1)[1].strip()
                if not inc_pattern.startswith("/"):
                    inc_pattern = "/etc/" + inc_pattern
                for inc_file in target.glob(inc_pattern):
                    if inc_file not in scanned_files and inc_file not in to_scan:
                        to_scan.append(inc_file)
                continue

            # Delimiters for multiple directories on a single line
            tokens = clean_line.replace(",", " ").replace(":", " ").split()
            for token in tokens:
                dir_path = token.strip()
                if not dir_path:
                    continue

                if is_untrusted_library_dir(dir_path):
                    norm_dir = normalize_virtual_path(dir_path)
                    flags = ["LD_CONF_UNTRUSTED_PATH"]
                    if norm_dir.startswith("/home/") or norm_dir == "/home":
                        flags.append("NON_ROOT_USER_PATH")
                    if norm_dir.startswith(
                        ("/tmp/", "/var/tmp/", "/dev/shm/")
                    ) or norm_dir in ("/tmp", "/var/tmp", "/dev/shm"):
                        flags.append("EXEC_FROM_TMP_OR_DEV_SHM")
                    if is_hidden_path(norm_dir) or "/." in dir_path:
                        flags.append("HIDDEN_PATH_EXECUTION")

                    findings.append(
                        Finding(
                            category="ld_so_conf_hijack",
                            risk_level=RiskLevel.HIGH,
                            technique_id="T1574.006",
                            path=current_file,
                            details={
                                "directory": dir_path,
                                "target_path": dir_path,
                                "flags": flags,
                            },
                            raw_content=line.strip(),
                        )
                    )

    return findings


def analyze_ld_preload(target: AnalysisTarget) -> list[Finding]:
    """Analyze Linux target for dynamic linker preloading and configuration persistence.

    Scans:
      - /etc/ld.so.preload for injected shared libraries (MITRE ATT&CK T1574.006).
      - /etc/ld.so.conf and /etc/ld.so.conf.d/* for untrusted library search directories.

    Args:
        target: The mounted disk image or extracted artifact target.

    Returns:
        List of Finding objects identifying persistence mechanisms and risk details.
    """
    findings: list[Finding] = []
    findings.extend(_parse_ld_so_preload(target))
    findings.extend(_parse_ld_so_conf(target))
    return findings


class LinuxLdPreloadParser:
    """Parser class interface for dynamic linker preloading persistence."""

    @staticmethod
    def parse(target: AnalysisTarget) -> list[Finding]:
        """Parse dynamic linker preloading persistence artifacts.

        Args:
            target: The AnalysisTarget to inspect.

        Returns:
            List of detected persistence findings.
        """
        return analyze_ld_preload(target)


__all__ = [
    "LinuxLdPreloadParser",
    "analyze_ld_preload",
    "is_hidden_path",
    "is_untrusted_library_dir",
]
