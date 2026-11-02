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
"""Linux sudoers and PAM modules persistence parser and analyzer."""

from __future__ import annotations

import posixpath
import re
from typing import Any

from src.utils.models import AnalysisTarget, Finding, RiskLevel

SUDOERS_TECHNIQUE_ID: str = "T1548.003"
SUDOERS_CATEGORY: str = "sudoers_privilege_persistence"

PAM_TECHNIQUE_ID: str = "T1556.003"
PAM_CATEGORY: str = "pam_module_persistence"


def _is_user_home(path: str) -> bool:
    """Check if path is located in a user home directory.

    Args:
        path: Path string to test.

    Returns:
        True if path is inside /home or starts with ~, False otherwise.
    """
    clean = path.replace("\\", "/").strip("\"'")
    return clean == "/home" or clean.startswith(("/home/", "~"))


def _is_tmp_or_dev_shm(path: str) -> bool:
    """Check if path is located in /tmp, /var/tmp, or /dev/shm.

    Args:
        path: Path string to test.

    Returns:
        True if path starts with temporary directory prefixes, False otherwise.
    """
    clean = path.replace("\\", "/").strip("\"'")
    return clean in ("/tmp", "/var/tmp", "/dev/shm") or clean.startswith(
        ("/tmp/", "/var/tmp/", "/dev/shm/")
    )


def _is_hidden_path(path: str) -> bool:
    """Check if path or any parent directory segment is hidden.

    Args:
        path: Path string to test.

    Returns:
        True if any path segment starts with a dot (excluding '.' and '..'), False otherwise.
    """
    clean = path.replace("\\", "/").strip("\"'")
    parts = [p for p in clean.split("/") if p]
    return any(p.startswith(".") and p not in (".", "..") for p in parts)


def _join_multiline(text: str) -> list[tuple[int, str]]:
    """Join physical lines ending with backslash into logical lines with 1-based start line.

    Args:
        text: Multiline string to process.

    Returns:
        List of tuples containing (start_line_number, joined_logical_line).
    """
    logical_lines: list[tuple[int, str]] = []
    current_start = 1
    current_parts: list[str] = []

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not current_parts:
            current_start = line_no

        if stripped.endswith("\\"):
            current_parts.append(stripped[:-1].strip())
        else:
            if current_parts:
                current_parts.append(stripped)
                logical_lines.append((current_start, " ".join(current_parts)))
                current_parts = []
            else:
                logical_lines.append((line_no, stripped))

    if current_parts:
        logical_lines.append((current_start, " ".join(current_parts)))

    return logical_lines


def _parse_sudoers_file(target: AnalysisTarget, file_path: str) -> list[Finding]:
    """Parse a sudoers file and extract persistence and privilege escalation findings.

    Args:
        target: Forensic analysis target.
        file_path: Virtual path of the sudoers file.

    Returns:
        List of findings extracted from the sudoers configuration.
    """
    content = target.read_text(file_path)
    if content is None:
        return []

    findings: list[Finding] = []
    logical_lines = _join_multiline(content)

    for line_num, line in logical_lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue

        # 1. Defaults entries
        if re.match(r"^Defaults(?:\b|[:!>@\s])", line_clean, re.IGNORECASE):
            defaults_flags: list[str] = []

            # Check LD_PRELOAD in env_keep
            if re.search(r"\benv_keep\b", line_clean, re.IGNORECASE) and re.search(
                r"\bLD_PRELOAD\b", line_clean
            ):
                defaults_flags.append("SUDOERS_ENV_KEEP_LD_PRELOAD")

            # Check !authenticate
            if re.search(r"!\s*authenticate\b", line_clean, re.IGNORECASE):
                defaults_flags.append("SUDOERS_NO_AUTHENTICATE")

            if defaults_flags:
                if "SUDOERS_ENV_KEEP_LD_PRELOAD" in defaults_flags:
                    risk = RiskLevel.CRITICAL
                else:
                    risk = RiskLevel.HIGH

                finding = Finding(
                    category=SUDOERS_CATEGORY,
                    risk_level=risk,
                    technique_id=SUDOERS_TECHNIQUE_ID,
                    path=file_path,
                    details={
                        "flags": defaults_flags,
                        "line_number": line_num,
                        "rule": line_clean,
                        "system_config_path": file_path,
                        "entry_type": "Defaults",
                    },
                    raw_content=line,
                )
                findings.append(finding)
            continue

        # 2. Active rule specifications
        rule_flags: list[str] = []
        target_binary_path: str | None = None

        # Check NOPASSWD
        if re.search(r"\bNOPASSWD\s*:", line_clean):
            rule_flags.append("SUDOERS_NOPASSWD")

        # Check !authenticate
        if re.search(r"!\s*authenticate\b", line_clean, re.IGNORECASE):
            rule_flags.append("SUDOERS_NO_AUTHENTICATE")

        # Inspect tokens for path destinations
        tokens = line_clean.split()
        for tok in tokens:
            clean_tok = tok.strip("(),:\"'")
            if _is_user_home(clean_tok):
                if "SYSTEM_SUDOERS_POINTS_TO_USER_HOME" not in rule_flags:
                    rule_flags.extend(
                        ["SYSTEM_SUDOERS_POINTS_TO_USER_HOME", "NON_ROOT_USER_PATH"]
                    )
                if target_binary_path is None:
                    target_binary_path = clean_tok
            elif _is_tmp_or_dev_shm(clean_tok):
                if "EXEC_FROM_TMP_OR_DEV_SHM" not in rule_flags:
                    rule_flags.append("EXEC_FROM_TMP_OR_DEV_SHM")
                if target_binary_path is None:
                    target_binary_path = clean_tok

        if rule_flags:
            if (
                "SYSTEM_SUDOERS_POINTS_TO_USER_HOME" in rule_flags
                or "EXEC_FROM_TMP_OR_DEV_SHM" in rule_flags
            ):
                risk = RiskLevel.CRITICAL
            elif (
                "SUDOERS_NOPASSWD" in rule_flags
                or "SUDOERS_NO_AUTHENTICATE" in rule_flags
            ):
                risk = RiskLevel.HIGH
            else:
                risk = RiskLevel.MEDIUM

            user_spec = tokens[0] if tokens else "unknown"

            details: dict[str, Any] = {
                "flags": rule_flags,
                "line_number": line_num,
                "rule": line_clean,
                "user": user_spec,
                "system_config_path": file_path,
                "entry_type": "Rule",
            }
            if target_binary_path:
                details["target_binary_path"] = target_binary_path

            finding = Finding(
                category=SUDOERS_CATEGORY,
                risk_level=risk,
                technique_id=SUDOERS_TECHNIQUE_ID,
                path=file_path,
                details=details,
                raw_content=line,
            )
            findings.append(finding)

    return findings


def _parse_pam_file(target: AnalysisTarget, file_path: str) -> list[Finding]:
    """Parse a PAM configuration file and extract persistence and bypass findings.

    Args:
        target: Forensic analysis target.
        file_path: Virtual path of the PAM configuration file.

    Returns:
        List of findings extracted from the PAM configuration.
    """
    content = target.read_text(file_path)
    if content is None:
        return []

    findings: list[Finding] = []
    logical_lines = _join_multiline(content)
    service_name = posixpath.basename(file_path)

    for line_num, line in logical_lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue

        tokens = line_clean.split()
        if not tokens:
            continue

        first_tok = tokens[0]
        if first_tok.startswith("@"):
            # @include or @substack directive
            continue

        module_type = first_tok.lstrip("-").lower()
        if module_type not in ("auth", "account", "session", "password"):
            continue

        if len(tokens) < 3:
            continue

        # Parse control field, handling possible bracket syntax like [default=bad ...]
        idx = 1
        control_tokens: list[str] = []
        if tokens[idx].startswith("["):
            while idx < len(tokens):
                control_tokens.append(tokens[idx])
                if tokens[idx].endswith("]"):
                    idx += 1
                    break
                idx += 1
            control = " ".join(control_tokens)
        else:
            control = tokens[idx]
            idx += 1

        if idx >= len(tokens):
            continue

        module_path = tokens[idx]
        module_args = tokens[idx + 1 :]

        pam_flags: list[str] = []
        target_binary_path: str | None = None
        module_base = posixpath.basename(module_path)

        # Check pam_exec.so hook
        if module_base == "pam_exec.so" or module_path.endswith("pam_exec.so"):
            pam_flags.append("PAM_EXEC_HOOK")

        # Check pam_permit.so in auth or account stacks (authentication bypass)
        if (
            module_base == "pam_permit.so" or module_path.endswith("pam_permit.so")
        ) and module_type in ("auth", "account"):
            pam_flags.append("PAM_PERMIT_AUTH_BYPASS")

        # Inspect module path and arguments for suspicious paths
        candidate_paths = [module_path] + [
            arg for arg in module_args if arg.startswith(("/", "~", "."))
        ]

        for p in candidate_paths:
            clean_p = p.strip("\"'")
            if _is_user_home(clean_p):
                if "SYSTEM_PAM_POINTS_TO_USER_HOME" not in pam_flags:
                    pam_flags.extend(
                        ["SYSTEM_PAM_POINTS_TO_USER_HOME", "NON_ROOT_USER_PATH"]
                    )
                if target_binary_path is None:
                    target_binary_path = clean_p
            elif _is_tmp_or_dev_shm(clean_p):
                if "EXEC_FROM_TMP_OR_DEV_SHM" not in pam_flags:
                    pam_flags.append("EXEC_FROM_TMP_OR_DEV_SHM")
                if target_binary_path is None:
                    target_binary_path = clean_p

            if _is_hidden_path(clean_p):
                if "HIDDEN_PATH_EXECUTION" not in pam_flags:
                    pam_flags.append("HIDDEN_PATH_EXECUTION")
                if target_binary_path is None:
                    target_binary_path = clean_p

        if pam_flags:
            if (
                "PAM_PERMIT_AUTH_BYPASS" in pam_flags
                or "SYSTEM_PAM_POINTS_TO_USER_HOME" in pam_flags
                or "EXEC_FROM_TMP_OR_DEV_SHM" in pam_flags
            ):
                risk = RiskLevel.CRITICAL
            elif "PAM_EXEC_HOOK" in pam_flags or "HIDDEN_PATH_EXECUTION" in pam_flags:
                risk = RiskLevel.HIGH
            else:
                risk = RiskLevel.MEDIUM

            details: dict[str, Any] = {
                "flags": pam_flags,
                "line_number": line_num,
                "module_type": module_type,
                "control": control,
                "module_path": module_path,
                "module_args": module_args,
                "service": service_name,
                "system_config_path": file_path,
            }
            if target_binary_path:
                details["target_binary_path"] = target_binary_path

            finding = Finding(
                category=PAM_CATEGORY,
                risk_level=risk,
                technique_id=PAM_TECHNIQUE_ID,
                path=file_path,
                details=details,
                raw_content=line,
            )
            findings.append(finding)

    return findings


def analyze_pam_sudoers(target: AnalysisTarget) -> list[Finding]:
    """Analyze sudoers and PAM configurations for privilege persistence vectors.

    Args:
        target: The AnalysisTarget containing filesystem context or virtual files.

    Returns:
        A list of Finding objects representing detected persistence mechanisms.
    """
    findings: list[Finding] = []

    # 1. Discover sudoers files
    sudoers_files: set[str] = set()
    if target.exists("/etc/sudoers"):
        sudoers_files.add("/etc/sudoers")
    for p in target.glob("/etc/sudoers*"):
        if p == "/etc/sudoers.d" or p.endswith("/"):
            continue
        sudoers_files.add(p)
    for p in target.glob("/etc/sudoers.d/*"):
        if p.endswith("/"):
            continue
        sudoers_files.add(p)
    for vp in target.virtual_paths:
        if "sudoers" in vp.lower():
            sudoers_files.add(vp)

    for sf in sorted(sudoers_files):
        findings.extend(_parse_sudoers_file(target, sf))

    # 2. Discover PAM files
    pam_files: set[str] = set()
    for p in target.glob("/etc/pam.d/*"):
        if p.endswith("/"):
            continue
        pam_files.add(p)
    for vp in target.virtual_paths:
        if "/pam.d/" in vp or vp.startswith("pam.d/"):
            pam_files.add(vp)

    for pf in sorted(pam_files):
        findings.extend(_parse_pam_file(target, pf))

    return findings


class LinuxPamSudoersParser:
    """Parser class for Linux sudoers configuration and PAM authentication modules."""

    def __init__(self, target: AnalysisTarget | None = None) -> None:
        """Initialize parser with optional target.

        Args:
            target: Optional AnalysisTarget to associate with this parser instance.
        """
        self.target: AnalysisTarget | None = target

    def parse(self, target: AnalysisTarget | None = None) -> list[Finding]:
        """Parse sudoers and PAM files.

        Supports both instance call LinuxPamSudoersParser(target).parse()
        and class call LinuxPamSudoersParser.parse(target).

        Args:
            target: Optional target override to analyze.

        Returns:
            List of detected findings.

        Raises:
            ValueError: If no AnalysisTarget is provided and self.target is None.
        """
        if isinstance(self, AnalysisTarget):
            return analyze_pam_sudoers(self)
        active_target = target if target is not None else self.target
        if active_target is None:
            raise ValueError("AnalysisTarget must be provided to parse")
        return analyze_pam_sudoers(active_target)

    @classmethod
    def parse_target(cls, target: AnalysisTarget) -> list[Finding]:
        """Classmethod helper to parse an AnalysisTarget directly.

        Args:
            target: AnalysisTarget instance to parse.

        Returns:
            List of detected findings.
        """
        return cls(target).parse()


__all__ = [
    "PAM_CATEGORY",
    "PAM_TECHNIQUE_ID",
    "SUDOERS_CATEGORY",
    "SUDOERS_TECHNIQUE_ID",
    "LinuxPamSudoersParser",
    "analyze_pam_sudoers",
]
