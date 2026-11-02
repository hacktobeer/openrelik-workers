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
"""Linux Shell Profile & RC Injection Scanner (T1546.004).

Scans system-wide and user shell profile scripts for backdoor injections,
obfuscated base64 payloads, reverse shells, prompt command tampering,
suspicious aliases, download cradles, and cross-boundary execution hooks.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any

from src.utils.models import AnalysisTarget, Finding, RiskLevel, normalize_virtual_path

# Target profile paths and globs
SYSTEM_PROFILE_PATHS: list[str] = [
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/zsh/zshrc",
]

SYSTEM_PROFILE_GLOBS: list[str] = [
    "/etc/profile.d/*",
    "/etc/zsh/*",
]

ROOT_PROFILE_PATHS: list[str] = [
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.profile",
    "/root/.zshrc",
    "/root/.bash_logout",
]

USER_PROFILE_GLOBS: list[str] = [
    "/home/*/.bashrc",
    "/home/*/.bash_profile",
    "/home/*/.profile",
    "/home/*/.zshrc",
    "/home/*/.bash_logout",
]

# Standard benign dotfiles that are commonly sourced in profiles
ALLOWED_SOURCED_DOTFILES: set[str] = {
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".bash_aliases",
    ".bash_login",
    ".bash_logout",
    ".bash_completion",
    ".dircolors",
    ".bash_history",
}

# Regex patterns for detection
PROMPT_COMMAND_RE = re.compile(
    r"""(?:\bexport\s+)?\bPROMPT_COMMAND\s*[\+]?=""",
)

REVERSE_SHELL_DEV_TCP_RE = re.compile(
    r"""/dev/(?:tcp|udp)/\S+""",
)

REVERSE_SHELL_BASH_I_RE = re.compile(
    r"""\b(?:bash|sh|zsh)\s+-i\b""",
)

REVERSE_SHELL_NC_RE = re.compile(
    r"""\b(?:nc|netcat|nc\.traditional)\s+.*-(?:e|c)\s+\S+""",
)

REVERSE_SHELL_NCAT_RE = re.compile(
    r"""\bncat\b.*(?:--exec|-e|-c|--sh-exec)\b""",
)

REVERSE_SHELL_SOCAT_RE = re.compile(
    r"""\bsocat\b.*(?:exec|pty|system):""",
    re.IGNORECASE,
)

REVERSE_SHELL_MKFIFO_RE = re.compile(
    r"""\bmkfifo\b""",
)

REVERSE_SHELL_SOCKET_RE = re.compile(
    r"""python\d*\s+-c\s+.*(?:import\s+socket|socket\.socket)"""
    r"""|perl\s+.*Socket.*connect"""
    r"""|ruby\s+.*TCPSocket"""
    r"""|php\s+-r\s+.*fsockopen""",
    re.IGNORECASE,
)

DOWNLOAD_PIPE_RE = re.compile(
    r"""\b(?:curl|wget|fetch|lynx)\b.*\|\s*(?:(?:/bin/)?(?:ba|z|da)?sh|python\d*|perl)""",
    re.IGNORECASE,
)

DOWNLOAD_EXEC_RE = re.compile(
    r"""\b(?:curl|wget)\b.*(?:&&|;)\s*(?:chmod\s+\+x\s+)?(?:\./|/(?:tmp|var/tmp|dev/shm)/)"""
    r"""|\b(?:curl\s+.*-[oO]\s+|wget\s+.*-[oO]\s+)(\S+)\s*(?:&&|;)\s*(?:chmod\s+\+x\s+\1\s*(?:&&|;)\s*)?(?:\1|\./\1)""",
    re.IGNORECASE,
)

TMP_EXEC_RE = re.compile(
    r"""(?:^|;|&&|\|\||\||\b(?:bash|sh|zsh|dash|python\d*|perl|ruby|exec|nohup|source|\.|(?:export\s+)?LD_PRELOAD\s*=)\s*)['"]?(/(?:tmp|var/tmp|dev/shm|run/shm)/[^\s'";]+)""",
    re.IGNORECASE,
)

CD_TMP_RE = re.compile(
    r"""cd\s+/(?:tmp|var/tmp|dev/shm|run/shm)\s*(?:&&|;)\s*(?:\./|[^\s'";]+)""",
    re.IGNORECASE,
)

SUSPICIOUS_ALIAS_RE = re.compile(
    r"""\balias\s+(?:sudo|ssh|su|passwd|scp|sftp|pkexec)\s*=""",
)

SUSPICIOUS_FUNCTION_RE = re.compile(
    r"""(?:^|\s)(?:function\s+)?(?:sudo|ssh|su|passwd|pkexec)\s*\(\)\s*\{"""
    r"""|\bfunction\s+(?:sudo|ssh|su|passwd|pkexec)\b""",
)

LD_PRELOAD_RE = re.compile(
    r"""(?:\bexport\s+)?\bLD_PRELOAD\s*=""",
)

SYSTEM_POINTS_TO_HOME_RE = re.compile(
    r"""(?:^|;|&&|\|\||\||\b(?:source|\.|bash|sh|zsh|dash|python\d*|perl|ruby|exec|nohup)\s+)['"]?(/home/[a-zA-Z0-9_.-]+/[^\s'";]+)""",
    re.IGNORECASE,
)

BASE64_DECODE_CMD_RE = re.compile(
    r"""\bbase64\s+(?:-[a-zA-Z]*[dD][a-zA-Z]*|--decode)\b"""
    r"""|\bopenssl\s+enc\s+.*-(?:d|base64).*-base64""",
    re.IGNORECASE,
)

OBFUSCATED_HEX_OCTAL_RE = re.compile(
    r"""eval\s+.*(?:\\[xX][0-9a-fA-F]{2}|\\[0-7]{3})"""
    r"""|(?:\\[xX][0-9a-fA-F]{2}){4,}"""
    r"""|\$(?:IFS|\{[0-9a-zA-Z_#]+:[0-9]+:[0-9]+\}).*(?:bash|sh|exec)""",
    re.IGNORECASE,
)


def _try_b64decode(s: str) -> str | None:
    """Attempt to decode a base64 string and return clean text if valid.

    Args:
        s: Candidate base64 string.

    Returns:
        Decoded text string if valid and printable, or None.
    """
    clean = s.strip().strip("'\"")
    if not clean or len(clean) < 4:
        return None
    missing_padding = len(clean) % 4
    if missing_padding:
        clean += "=" * (4 - missing_padding)
    try:
        decoded_bytes = base64.b64decode(clean)
        text = decoded_bytes.decode("utf-8", errors="replace")
        if text and any(c.isprintable() for c in text):
            return text
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return None


def extract_and_decode_base64(line: str) -> str | None:
    """Extract and decode base64 payload from an execution pipeline.

    Args:
        line: Command line or script line to search.

    Returns:
        Decoded text string if valid base64 payload is found, or None.
    """
    # 1. Direct pipe: echo '...' | base64 -d
    m = re.search(
        r"""(?:echo|printf)\s+(?:-[a-zA-Z]+\s+)?['"]?([A-Za-z0-9+/=]{4,})['"]?\s*\|\s*(?:base64|openssl)""",
        line,
        re.IGNORECASE,
    )
    if m:
        decoded = _try_b64decode(m.group(1))
        if decoded:
            return decoded

    # 2. Heredoc: base64 -d <<< '...'
    m = re.search(
        r"""base64\s+(?:-[a-zA-Z]*[dD][a-zA-Z]*|--decode)\s*<<<\s*['"]?([A-Za-z0-9+/=]{4,})['"]?""",
        line,
        re.IGNORECASE,
    )
    if m:
        decoded = _try_b64decode(m.group(1))
        if decoded:
            return decoded

    # 3. Quoted tokens in line
    for match in re.finditer(r"""['"]([A-Za-z0-9+/=]{8,})['"]""", line):
        decoded = _try_b64decode(match.group(1))
        if decoded:
            return decoded

    # 4. Unquoted tokens in line
    for match in re.finditer(r"""\b([A-Za-z0-9+/=]{8,})\b""", line):
        decoded = _try_b64decode(match.group(1))
        if decoded:
            return decoded

    return None


def is_hidden_path_execution(line: str) -> bool:
    """Detect if the command executes a hidden binary or a file within a hidden directory.

    Args:
        line: Command line string to test.

    Returns:
        True if the line executes from a hidden file or directory, False otherwise.
    """
    pattern = re.compile(
        r"""(?:^|;|&&|\|\||\||\b(?:bash|sh|zsh|dash|python\d*|perl|ruby|exec|nohup|source|\.)\s+)['"]?([~./][^\s'";]*|/[^\s'";]+)""",
        re.IGNORECASE,
    )
    for m in pattern.finditer(line):
        token = m.group(1).strip()
        if token in (".", "..", "/"):
            continue
        parts = [p for p in token.replace("\\", "/").split("/") if p and p != "."]
        for idx, part in enumerate(parts):
            if part.startswith(".") and part != "..":
                # Sourcing known standard dotfiles (e.g. .bashrc, .bash_aliases) is normal
                if idx == len(parts) - 1 and part in ALLOWED_SOURCED_DOTFILES:
                    continue
                return True
    return False


def extract_user_from_path(virtual_path: str) -> str:
    """Extract the associated username from the virtual path of a profile file.

    Args:
        virtual_path: Virtual path of the profile file.

    Returns:
        Username string owning the profile (e.g. 'root', or user name from /home/<user>/).
    """
    parts = virtual_path.strip("/").split("/")
    if len(parts) >= 2 and parts[0] == "home":
        return parts[1]
    if parts and parts[0] == "root":
        return "root"
    if parts and parts[0] == "etc":
        return "root"
    return "root"


def is_system_profile_path(virtual_path: str) -> bool:
    """Check if the given path represents a global/system-wide shell profile.

    Args:
        virtual_path: Virtual path of the file.

    Returns:
        True if the path is a global shell profile, False otherwise.
    """
    norm = normalize_virtual_path(virtual_path)
    return norm.startswith(("/etc/profile", "/etc/zsh/")) or norm in (
        "/etc/bash.bashrc",
        "/etc/bashrc",
    )


def analyze_shell_profiles(target: AnalysisTarget) -> list[Finding]:
    """Scan system-wide and user shell profiles for persistence artifacts and injection hooks.

    Args:
        target: Target AnalysisTarget providing filesystem access.

    Returns:
        List of Finding instances representing detected persistence mechanisms.
    """
    candidate_paths: list[str] = []

    # 1. Exact paths
    for p in SYSTEM_PROFILE_PATHS + ROOT_PROFILE_PATHS:
        if target.exists(p):
            candidate_paths.append(normalize_virtual_path(p))

    # 2. Glob matches
    for g in SYSTEM_PROFILE_GLOBS + USER_PROFILE_GLOBS:
        matched = target.glob(g)
        for m in matched:
            candidate_paths.append(normalize_virtual_path(m))

    # Deduplicate while preserving order
    seen_paths: set[str] = set()
    unique_paths: list[str] = []
    for p in candidate_paths:
        if p not in seen_paths:
            seen_paths.add(p)
            unique_paths.append(p)

    findings: list[Finding] = []

    for vpath in unique_paths:
        content = target.read_text(vpath)
        if content is None:
            continue

        user = extract_user_from_path(vpath)
        is_system = is_system_profile_path(vpath)

        for line_num, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            # Ignore empty lines and pure comments
            if not line or line.startswith("#"):
                continue

            flags: list[str] = []
            decoded_payload: str | None = None

            # 1. Base64 execution pipelines
            if BASE64_DECODE_CMD_RE.search(line):
                decoded_payload = extract_and_decode_base64(line)
                flags.append("OBFUSCATED_COMMAND")
                flags.append("BASE64_PAYLOAD")
            elif OBFUSCATED_HEX_OCTAL_RE.search(line):
                flags.append("OBFUSCATED_COMMAND")

            # 2. PROMPT_COMMAND tampering
            if PROMPT_COMMAND_RE.search(line):
                flags.append("PROMPT_COMMAND_HOOK")

            # 3. Reverse shell patterns
            if (
                REVERSE_SHELL_DEV_TCP_RE.search(line)
                or REVERSE_SHELL_BASH_I_RE.search(line)
                or REVERSE_SHELL_NC_RE.search(line)
                or REVERSE_SHELL_NCAT_RE.search(line)
                or REVERSE_SHELL_SOCAT_RE.search(line)
                or REVERSE_SHELL_MKFIFO_RE.search(line)
                or REVERSE_SHELL_SOCKET_RE.search(line)
            ):
                flags.append("REVERSE_SHELL_PATTERN")

            # 4. Download cradles
            if DOWNLOAD_PIPE_RE.search(line) or DOWNLOAD_EXEC_RE.search(line):
                flags.append("DOWNLOAD_CRADLE")

            # 5. Execution from /tmp or /dev/shm
            if TMP_EXEC_RE.search(line) or CD_TMP_RE.search(line):
                flags.append("EXEC_FROM_TMP_OR_DEV_SHM")

            # 6. Hidden path execution
            if is_hidden_path_execution(line):
                flags.append("HIDDEN_PATH_EXECUTION")

            # 7. Suspicious alias or function / LD_PRELOAD
            if (
                SUSPICIOUS_ALIAS_RE.search(line)
                or SUSPICIOUS_FUNCTION_RE.search(line)
                or LD_PRELOAD_RE.search(line)
            ):
                flags.append("SUSPICIOUS_ALIAS_OR_FUNCTION")

            # 8. System profile pointing to user home directory
            if is_system and SYSTEM_POINTS_TO_HOME_RE.search(line):
                flags.append("SYSTEM_PROFILE_POINTS_TO_USER_HOME")

            if not flags:
                continue

            # Deduplicate flags preserving order
            unique_flags: list[str] = []
            seen_f: set[str] = set()
            for f in flags:
                if f not in seen_f:
                    seen_f.add(f)
                    unique_flags.append(f)

            # Determine risk level
            if any(
                f in unique_flags
                for f in ("REVERSE_SHELL_PATTERN", "SYSTEM_PROFILE_POINTS_TO_USER_HOME")
            ):
                risk_level = RiskLevel.CRITICAL
            elif any(
                f in unique_flags
                for f in (
                    "BASE64_PAYLOAD",
                    "OBFUSCATED_COMMAND",
                    "PROMPT_COMMAND_HOOK",
                    "DOWNLOAD_CRADLE",
                    "EXEC_FROM_TMP_OR_DEV_SHM",
                    "HIDDEN_PATH_EXECUTION",
                    "SUSPICIOUS_ALIAS_OR_FUNCTION",
                )
            ):
                risk_level = RiskLevel.HIGH
            else:
                risk_level = RiskLevel.MEDIUM

            details: dict[str, Any] = {
                "user": user,
                "line_number": line_num,
                "flags": unique_flags,
            }

            finding = Finding(
                category="shell_rc_injection",
                risk_level=risk_level,
                technique_id="T1546.004",
                path=vpath,
                details=details,
                raw_content=line,
                decoded_payload=decoded_payload,
            )
            findings.append(finding)

    return findings


class LinuxShellProfilesParser:
    """Parser class for Linux shell profiles and startup hooks (T1546.004)."""

    @staticmethod
    def parse(target: AnalysisTarget) -> list[Finding]:
        """Parse shell profile persistence vectors.

        Args:
            target: The AnalysisTarget to inspect.

        Returns:
            List of detected persistence findings.
        """
        return analyze_shell_profiles(target)


__all__ = [
    "ALLOWED_SOURCED_DOTFILES",
    "LinuxShellProfilesParser",
    "analyze_shell_profiles",
    "extract_and_decode_base64",
    "extract_user_from_path",
    "is_hidden_path_execution",
    "is_system_profile_path",
]
