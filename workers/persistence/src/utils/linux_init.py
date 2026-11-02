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
"""Linux Init & Startup Scripts (rc.local, init.d, rc[0-6].d) Parser submodule."""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
from typing import Any

from src.utils.models import AnalysisTarget, Finding, RiskLevel

# Target paths for rc.local execution
RC_LOCAL_PATHS: list[str] = [
    "/etc/rc.local",
    "/etc/rc.d/rc.local",
]

# Runlevel directories to inspect for SysV symlinks and scripts
RC_DIR_PATTERNS: list[str] = (
    [f"/etc/rc{i}.d/*" for i in range(7)]
    + ["/etc/rcS.d/*"]
    + [f"/etc/rc.d/rc{i}.d/*" for i in range(7)]
    + ["/etc/rc.d/rcS.d/*"]
)

# Standard SysV init.d script directories
INIT_DIR_PATTERNS: list[str] = [
    "/etc/init.d/*",
    "/etc/rc.d/init.d/*",
]

# Regex to detect execution out of user home directories: /home/<user>/*
USER_HOME_RE: re.Pattern[str] = re.compile(
    r"(?:^|[\s\"'=])(/home/[a-zA-Z0-9._-]+/[^\s\"';`]+)"
)

# Regex to detect execution out of temporary or shared memory locations
TMP_PATH_RE: re.Pattern[str] = re.compile(
    r"(?:^|[\s\"'=])(/(?:tmp|var/tmp|dev/shm|run/shm)/[^\s\"';`]+)"
)

# Regex to detect execution of hidden paths or files
HIDDEN_PATH_RE: re.Pattern[str] = re.compile(
    r"(?:^|[\s\"'=])(?:/(?:[^\s\"';`]+/)*|(?:\./)?)\.[a-zA-Z0-9_-]+[^\s\"';`]*"
)

# Reverse shell command patterns
REVERSE_SHELL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/dev/(?:tcp|udp)/\S+"),
    re.compile(r"\b(?:bash|sh|zsh)\s+-i\s+>&"),
    re.compile(r">&/dev/(?:tcp|udp)/"),
    re.compile(r"exec\s+\d*<>/dev/(?:tcp|udp)/"),
    re.compile(r"\b(?:nc|netcat|ncat)\b.*(?:\s-[ec]\s|\s/bin/(?:ba)?sh\b)"),
    re.compile(r"\bmkfifo\s+\S+.*(?:nc|netcat|ncat|cat|sh|bash)\b"),
    re.compile(r"python(?:\d+)?\s+-c\s+.*(?:socket.*connect|pty\.spawn)"),
    re.compile(r"perl\s+-e\s+.*socket.*connect"),
    re.compile(r"ruby\s+-e\s+.*socket.*connect"),
    re.compile(r"php\s+-r\s+.*socket.*connect"),
    re.compile(r"socat\s+exec:.*tcp:"),
    re.compile(r"\bmkfifo\b.*\b(?:nc|netcat|ncat)\b"),
]

# Download cradle execution patterns (curl/wget/fetch piped to shell or python)
DOWNLOAD_CRADLE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bcurl\b.*\|\s*(?:ba)?sh\b"),
    re.compile(r"\bwget\b.*\|\s*(?:ba)?sh\b"),
    re.compile(r"\bfetch\b.*\|\s*(?:ba)?sh\b"),
    re.compile(r"\bcurl\b.*\|\s*python"),
    re.compile(r"\bwget\b.*\|\s*python"),
    re.compile(r"\bcurl\s+.*-[oO]\s+\S+\s*(?:&&|;)\s*(?:bash|sh|chmod\s+\+x)"),
    re.compile(r"\bwget\s+.*-[oO]\s+\S+\s*(?:&&|;)\s*(?:bash|sh|chmod\s+\+x)"),
]

# Base64 pipe or command patterns
B64_PIPE_RE: re.Pattern[str] = re.compile(
    r"""(?:echo\s+['"]?([A-Za-z0-9+/=]{4,})['"]?\s*\|\s*(?:base64\s+(?:-d|--decode)|openssl\s+enc\s+-d\s+-base64))"""
    r"""|(?:base64\s+(?:-d|--decode)\s+<<<['"]?([A-Za-z0-9+/=]{4,})['"]?)"""
    r"""|(?:base64\s+(?:-d|--decode))""",
    re.IGNORECASE,
)

STANDALONE_B64_RE: re.Pattern[str] = re.compile(
    r"""['"]?([A-Za-z0-9+/=]{4,})['"]?\s*\|\s*(?:base64|openssl)"""
)

# Regex matching clean script termination lines in rc.local
EXIT_ZERO_RE: re.Pattern[str] = re.compile(r"^exit(\s+0)?\s*;?$", re.IGNORECASE)


def extract_base64_payload(text: str) -> tuple[bool, str | None]:
    """Detect and decode base64 encoded strings in commands.

    Args:
        text: Shell command or script content line.

    Returns:
        Tuple of (is_base64_detected, decoded_string_or_none).
    """
    match = B64_PIPE_RE.search(text)
    if not match:
        return False, None

    b64_candidate = match.group(1) or match.group(2)
    if not b64_candidate:
        m_standalone = STANDALONE_B64_RE.search(text)
        if m_standalone:
            b64_candidate = m_standalone.group(1)
        else:
            tokens = re.findall(r"[A-Za-z0-9+/=]{4,}", text)
            for token in tokens:
                if token.lower() in ("base64", "openssl", "decode", "echo"):
                    continue
                b64_candidate = token
                break

    if not b64_candidate:
        return True, None

    clean_b64 = b64_candidate.strip("'\"")
    pad_needed = len(clean_b64) % 4
    if pad_needed:
        clean_b64 += "=" * (4 - pad_needed)

    try:
        raw_bytes = base64.b64decode(clean_b64)
        decoded = raw_bytes.decode("utf-8", errors="replace")
        return True, decoded
    except (binascii.Error, ValueError):
        return True, None


def extract_active_rc_commands(content: str) -> list[str]:
    """Extract active (non-comment, non-exit 0) commands from rc.local.

    Args:
        content: Raw text content of rc.local script.

    Returns:
        List of active shell command lines executed on boot.
    """
    active_commands: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if EXIT_ZERO_RE.match(stripped):
            continue
        active_commands.append(stripped)
    return active_commands


def inspect_command_indicators(
    lines: list[str],
) -> tuple[list[str], str | None, list[str]]:
    """Scan shell lines for persistence and malicious execution indicators.

    Args:
        lines: Active command lines from startup script.

    Returns:
        Tuple of (flags, decoded_payload, suspicious_lines).
    """
    flags: list[str] = []
    suspicious_lines: list[str] = []
    decoded_payload: str | None = None

    for line in lines:
        matched = False

        if any(p.search(line) for p in REVERSE_SHELL_PATTERNS):
            flags.append("REVERSE_SHELL_PATTERN")
            matched = True

        if USER_HOME_RE.search(line):
            flags.append("SYSTEM_INIT_POINTS_TO_USER_HOME")
            matched = True

        if TMP_PATH_RE.search(line):
            flags.append("EXEC_FROM_TMP_OR_DEV_SHM")
            matched = True

        if HIDDEN_PATH_RE.search(line):
            flags.append("HIDDEN_PATH_EXECUTION")
            matched = True

        if any(p.search(line) for p in DOWNLOAD_CRADLE_PATTERNS):
            flags.append("DOWNLOAD_CRADLE")
            matched = True

        has_b64, dec = extract_base64_payload(line)
        if has_b64:
            flags.append("BASE64_PAYLOAD")
            matched = True
            if dec and decoded_payload is None:
                decoded_payload = dec
                if any(p.search(dec) for p in REVERSE_SHELL_PATTERNS):
                    flags.append("REVERSE_SHELL_PATTERN")
                if any(p.search(dec) for p in DOWNLOAD_CRADLE_PATTERNS):
                    flags.append("DOWNLOAD_CRADLE")
                if USER_HOME_RE.search(dec):
                    flags.append("SYSTEM_INIT_POINTS_TO_USER_HOME")
                if TMP_PATH_RE.search(dec):
                    flags.append("EXEC_FROM_TMP_OR_DEV_SHM")

        if matched:
            suspicious_lines.append(line)

    unique_flags = list(dict.fromkeys(flags))
    return unique_flags, decoded_payload, suspicious_lines


def determine_risk_level(flags: list[str], is_rc_local: bool = False) -> RiskLevel:
    """Determine risk level based on aggregated indicator flags.

    Args:
        flags: List of identified forensic flags.
        is_rc_local: Whether the finding originates from rc.local.

    Returns:
        Assigned RiskLevel enum value.
    """
    if "REVERSE_SHELL_PATTERN" in flags or "SYSTEM_INIT_POINTS_TO_USER_HOME" in flags:
        return RiskLevel.CRITICAL
    if any(
        f in flags
        for f in (
            "EXEC_FROM_TMP_OR_DEV_SHM",
            "BASE64_PAYLOAD",
            "DOWNLOAD_CRADLE",
            "HIDDEN_PATH_EXECUTION",
        )
    ):
        return RiskLevel.HIGH
    if is_rc_local and "RC_LOCAL_ACTIVE_COMMANDS" in flags:
        return RiskLevel.MEDIUM
    if "SUSPICIOUS_INIT_SCRIPT" in flags:
        return RiskLevel.MEDIUM
    return RiskLevel.INFO


class LinuxInitParser:
    """Parser for Linux init and startup scripts (rc.local, SysV init.d, rc*.d)."""

    def parse(self, target: AnalysisTarget) -> list[Finding]:
        """Parse startup scripts and symlinks on target filesystem.

        Args:
            target: AnalysisTarget representation of disk image or extracted files.

        Returns:
            List of identified persistence findings.
        """
        findings: list[Finding] = []
        seen_rc_paths: set[str] = set()

        # 1. Parse /etc/rc.local and /etc/rc.d/rc.local
        for rc_path in RC_LOCAL_PATHS:
            if not target.exists(rc_path):
                continue

            resolved_link = target.resolve_symlink(rc_path)
            canonical = resolved_link if resolved_link else rc_path
            if canonical in seen_rc_paths:
                continue
            seen_rc_paths.add(canonical)
            seen_rc_paths.add(rc_path)

            raw_content = target.read_text(rc_path)
            if not raw_content:
                continue

            active_cmds = extract_active_rc_commands(raw_content)
            if not active_cmds:
                continue

            flags = ["RC_LOCAL_ACTIVE_COMMANDS"]
            content_flags, dec, sus_lines = inspect_command_indicators(active_cmds)
            flags.extend(content_flags)
            unique_flags = list(dict.fromkeys(flags))

            risk = determine_risk_level(unique_flags, is_rc_local=True)
            details: dict[str, Any] = {
                "flags": unique_flags,
                "active_commands": active_cmds,
            }
            if sus_lines:
                details["suspicious_lines"] = sus_lines

            findings.append(
                Finding(
                    category="rc_local_script",
                    risk_level=risk,
                    technique_id="T1037.004",
                    path=rc_path,
                    details=details,
                    raw_content=raw_content,
                    decoded_payload=dec,
                )
            )

        # 2. Check /etc/rc[0-6].d/* and /etc/rcS.d/* symlinks and scripts
        seen_rc_symlinks: set[str] = set()
        for pat in RC_DIR_PATTERNS:
            for entry_path in target.glob(pat):
                if entry_path in seen_rc_symlinks:
                    continue
                seen_rc_symlinks.add(entry_path)

                symlink_dest = target.resolve_symlink(entry_path)
                runlevel = posixpath.basename(posixpath.dirname(entry_path))

                if symlink_dest is not None:
                    # Entry is a valid symlink
                    sym_flags: list[str] = []
                    if symlink_dest.startswith("/home/"):
                        sym_flags.append("SYSTEM_INIT_POINTS_TO_USER_HOME")
                    elif symlink_dest.startswith(
                        ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")
                    ):
                        sym_flags.append("EXEC_FROM_TMP_OR_DEV_SHM")
                    elif HIDDEN_PATH_RE.search(symlink_dest):
                        sym_flags.append("HIDDEN_PATH_EXECUTION")

                    if sym_flags:
                        raw_content = target.read_text(entry_path) or target.read_text(
                            symlink_dest
                        )
                        dec_payload: str | None = None
                        sus_lines: list[str] = []

                        if raw_content:
                            active_lines = [
                                line.strip()
                                for line in raw_content.splitlines()
                                if line.strip() and not line.strip().startswith("#")
                            ]
                            c_flags, dec_payload, sus_lines = (
                                inspect_command_indicators(active_lines)
                            )
                            sym_flags.extend(c_flags)

                        unique_flags = list(dict.fromkeys(sym_flags))
                        risk = determine_risk_level(unique_flags)
                        details_dict: dict[str, Any] = {
                            "flags": unique_flags,
                            "symlink_target": symlink_dest,
                            "runlevel": runlevel,
                        }
                        if sus_lines:
                            details_dict["suspicious_lines"] = sus_lines

                        findings.append(
                            Finding(
                                category="sysv_init_script",
                                risk_level=risk,
                                technique_id="T1037.004",
                                path=entry_path,
                                details=details_dict,
                                raw_content=raw_content,
                                decoded_payload=dec_payload,
                            )
                        )
                else:
                    # Regular script placed directly in rc*.d
                    raw_content = target.read_text(entry_path)
                    if not raw_content:
                        continue

                    active_lines = [
                        line.strip()
                        for line in raw_content.splitlines()
                        if line.strip() and not line.strip().startswith("#")
                    ]
                    c_flags, dec_payload, sus_lines = inspect_command_indicators(
                        active_lines
                    )
                    if c_flags:
                        c_flags.append("SUSPICIOUS_INIT_SCRIPT")
                        unique_flags = list(dict.fromkeys(c_flags))
                        risk = determine_risk_level(unique_flags)
                        findings.append(
                            Finding(
                                category="sysv_init_script",
                                risk_level=risk,
                                technique_id="T1037.004",
                                path=entry_path,
                                details={
                                    "flags": unique_flags,
                                    "suspicious_lines": sus_lines,
                                    "runlevel": runlevel,
                                    "script_name": posixpath.basename(entry_path),
                                },
                                raw_content=raw_content,
                                decoded_payload=dec_payload,
                            )
                        )

        # 3. Check /etc/init.d/* scripts
        seen_init_paths: set[str] = set()
        for pat in INIT_DIR_PATTERNS:
            for init_path in target.glob(pat):
                if init_path in seen_init_paths:
                    continue
                seen_init_paths.add(init_path)

                raw_content = target.read_text(init_path)
                if not raw_content:
                    continue

                active_lines = [
                    line.strip()
                    for line in raw_content.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
                c_flags, dec_payload, sus_lines = inspect_command_indicators(
                    active_lines
                )
                if c_flags:
                    c_flags.append("SUSPICIOUS_INIT_SCRIPT")
                    unique_flags = list(dict.fromkeys(c_flags))
                    risk = determine_risk_level(unique_flags)
                    findings.append(
                        Finding(
                            category="sysv_init_script",
                            risk_level=risk,
                            technique_id="T1037.004",
                            path=init_path,
                            details={
                                "flags": unique_flags,
                                "suspicious_lines": sus_lines,
                                "script_name": posixpath.basename(init_path),
                            },
                            raw_content=raw_content,
                            decoded_payload=dec_payload,
                        )
                    )

        return findings


def analyze_init(target: AnalysisTarget) -> list[Finding]:
    """Exposed entrypoint to analyze Linux init and startup scripts.

    Args:
        target: AnalysisTarget representation.

    Returns:
        List of persistence findings.
    """
    return LinuxInitParser().parse(target)


__all__ = [
    "LinuxInitParser",
    "analyze_init",
    "determine_risk_level",
    "extract_active_rc_commands",
    "extract_base64_payload",
    "inspect_command_indicators",
]
