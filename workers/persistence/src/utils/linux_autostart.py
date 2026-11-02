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
"""Linux XDG Desktop Autostart (*.desktop) parser and security analyzer."""

from __future__ import annotations

import base64
import binascii
import re
import shlex
from typing import Any

from src.utils.models import (
    AnalysisTarget,
    Finding,
    RiskLevel,
    normalize_virtual_path,
)

AUTOSTART_GLOBS: list[str] = [
    "/etc/xdg/autostart/*.desktop",
    "/home/*/.config/autostart/*.desktop",
    "/root/.config/autostart/*.desktop",
]

# Reverse shell signatures
REVERSE_SHELL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/dev/(?:tcp|udp)/\d{1,3}(?:\.\d{1,3}){3}/\d+"),
    re.compile(r"/dev/(?:tcp|udp)/[a-zA-Z0-9.-]+/\d+"),
    re.compile(r"\bmkfifo\s+.*(?:nc|sh|bash)"),
    re.compile(r"\bnc(?:\.traditional)?\s+.*-e\s+(?:/bin/)?(?:ba)?sh"),
    re.compile(r"\bncat\s+.*-e\s+(?:/bin/)?(?:ba)?sh"),
    re.compile(r"\bsocat\s+.*exec:.*tcp:"),
    re.compile(
        r"python(?:\d)?\s+-c\s+.*import\s+(?:socket|pty|subprocess).*(?:connect|spawn)"
    ),
    re.compile(r"perl\s+-e\s+.*use\s+Socket"),
    re.compile(r"bash\s+-i\s+>&"),
    re.compile(r"exec\s+\d+<>/dev/(?:tcp|udp)"),
]

# Download cradle signatures
DOWNLOAD_CRADLE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:curl|wget|fetch)\s+[^|;]+?\|\s*(?:(?:/bin/)?(?:ba|z|da|k)?sh)"),
    re.compile(r"(?:curl|wget)\s+.*https?://.*(?:\.sh|\.py|\.bin|\.elf)"),
    re.compile(
        r"(?:curl\s+.*-[oO]|wget\s+.*-O)\s+(?:/tmp/|/var/tmp/|/dev/shm/|/run/shm/)"
    ),
    re.compile(
        r"(?:curl|wget)\s+.*https?://[^\s;]+\s*;\s*(?:chmod\s+\+x\s+.*&&\s*)?"
        r"(?:/tmp/|/var/tmp/|/dev/shm/)"
    ),
]

# Suspicious shell execution (-c invocation)
SHELL_EXEC_PATTERN: re.Pattern[str] = re.compile(
    r"(?:^|[\s/\"'])(?:(?:/bin/|/usr/bin/)?(?:ba|z|da)?sh)\s+-c\b"
)

# Base64 decoder command pattern
BASE64_CMD_PATTERN: re.Pattern[str] = re.compile(
    r"(?:base64\s+(?:-[dD]|--decode)|openssl\s+enc\s+-d\s+-base64|b64decode)"
)

# Base64 token candidate pattern (at least 8 chars of valid base64)
BASE64_TOKEN_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")

# Temporary or shared memory execution directory pattern
TMP_DEV_SHM_PATTERN: re.Pattern[str] = re.compile(
    r"(?:^|[\s\"'=])(?:/tmp/|/var/tmp/|/dev/shm/|/run/shm/)"
)

# User home directory execution pattern
USER_HOME_PATTERN: re.Pattern[str] = re.compile(r"/home/([^/\s\"']+)")


class FlexibleBool(str):
    """String subclass that compares transparently with booleans and strings."""

    def __bool__(self) -> bool:
        """Evaluate truthiness of the wrapped string.

        Returns:
            True if string matches 'true', '1', or 'yes' (case-insensitive), False otherwise.
        """
        return self.lower() in ("true", "1", "yes")

    def __eq__(self, other: object) -> bool:
        """Check equality against bool, str, or other object types.

        Args:
            other: Object to compare against.

        Returns:
            True if values are semantically equal, False otherwise.
        """
        if isinstance(other, bool):
            return bool(self) is other
        if isinstance(other, str):
            return self.lower() == other.lower()
        return super().__eq__(other)


def parse_desktop_entry(content: str) -> dict[str, str]:
    """Parse FreeDesktop .desktop file returning keys from [Desktop Entry] section.

    Args:
        content: Raw text content of the .desktop file.

    Returns:
        Dictionary mapping field names to raw string values.
    """
    fields: dict[str, str] = {}
    current_section: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            continue

        is_desktop_section = (
            current_section is None or current_section.lower() == "desktop entry"
        )
        if is_desktop_section and "=" in line:
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if key not in fields:
                fields[key] = val

    return fields


def _get_field(fields: dict[str, str], target_key: str) -> str | None:
    """Retrieve case-insensitive field value from parsed fields dictionary.

    Args:
        fields: Parsed key-value dictionary.
        target_key: Target key name to look up.

    Returns:
        String value if key exists, or None.
    """
    target_lower = target_key.lower()
    for k, v in fields.items():
        if k.lower() == target_lower:
            return v
    return None


def _is_system_autostart(path: str) -> bool:
    """Check if autostart file is located in a system-wide directory.

    Args:
        path: Virtual path of the desktop file.

    Returns:
        True if the path starts with system configuration prefixes, False otherwise.
    """
    norm = normalize_virtual_path(path)
    return norm.startswith(("/etc/xdg/autostart", "/usr/share/autostart"))


def _is_user_autostart(path: str) -> bool:
    """Check if autostart file is located in a user-specific autostart directory.

    Args:
        path: Virtual path of the desktop file.

    Returns:
        True if the path resides under /home/* or /root/*, False otherwise.
    """
    norm = normalize_virtual_path(path)
    return norm.startswith(("/home/", "/root/"))


def _extract_user_from_path(path: str) -> str | None:
    """Extract username from a user-specific virtual autostart path.

    Args:
        path: Virtual path of the desktop file.

    Returns:
        Username string if path is under user home or root, or None.
    """
    norm = normalize_virtual_path(path)
    if norm.startswith("/root/"):
        return "root"
    m = re.match(r"^/home/([^/]+)/", norm)
    if m:
        return m.group(1)
    return None


def _extract_target_binary(exec_str: str) -> str:
    """Extract primary target binary or script from an Exec command line.

    Args:
        exec_str: Exec command line string from .desktop entry.

    Returns:
        Path or command token of the primary executable target.
    """
    if not exec_str:
        return ""
    try:
        tokens = shlex.split(exec_str)
    except ValueError:
        tokens = exec_str.split()

    if not tokens:
        return ""

    # Strip environment variable assignments (e.g. env VAR=val binary)
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "env":
            idx += 1
            continue
        if "=" in tok and not tok.startswith("/"):
            idx += 1
            continue
        break

    if idx >= len(tokens):
        return tokens[0]

    primary = tokens[idx]
    # If primary is an interpreter, check if the second token is a script path
    interpreters = {
        "sh",
        "/bin/sh",
        "bash",
        "/bin/bash",
        "python",
        "python3",
        "/usr/bin/python3",
        "perl",
        "/usr/bin/perl",
        "ruby",
        "/usr/bin/ruby",
    }
    if primary in interpreters and len(tokens) > idx + 1 and tokens[idx + 1] != "-c":
        # Likely script file argument: python /path/to/script.py
        return tokens[idx + 1]
    return primary


def _has_hidden_path(path_or_cmd: str) -> bool:
    """Check whether any path component in the command is hidden (starts with .).

    Args:
        path_or_cmd: Command line or filesystem path string.

    Returns:
        True if any path component starts with a dot, False otherwise.
    """
    try:
        tokens = shlex.split(path_or_cmd)
    except ValueError:
        tokens = path_or_cmd.split()

    for token in tokens:
        if "/" in token or token.startswith("."):
            parts = token.split("/")
            for part in parts:
                if part.startswith(".") and part not in (".", ".."):
                    return True
    return False


def _decode_base64_payload(text: str) -> str | None:
    """Detect and decode printable base64 payloads embedded in a command line.

    Args:
        text: Command line string to inspect.

    Returns:
        Decoded text string if valid printable payload found, or None.
    """
    candidates = BASE64_TOKEN_PATTERN.findall(text)
    for candidate in candidates:
        # Check padding
        padded = candidate
        if len(padded) % 4 != 0:
            padded += "=" * (4 - len(padded) % 4)
        try:
            raw_bytes = base64.b64decode(padded)
            decoded = raw_bytes.decode("utf-8")
            # Ensure decoded payload has printable text
            if len(decoded) >= 4 and all(
                c.isprintable() or c in "\n\r\t" for c in decoded
            ):
                return decoded
        except (ValueError, binascii.Error, UnicodeDecodeError):
            pass
    return None


def _check_obfuscation(text: str) -> bool:
    """Check for command obfuscation techniques such as hex/octal escapes or $IFS.

    Args:
        text: Command line string to inspect.

    Returns:
        True if obfuscation patterns are detected, False otherwise.
    """
    if re.search(r"\\x[0-9a-fA-F]{2}", text):
        return True
    if re.search(r"\\[0-7]{3}", text):
        return True
    return bool("$IFS" in text or "${IFS}" in text)


def analyze_autostart(target: AnalysisTarget) -> list[Finding]:
    """Scan and parse Linux XDG autostart entries on an AnalysisTarget.

    Args:
        target: Target filesystem or artifact collection.

    Returns:
        List of Finding objects identified from autostart .desktop entries.
    """
    matched_paths: set[str] = set()

    for pattern in AUTOSTART_GLOBS:
        for p in target.glob(pattern):
            matched_paths.add(p)

    for vpath in target.virtual_paths:
        vpath_norm = normalize_virtual_path(vpath)
        if vpath_norm.endswith(".desktop") and (
            "/autostart/" in vpath_norm or vpath_norm.startswith("/etc/xdg/autostart")
        ):
            matched_paths.add(vpath_norm)

    findings: list[Finding] = []

    for vpath in sorted(matched_paths):
        raw_content = target.read_text(vpath)
        if raw_content is None:
            continue

        entry_fields = parse_desktop_entry(raw_content)

        name = _get_field(entry_fields, "Name")
        exec_val = _get_field(entry_fields, "Exec") or ""
        try_exec_val = _get_field(entry_fields, "TryExec") or ""
        type_val = _get_field(entry_fields, "Type")
        hidden_val = _get_field(entry_fields, "Hidden")
        no_display_val = _get_field(entry_fields, "NoDisplay")
        autostart_enabled_val = _get_field(entry_fields, "X-GNOME-Autostart-enabled")

        flags: list[str] = []
        is_sys = _is_system_autostart(vpath)
        is_usr = _is_user_autostart(vpath)

        if is_usr:
            flags.append("USER_XDG_AUTOSTART")

        target_binary_path = _extract_target_binary(exec_val)
        exec_combined = f"{exec_val} {try_exec_val}".strip()

        # Cross-boundary check: system-wide autostart pointing to /home/<user>/*
        user_home_match = USER_HOME_PATTERN.search(exec_combined)
        if is_sys and user_home_match:
            flags.append("SYSTEM_AUTOSTART_POINTS_TO_USER_HOME")
            flags.append("NON_ROOT_USER_PATH")

        # Execution from temporary or dev/shm directories
        if TMP_DEV_SHM_PATTERN.search(exec_combined) or TMP_DEV_SHM_PATTERN.search(
            target_binary_path
        ):
            flags.append("EXEC_FROM_TMP_OR_DEV_SHM")

        # Hidden path execution
        if _has_hidden_path(exec_val) or _has_hidden_path(target_binary_path):
            flags.append("HIDDEN_PATH_EXECUTION")

        # Suspicious shell execution: sh -c or bash -c
        if SHELL_EXEC_PATTERN.search(exec_val):
            flags.append("SUSPICIOUS_SHELL_EXECUTION")

        # Reverse shell detection in exec line
        for pattern in REVERSE_SHELL_PATTERNS:
            if pattern.search(exec_val):
                flags.append("REVERSE_SHELL_PATTERN")
                break

        # Download cradle detection in exec line
        for pattern in DOWNLOAD_CRADLE_PATTERNS:
            if pattern.search(exec_val):
                flags.append("DOWNLOAD_CRADLE")
                break

        # Base64 payload detection and decoding
        decoded_payload: str | None = None
        has_base64_cmd = bool(BASE64_CMD_PATTERN.search(exec_val))
        candidate_decoded = _decode_base64_payload(exec_val)

        if has_base64_cmd or candidate_decoded:
            flags.append("BASE64_PAYLOAD")
            flags.append("OBFUSCATED_COMMAND")
            decoded_payload = candidate_decoded

        if _check_obfuscation(exec_val) and "OBFUSCATED_COMMAND" not in flags:
            flags.append("OBFUSCATED_COMMAND")

        # Inspect decoded payload for nested threats
        if decoded_payload:
            for pattern in REVERSE_SHELL_PATTERNS:
                if (
                    pattern.search(decoded_payload)
                    and "REVERSE_SHELL_PATTERN" not in flags
                ):
                    flags.append("REVERSE_SHELL_PATTERN")
                    break
            for pattern in DOWNLOAD_CRADLE_PATTERNS:
                if pattern.search(decoded_payload) and "DOWNLOAD_CRADLE" not in flags:
                    flags.append("DOWNLOAD_CRADLE")
                    break
            if (
                TMP_DEV_SHM_PATTERN.search(decoded_payload)
                and "EXEC_FROM_TMP_OR_DEV_SHM" not in flags
            ):
                flags.append("EXEC_FROM_TMP_OR_DEV_SHM")

        # Deduplicate flags preserving order
        dedup_flags: list[str] = list(dict.fromkeys(flags))

        # Risk scoring evaluation
        if (
            "SYSTEM_AUTOSTART_POINTS_TO_USER_HOME" in dedup_flags
            or "REVERSE_SHELL_PATTERN" in dedup_flags
        ):
            risk_level = RiskLevel.CRITICAL
        elif (
            "BASE64_PAYLOAD" in dedup_flags
            or "DOWNLOAD_CRADLE" in dedup_flags
            or "EXEC_FROM_TMP_OR_DEV_SHM" in dedup_flags
            or "OBFUSCATED_COMMAND" in dedup_flags
            or "HIDDEN_PATH_EXECUTION" in dedup_flags
            or "SUSPICIOUS_SHELL_EXECUTION" in dedup_flags
        ):
            risk_level = RiskLevel.HIGH
        elif "USER_XDG_AUTOSTART" in dedup_flags or "NON_ROOT_USER_PATH" in dedup_flags:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.INFO

        details: dict[str, Any] = {
            "name": name,
            "exec": exec_val,
            "try_exec": try_exec_val or None,
            "type": type_val,
            "hidden": FlexibleBool(hidden_val) if hidden_val is not None else None,
            "no_display": FlexibleBool(no_display_val)
            if no_display_val is not None
            else None,
            "autostart_enabled": (
                FlexibleBool(autostart_enabled_val)
                if autostart_enabled_val is not None
                else None
            ),
            "target_binary_path": target_binary_path,
            "flags": dedup_flags,
            # Backward-compatible exact field accessors
            "Name": name,
            "Exec": exec_val,
            "TryExec": try_exec_val or None,
            "Type": type_val,
            "Hidden": hidden_val,
            "NoDisplay": no_display_val,
            "X-GNOME-Autostart-enabled": autostart_enabled_val,
        }

        user = _extract_user_from_path(vpath)
        if user:
            details["user"] = user

        if decoded_payload:
            details["decoded_payload"] = decoded_payload

        findings.append(
            Finding(
                category="xdg_autostart",
                risk_level=risk_level,
                technique_id="T1547.013",
                path=vpath,
                details=details,
                raw_content=raw_content,
                decoded_payload=decoded_payload,
            )
        )

    return findings


class LinuxAutostartParser:
    """Parser class for Linux XDG Desktop Autostart persistence mechanisms."""

    @staticmethod
    def parse(target: AnalysisTarget) -> list[Finding]:
        """Parse autostart desktop entries from an AnalysisTarget.

        Args:
            target: The AnalysisTarget to inspect.

        Returns:
            List of detected persistence findings.
        """
        return analyze_autostart(target)


__all__ = ["LinuxAutostartParser", "analyze_autostart"]
