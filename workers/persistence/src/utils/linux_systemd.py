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
"""Linux Systemd persistence parser and threat analyzer (MITRE ATT&CK T1543.002)."""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
import shlex
from typing import Any

from src.utils.models import AnalysisTarget, Finding, RiskLevel

TECHNIQUE_ID: str = "T1543.002"

# System-level unit directories
SYSTEM_UNIT_PREFIXES: tuple[str, ...] = (
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
)

# Standard directories scanned for systemd units
SCAN_PATTERNS: list[str] = [
    "/etc/systemd/system/*",
    "/etc/systemd/system/*/*",
    "/lib/systemd/system/*",
    "/lib/systemd/system/*/*",
    "/usr/lib/systemd/system/*",
    "/usr/lib/systemd/system/*/*",
    "/home/*/.config/systemd/user/*",
    "/home/*/.config/systemd/user/*/*",
    "/home/*/.local/share/systemd/user/*",
    "/home/*/.local/share/systemd/user/*/*",
    "/root/.config/systemd/user/*",
    "/root/.config/systemd/user/*/*",
    "/root/.local/share/systemd/user/*",
    "/root/.local/share/systemd/user/*/*",
]

TMP_DEV_SHM_PREFIXES: tuple[str, ...] = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
)

INTERPRETER_NAMES: set[str] = {
    "sh",
    "bash",
    "zsh",
    "dash",
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "lua",
    "php",
    "env",
}


def parse_systemd_ini(content: str) -> dict[str, dict[str, list[str]]]:
    """Parse systemd unit file content into sections and key-value lists.

    Handles line continuations with trailing backslashes, comment lines (# and ;),
    and preserves multiple entries for the same key.

    Args:
        content: Raw text content of the systemd unit file.

    Returns:
        Dictionary mapping section names to dictionaries of directive keys and value lists.
    """
    sections: dict[str, dict[str, list[str]]] = {}
    current_section: str | None = None

    raw_lines = content.splitlines()
    joined_lines: list[str] = []
    accum = ""

    for line in raw_lines:
        line_stripped_r = line.rstrip()
        if accum:
            if line_stripped_r.endswith("\\"):
                accum += " " + line_stripped_r[:-1].strip()
            else:
                accum += " " + line_stripped_r.strip()
                joined_lines.append(accum)
                accum = ""
        else:
            if line_stripped_r.endswith("\\"):
                accum = line_stripped_r[:-1].strip()
            else:
                joined_lines.append(line)
    if accum:
        joined_lines.append(accum)

    for line in joined_lines:
        clean = line.strip()
        if not clean or clean.startswith(("#", ";")):
            continue

        if clean.startswith("[") and clean.endswith("]"):
            current_section = clean[1:-1].strip()
            if current_section not in sections:
                sections[current_section] = {}
            continue

        if "=" in clean and current_section:
            key, val = clean.split("=", 1)
            key = key.strip()
            val = val.strip()
            if key not in sections[current_section]:
                sections[current_section][key] = []
            sections[current_section][key].append(val)

    return sections


def _get_first(section: dict[str, list[str]], key: str) -> str | None:
    """Retrieve the first value for key in section ignoring case.

    Args:
        section: Section dictionary mapping directive names to lists of values.
        key: Directive name to look up.

    Returns:
        First value for directive if present, or None.
    """
    for k, v in section.items():
        if k.lower() == key.lower() and v:
            return v[0]
    return None


def _get_last(section: dict[str, list[str]], key: str) -> str | None:
    """Retrieve the last value for key in section ignoring case.

    Args:
        section: Section dictionary mapping directive names to lists of values.
        key: Directive name to look up.

    Returns:
        Last value for directive if present, or None.
    """
    for k, v in section.items():
        if k.lower() == key.lower() and v:
            return v[-1]
    return None


def _get_all(section: dict[str, list[str]], key: str) -> list[str]:
    """Retrieve all values for key in section ignoring case.

    Args:
        section: Section dictionary mapping directive names to lists of values.
        key: Directive name to look up.

    Returns:
        List of all values matching key.
    """
    result: list[str] = []
    for k, v in section.items():
        if k.lower() == key.lower():
            result.extend(v)
    return result


def extract_binary_and_script(exec_cmd: str) -> tuple[str, str | None]:
    """Extract binary executable path and optional target script from an Exec* command line.

    Args:
        exec_cmd: Command line string from ExecStart or related directive.

    Returns:
        Tuple of (binary_executable_path, target_script_path_or_none).
    """
    clean = exec_cmd.strip()
    while clean and clean[0] in ("@", "-", "+", "!"):
        clean = clean[1:].lstrip()

    try:
        tokens = shlex.split(clean)
    except ValueError:
        tokens = clean.split()

    if not tokens:
        return ("", None)

    binary = tokens[0]
    script: str | None = None
    bin_name = posixpath.basename(binary)

    if bin_name in INTERPRETER_NAMES and len(tokens) > 1:
        for t in tokens[1:]:
            if t.startswith(("-", "+")):
                continue
            if "/" in t or t.endswith((".sh", ".py", ".pl", ".rb", ".bin")):
                script = t
                break

    return (binary, script)


def extract_and_decode_base64(cmd: str) -> str | None:
    """Search for base64 encoded payload inside an exec command line and decode it.

    Args:
        cmd: Exec command line string.

    Returns:
        Decoded text string if base64 payload detected, or None.
    """
    patterns = [
        r"(?:echo|printf)\s+['\"]?([A-Za-z0-9+/=]{8,})['\"]?\s*\|\s*base64",
        r"base64\s+(?:-d|--decode)[^|;]*<<<['\"]?([A-Za-z0-9+/=]{8,})['\"]?",
        r"base64\s+(?:-d|--decode)\s+['\"]?([A-Za-z0-9+/=]{8,})['\"]?",
        r"['\"]([A-Za-z0-9+/=]{16,})['\"]\s*\|\s*base64",
        r"(?:\s|^)['\"]?([A-Za-z0-9+/]{16,}={0,2})['\"]?(?:\s|$)",
    ]
    for pattern in patterns:
        m = re.search(pattern, cmd, re.IGNORECASE)
        if m:
            b64_str = m.group(1).strip("'\"")
            missing_padding = len(b64_str) % 4
            if missing_padding:
                b64_str += "=" * (4 - missing_padding)
            try:
                decoded_bytes = base64.b64decode(b64_str)
                text = decoded_bytes.decode("utf-8", errors="replace")
                if text and any(c.isprintable() for c in text):
                    return text
            except (ValueError, binascii.Error, UnicodeDecodeError):
                continue
    return None


def _extract_user_from_path(path: str) -> str | None:
    """Extract username from user unit path or user home directory path.

    Args:
        path: Path string to inspect.

    Returns:
        Extracted username string if found, or None.
    """
    clean = path.replace("\\", "/")
    if clean.startswith(("/root/", "/root")):
        return "root"
    m = re.match(r"^/home/([^/]+)/", clean)
    if m:
        return m.group(1)
    if clean.startswith("~"):
        user_part = clean[1:].split("/")[0]
        return user_part if user_part else None
    return None


def _has_hidden_component(path: str) -> bool:
    """Check if any directory segment or the filename itself is hidden.

    Args:
        path: Path string to test.

    Returns:
        True if any path segment starts with a dot, False otherwise.
    """
    clean = path.replace("\\", "/").strip()
    parts = clean.split("/")
    for p in parts:
        if p.startswith(".") and p not in (".", ".."):
            # Whitelist standard user configuration paths
            if p == ".config":
                continue
            return True
    return False


def _check_suspicious_indicators(
    path: str,
    all_exec_cmds: list[str],
    is_system_unit: bool,
    is_user_unit: bool,
    unit_user: str | None,
    lingering_users: set[str],
    target: AnalysisTarget,
) -> tuple[list[str], str | None, str | None, str | None]:
    """Inspect unit properties and commands for suspicious indicators.

    Args:
        path: Virtual path of the unit file.
        all_exec_cmds: All executable commands defined in the unit.
        is_system_unit: Whether the unit is system-level.
        is_user_unit: Whether the unit is user-level.
        unit_user: Target user associated with the unit.
        lingering_users: Set of usernames with systemd linger enabled.
        target: Forensic analysis target.

    Returns:
        Tuple of (flags, target_binary_path, target_binary_owner, decoded_payload).
    """
    flags: list[str] = []
    decoded_payload: str | None = None
    target_binary_path: str | None = None
    target_binary_owner: str | None = None

    # Check user unit & linger
    if is_user_unit:
        flags.append("USER_SYSTEMD_UNIT")
        if unit_user and (
            unit_user in lingering_users
            or target.exists(f"/var/lib/systemd/linger/{unit_user}")
        ):
            flags.append("USER_LINGER_ENABLED")

    for cmd in all_exec_cmds:
        binary, script = extract_binary_and_script(cmd)
        candidate_target = script if script else binary

        if not target_binary_path and candidate_target:
            target_binary_path = candidate_target

        effective_path = candidate_target or binary

        # Cross-boundary check: system service pointing to user home
        if is_system_unit and effective_path:
            norm_eff = (
                effective_path
                if effective_path.startswith("~")
                else posixpath.normpath(effective_path)
            )
            if norm_eff.startswith(("/home/", "~")):
                owner = _extract_user_from_path(norm_eff)
                target_binary_owner = owner or "unknown"
                target_binary_path = norm_eff
                flags.append("SYSTEM_SERVICE_POINTS_TO_USER_HOME")
                flags.append("NON_ROOT_USER_PATH")

        # Execution from temporary or shared memory directories
        if any(
            t.startswith(TMP_DEV_SHM_PREFIXES)
            for t in (binary, script, effective_path)
            if t
        ) or any(prefix in cmd for prefix in TMP_DEV_SHM_PREFIXES):
            flags.append("EXEC_FROM_TMP_OR_DEV_SHM")
            if not target_binary_path:
                target_binary_path = effective_path

        # Hidden path execution
        if (
            (effective_path and _has_hidden_component(effective_path))
            or _has_hidden_component(binary)
            or posixpath.basename(path).startswith(".")
        ):
            flags.append("HIDDEN_PATH_EXECUTION")

        # Shell execution checks
        if (
            re.search(
                r"\b(?:bash|sh|zsh|dash)\s+-(?:[a-zA-Z]*[ci])\b",
                cmd,
            )
            or re.search(r"\b(?:python|python2|python3)\s+-c\b", cmd)
            or re.search(r"\bperl\s+-e\b", cmd)
            or re.search(r"\bruby\s+-e\b", cmd)
            or re.search(r"\bphp\s+-r\b", cmd)
            or re.search(r"\b(?:curl|wget)\b", cmd)
            or re.search(r"\b(?:nc|ncat|netcat|socat)\b", cmd)
        ):
            flags.append("SUSPICIOUS_SHELL_EXECUTION")

        # Reverse shell detection
        if (
            "/dev/tcp/" in cmd
            or "/dev/udp/" in cmd
            or re.search(r"\bmkfifo\b", cmd)
            or re.search(r"\b(?:nc|ncat|netcat)\s+.*-(?:[a-zA-Z]*e)\b", cmd)
            or re.search(r"\bsocat\b.*exec:", cmd, re.IGNORECASE)
            or ("socket.socket" in cmd and "connect" in cmd)
        ):
            flags.append("REVERSE_SHELL_PATTERN")

        # Base64 payload detection & decoding
        if re.search(r"\bbase64\b", cmd) or (
            re.search(r"[A-Za-z0-9+/]{20,}={0,2}", cmd) and "|" in cmd
        ):
            flags.append("BASE64_PAYLOAD")
            if not decoded_payload:
                decoded_payload = extract_and_decode_base64(cmd)

        # Obfuscated command detection
        if (
            "BASE64_PAYLOAD" in flags
            or re.search(r"\\x[0-9a-fA-F]{2}", cmd)
            or re.search(r"\\[0-7]{3}", cmd)
            or re.search(r"\$\{IFS\}|\$IFS\b", cmd)
            or re.search(r"\beval\s+", cmd)
        ):
            flags.append("OBFUSCATED_COMMAND")

    deduped_flags = list(dict.fromkeys(flags))
    return (
        deduped_flags,
        target_binary_path,
        target_binary_owner,
        decoded_payload,
    )


def _determine_category(
    path: str,
    flags: list[str],
    is_user_unit: bool,
) -> str:
    """Determine finding category based on flags and unit type.

    Args:
        path: Virtual path of the unit file.
        flags: Heuristic indicator flags.
        is_user_unit: Whether the unit is a user-level service.

    Returns:
        Category name string.
    """
    if "SYSTEM_SERVICE_POINTS_TO_USER_HOME" in flags:
        return "cross_boundary_systemd"
    if path.endswith(".timer"):
        return "systemd_timer"
    if is_user_unit or "USER_SYSTEMD_UNIT" in flags:
        return "user_systemd_service"
    return "systemd_service"


def _determine_risk_level(
    flags: list[str],
    is_system_unit: bool,
) -> RiskLevel:
    """Compute risk level from extracted flags and context.

    Args:
        flags: List of identified forensic flags.
        is_system_unit: Whether unit executes under system context.

    Returns:
        RiskLevel enum value.
    """
    if (
        "SYSTEM_SERVICE_POINTS_TO_USER_HOME" in flags
        or "REVERSE_SHELL_PATTERN" in flags
    ):
        return RiskLevel.CRITICAL
    if "EXEC_FROM_TMP_OR_DEV_SHM" in flags and is_system_unit:
        return RiskLevel.CRITICAL
    if "EXEC_FROM_TMP_OR_DEV_SHM" in flags:
        return RiskLevel.HIGH
    if any(
        f in flags
        for f in (
            "BASE64_PAYLOAD",
            "OBFUSCATED_COMMAND",
            "HIDDEN_PATH_EXECUTION",
            "SUSPICIOUS_SHELL_EXECUTION",
        )
    ):
        return RiskLevel.HIGH
    if "USER_LINGER_ENABLED" in flags:
        return RiskLevel.MEDIUM
    return RiskLevel.INFO


def analyze_unit_file(
    target: AnalysisTarget,
    path: str,
    lingering_users: set[str],
) -> Finding | None:
    """Parse and analyze a single systemd unit file.

    Args:
        target: Forensic analysis target.
        path: Virtual path of the systemd unit file.
        lingering_users: Set of usernames with lingering sessions enabled.

    Returns:
        Finding object if the unit file is parsed, or None if unreadable or empty.
    """
    content = target.read_text(path)
    if content is None or not content.strip():
        return None

    sections = parse_systemd_ini(content)
    unit_sec = sections.get("Unit", {})
    service_sec = sections.get("Service", {})
    timer_sec = sections.get("Timer", {})

    is_system_unit = path.startswith(SYSTEM_UNIT_PREFIXES)
    is_user_unit = (
        ("/.config/systemd/user" in path)
        or ("/.local/share/systemd/user" in path)
        or ("/systemd/user/" in path)
        or (path.startswith("/home/") and "/systemd/" in path)
    )

    user_from_path = _extract_user_from_path(path) if is_user_unit else None

    # Extract parsed directives
    exec_starts = _get_all(service_sec, "ExecStart")
    exec_start_pres = _get_all(service_sec, "ExecStartPre")
    exec_start_posts = _get_all(service_sec, "ExecStartPost")
    exec_stop = _get_last(service_sec, "ExecStop")
    exec_reload = _get_last(service_sec, "ExecReload")
    condition_path = _get_first(unit_sec, "ConditionPathExists") or _get_first(
        service_sec, "ConditionPathExists"
    )
    user_directive = _get_first(service_sec, "User")
    working_dir = _get_first(service_sec, "WorkingDirectory")
    on_boot_sec = _get_first(timer_sec, "OnBootSec")
    on_unit_active_sec = _get_first(timer_sec, "OnUnitActiveSec")
    on_calendar = _get_first(timer_sec, "OnCalendar")
    timer_unit = _get_first(timer_sec, "Unit")

    all_execs: list[str] = []
    all_execs.extend(exec_starts)
    all_execs.extend(exec_start_pres)
    all_execs.extend(exec_start_posts)
    if exec_stop:
        all_execs.append(exec_stop)
    if exec_reload:
        all_execs.append(exec_reload)

    # Unit user for linger evaluation
    eval_user = user_from_path or user_directive

    (
        flags,
        target_bin_path,
        target_bin_owner,
        decoded_payload,
    ) = _check_suspicious_indicators(
        path=path,
        all_exec_cmds=all_execs,
        is_system_unit=is_system_unit,
        is_user_unit=is_user_unit,
        unit_user=eval_user,
        lingering_users=lingering_users,
        target=target,
    )

    category = _determine_category(path, flags, is_user_unit)
    risk_level = _determine_risk_level(flags, is_system_unit)

    service_name = posixpath.basename(path)
    primary_exec_start = exec_starts[-1] if exec_starts else None

    details: dict[str, Any] = {
        "service_name": service_name,
        "flags": flags,
    }

    if is_system_unit:
        details["system_config_path"] = path

    if primary_exec_start is not None:
        details["exec_start"] = primary_exec_start
    if exec_start_pres:
        details["exec_start_pre"] = (
            exec_start_pres[0] if len(exec_start_pres) == 1 else exec_start_pres
        )
    if exec_start_posts:
        details["exec_start_post"] = (
            exec_start_posts[0] if len(exec_start_posts) == 1 else exec_start_posts
        )
    if exec_stop is not None:
        details["exec_stop"] = exec_stop
    if exec_reload is not None:
        details["exec_reload"] = exec_reload
    if condition_path is not None:
        details["condition_path_exists"] = condition_path

    if user_directive is not None:
        details["user"] = user_directive
    elif user_from_path is not None:
        details["user"] = user_from_path

    if working_dir is not None:
        details["working_directory"] = working_dir
    if on_boot_sec is not None:
        details["on_boot_sec"] = on_boot_sec
    if on_unit_active_sec is not None:
        details["on_unit_active_sec"] = on_unit_active_sec
    if on_calendar is not None:
        details["on_calendar"] = on_calendar
    if timer_unit is not None:
        details["unit"] = timer_unit

    if target_bin_path is not None:
        details["target_binary_path"] = target_bin_path
    if target_bin_owner is not None:
        details["target_binary_owner"] = target_bin_owner

    if "USER_LINGER_ENABLED" in flags:
        details["linger_enabled"] = True

    if decoded_payload is not None:
        details["decoded_payload"] = decoded_payload

    return Finding(
        id="",
        category=category,
        risk_level=risk_level,
        technique_id=TECHNIQUE_ID,
        path=path,
        details=details,
        raw_content=content,
        decoded_payload=decoded_payload,
    )


def analyze_systemd(target: AnalysisTarget) -> list[Finding]:
    """Scan and analyze system and user systemd units on the target filesystem.

    Args:
        target: Forensic analysis target (mounted image or artifact collection).

    Returns:
        List of Finding objects discovered across system and user unit directories.
    """
    discovered_paths: set[str] = set()

    for pattern in SCAN_PATTERNS:
        for matched in target.glob(pattern):
            if matched.endswith((".service", ".timer")):
                discovered_paths.add(matched)

    # Include any .service or .timer paths explicitly registered in virtual_paths
    if target.virtual_paths:
        for vpath in target.virtual_paths:
            if vpath.endswith((".service", ".timer")):
                discovered_paths.add(vpath)

    # Discover users with linger enabled
    lingering_users: set[str] = set()
    for linger_path in target.glob("/var/lib/systemd/linger/*"):
        user = posixpath.basename(linger_path)
        if user and not user.startswith("."):
            lingering_users.add(user)

    if target.virtual_paths:
        for vpath in target.virtual_paths:
            if vpath.startswith("/var/lib/systemd/linger/"):
                user = posixpath.basename(vpath)
                if user and not user.startswith("."):
                    lingering_users.add(user)

    findings: list[Finding] = []
    for path in sorted(discovered_paths):
        finding = analyze_unit_file(target, path, lingering_users)
        if finding is not None:
            findings.append(finding)

    return findings


class LinuxSystemdParser:
    """Parser class interface matching Linux coordinator dispatch."""

    @classmethod
    def parse(cls, target: AnalysisTarget) -> list[Finding]:
        """Dispatch analysis on target.

        Args:
            target: The AnalysisTarget to inspect.

        Returns:
            List of detected systemd findings.
        """
        return analyze_systemd(target)


__all__ = [
    "LinuxSystemdParser",
    "analyze_systemd",
    "analyze_unit_file",
    "extract_and_decode_base64",
    "extract_binary_and_script",
    "parse_systemd_ini",
]
