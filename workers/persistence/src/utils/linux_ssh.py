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
"""Linux SSH Authorized Keys and sshd_config persistence extractor."""

from __future__ import annotations

import base64
import binascii
import hashlib
import posixpath
import re
from typing import Any

from src.utils.models import (
    AnalysisTarget,
    Finding,
    RiskLevel,
    normalize_virtual_path,
)

TECHNIQUE_ID: str = "T1098.004"
CATEGORY_AUTHORIZED_KEYS: str = "ssh_authorized_keys"
CATEGORY_SSHD_CONFIG: str = "sshd_config_override"

REVERSE_SHELL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/dev/tcp/"),
    re.compile(r"/dev/udp/"),
    re.compile(r"\bnc(\.traditional)?\s+-[a-zA-Z]*e\b"),
    re.compile(r"\bncat\s+-[a-zA-Z]*e\b"),
    re.compile(r"\bnetcat\s+-[a-zA-Z]*e\b"),
    re.compile(r"\bmkfifo\b"),
    re.compile(r"\bbash\s+-i\b"),
    re.compile(r"\bsh\s+-i\b"),
    re.compile(r"python.*socket", re.IGNORECASE),
    re.compile(r"perl.*Socket", re.IGNORECASE),
    re.compile(r"\bsocat\b"),
]

SUSPICIOUS_TMP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/tmp/"),
    re.compile(r"/var/tmp/"),
    re.compile(r"/dev/shm/"),
    re.compile(r"/run/"),
]

BASE64_EXEC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"base64\s+(-d|--decode)", re.IGNORECASE),
    re.compile(r"\|\s*base64\s+-d", re.IGNORECASE),
    re.compile(r"b64decode", re.IGNORECASE),
]

UNCOMMON_COMMENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^$"),
    re.compile(r"^root@localhost$", re.IGNORECASE),
    re.compile(r".*@localhost$", re.IGNORECASE),
    re.compile(r"^test(@.*)?$", re.IGNORECASE),
    re.compile(r"^temp(@.*)?$", re.IGNORECASE),
    re.compile(r"^deploy-bot.*", re.IGNORECASE),
    re.compile(r"^ci-bot.*", re.IGNORECASE),
    re.compile(r"^backup.*", re.IGNORECASE),
    re.compile(r"^backdoor.*", re.IGNORECASE),
]

STANDARD_AUTHORIZED_KEYS_PATTERNS: set[str] = {
    ".ssh/authorized_keys",
    ".ssh/authorized_keys2",
    "%h/.ssh/authorized_keys",
    "%h/.ssh/authorized_keys2",
    "~/.ssh/authorized_keys",
    "~/.ssh/authorized_keys2",
}


def _is_ssh_key_type(token: str) -> bool:
    """Check if token matches known SSH public key algorithm types.

    Args:
        token: Key algorithm token string.

    Returns:
        True if token matches standard OpenSSH key algorithm prefixes, False otherwise.
    """
    return token.startswith(("ssh-", "ecdsa-", "sk-"))


def parse_options_list(tokens: list[str]) -> dict[str, Any]:
    """Parse comma- or space-delimited authorized_keys options respecting quoted strings.

    Args:
        tokens: Option string tokens preceding the public key algorithm.

    Returns:
        Dictionary mapping option names to string values or True for boolean flags.
    """
    options: dict[str, Any] = {}
    combined = ",".join(tokens)
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    escape = False

    for ch in combined:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == "\\":
            escape = True
            current.append(ch)
            continue
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
            continue
        if ch == "," and not in_quotes:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
        else:
            current.append(ch)

    if current:
        part = "".join(current).strip()
        if part:
            parts.append(part)

    for item in parts:
        if "=" in item:
            k, v = item.split("=", 1)
            k = k.strip()
            v = v.strip()
            if v.startswith('"') and v.endswith('"') and len(v) >= 2:
                v = v[1:-1]
            options[k] = v
        else:
            options[item.strip()] = True

    return options


def parse_authorized_keys_line(raw_line: str) -> dict[str, Any] | None:
    """Parse a single line from an authorized_keys file.

    Args:
        raw_line: Raw line text from authorized_keys file.

    Returns:
        Dictionary with 'options', 'key_type', 'key_blob', and 'comment',
        or None if line is blank, comment, or malformed.
    """
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None

    idx = 0
    in_quotes = False
    escape = False
    tokens: list[str] = []
    current: list[str] = []

    while idx < len(line):
        ch = line[idx]
        if escape:
            current.append(ch)
            escape = False
            idx += 1
            continue
        if ch == "\\":
            escape = True
            current.append(ch)
            idx += 1
            continue
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
            idx += 1
            continue
        if not in_quotes and ch in (" ", "\t"):
            if current:
                token_str = "".join(current)
                tokens.append(token_str)
                current = []
                if _is_ssh_key_type(token_str):
                    break
            idx += 1
        else:
            current.append(ch)
            idx += 1

    if current:
        tokens.append("".join(current))

    if not tokens or not _is_ssh_key_type(tokens[-1]):
        return None

    key_type = tokens[-1]
    options_tokens = tokens[:-1]

    rest = line[idx:].lstrip()
    if not rest:
        return None

    rest_parts = rest.split(None, 1)
    key_blob = rest_parts[0]
    comment = rest_parts[1] if len(rest_parts) > 1 else ""

    options = parse_options_list(options_tokens)

    return {
        "options": options,
        "key_type": key_type,
        "key_blob": key_blob,
        "comment": comment,
    }


def get_fingerprint_and_prefix(key_blob: str) -> tuple[str, str]:
    """Derive OpenSSH SHA256 fingerprint and prefix snippet from a base64 key blob.

    Args:
        key_blob: Base64-encoded public key payload.

    Returns:
        Tuple of (sha256_fingerprint, prefix_snippet).
    """
    prefix = key_blob[:32] + "..." if len(key_blob) > 32 else key_blob
    try:
        padded = key_blob
        missing_padding = len(padded) % 4
        if missing_padding:
            padded += "=" * (4 - missing_padding)
        raw_key = base64.b64decode(padded)
        sha256_hash = hashlib.sha256(raw_key).digest()
        b64_hash = base64.b64encode(sha256_hash).decode("ascii").rstrip("=")
        fingerprint = f"SHA256:{b64_hash}"
    except (ValueError, binascii.Error, TypeError):
        fingerprint = prefix
    return fingerprint, prefix


def infer_user_from_path(vpath: str) -> str:
    """Infer target operating system user from authorized_keys virtual path.

    Args:
        vpath: Virtual path of the key file.

    Returns:
        Inferred username string (e.g. 'root', or user from /home/<user>/).
    """
    norm = normalize_virtual_path(vpath)
    if norm.startswith("/root/") or norm == "/root":
        return "root"
    m = re.match(r"^/home/([^/]+)/", norm)
    if m:
        return m.group(1)
    base = posixpath.basename(norm)
    if base not in ("authorized_keys", "authorized_keys2"):
        return base
    return "unknown"


def parse_sshd_line(line: str) -> tuple[str, str] | None:
    """Parse a single sshd_config line into (keyword, value) tuple.

    Args:
        line: Configuration line from sshd_config.

    Returns:
        Tuple of (directive_keyword, directive_value) or None if invalid or comment.
    """
    clean = line.strip()
    if not clean or clean.startswith("#"):
        return None

    if "=" in clean:
        parts = clean.split("=", 1)
        kw = parts[0].strip()
        if " " not in kw:
            val = parts[1].strip()
            if val.startswith('"') and val.endswith('"') and len(val) >= 2:
                val = val[1:-1]
            return kw, val

    parts = clean.split(None, 1)
    if len(parts) == 2:
        kw = parts[0].strip()
        val = parts[1].strip()
        if not val.startswith('"') and " #" in val:
            val = val.split(" #", 1)[0].strip()
        if val.startswith('"') and val.endswith('"') and len(val) >= 2:
            val = val[1:-1]
        return kw, val

    return None


class LinuxSSHParser:
    """Parser and threat detector for SSH authorized keys and sshd daemon configurations."""

    def __init__(self, target: AnalysisTarget) -> None:
        """Initialize with an AnalysisTarget.

        Args:
            target: The AnalysisTarget providing file access.
        """
        self.target: AnalysisTarget = target
        self.findings: list[Finding] = []
        self.custom_keys_file_patterns: list[str] = []

    def parse(self) -> list[Finding]:
        """Execute full SSH inspection across daemon configs and authorized key stores.

        Returns:
            List of detected SSH persistence findings.
        """
        self.findings = []
        self.custom_keys_file_patterns = []

        # 1. Parse sshd_config files first (extracts overrides and custom AuthorizedKeysFile directives)
        self._parse_sshd_configs()

        # 2. Parse authorized_keys files (root, user homes, and custom paths)
        self._parse_authorized_keys_files()

        return self.findings

    def _parse_sshd_configs(self) -> None:
        """Scan /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/* for security risks."""
        config_paths: set[str] = set()

        if self.target.exists("/etc/ssh/sshd_config"):
            config_paths.add("/etc/ssh/sshd_config")

        for p in self.target.glob("/etc/ssh/sshd_config.d/*"):
            config_paths.add(p)

        for p in self.target.glob("*sshd_config*"):
            config_paths.add(p)

        for config_path in sorted(config_paths):
            content = self.target.read_text(config_path)
            if content is None:
                continue

            for line_no, raw_line in enumerate(content.splitlines(), start=1):
                parsed = parse_sshd_line(raw_line)
                if not parsed:
                    continue

                keyword, value = parsed
                kw_lower = keyword.lower()

                if kw_lower == "permitrootlogin":
                    self._check_permit_root_login(config_path, raw_line, line_no, value)
                elif kw_lower == "permitemptypasswords":
                    self._check_permit_empty_passwords(
                        config_path, raw_line, line_no, value
                    )
                elif kw_lower == "authorizedkeyscommand":
                    self._check_authorized_keys_command(
                        config_path, raw_line, line_no, value
                    )
                elif kw_lower == "authorizedkeysfile":
                    self._check_authorized_keys_file(
                        config_path, raw_line, line_no, value
                    )

    def _check_permit_root_login(
        self, config_path: str, raw_line: str, line_no: int, value: str
    ) -> None:
        """Check PermitRootLogin directive for permissive settings.

        Args:
            config_path: Virtual configuration file path.
            raw_line: Raw configuration line.
            line_no: 1-based line number.
            value: Configured directive value.
        """
        if value.strip().lower() == "yes":
            self.findings.append(
                Finding(
                    category=CATEGORY_SSHD_CONFIG,
                    risk_level=RiskLevel.MEDIUM,
                    technique_id=TECHNIQUE_ID,
                    path=config_path,
                    details={
                        "directive": "PermitRootLogin",
                        "value": value,
                        "line_number": line_no,
                        "flags": ["SSHD_PERMIT_ROOT_LOGIN"],
                    },
                    raw_content=raw_line.strip(),
                )
            )

    def _check_permit_empty_passwords(
        self, config_path: str, raw_line: str, line_no: int, value: str
    ) -> None:
        """Check PermitEmptyPasswords directive.

        Args:
            config_path: Virtual configuration file path.
            raw_line: Raw configuration line.
            line_no: 1-based line number.
            value: Configured directive value.
        """
        if value.strip().lower() == "yes":
            self.findings.append(
                Finding(
                    category=CATEGORY_SSHD_CONFIG,
                    risk_level=RiskLevel.HIGH,
                    technique_id=TECHNIQUE_ID,
                    path=config_path,
                    details={
                        "directive": "PermitEmptyPasswords",
                        "value": value,
                        "line_number": line_no,
                        "flags": ["SSHD_PERMIT_EMPTY_PASSWORDS"],
                    },
                    raw_content=raw_line.strip(),
                )
            )

    def _check_authorized_keys_command(
        self, config_path: str, raw_line: str, line_no: int, value: str
    ) -> None:
        """Check AuthorizedKeysCommand directive for suspicious scripts.

        Args:
            config_path: Virtual configuration file path.
            raw_line: Raw configuration line.
            line_no: 1-based line number.
            value: Configured command line string.
        """
        cmd_val = value.strip()
        if not cmd_val or cmd_val.lower() == "none":
            return

        flags = ["SSHD_AUTHORIZED_KEYS_COMMAND"]
        risk_level = RiskLevel.MEDIUM

        if any(pat.search(cmd_val) for pat in SUSPICIOUS_TMP_PATTERNS):
            flags.append("COMMAND_IN_TMP")
            risk_level = RiskLevel.CRITICAL
        elif "/home/" in cmd_val:
            flags.append("COMMAND_IN_USER_HOME")
            risk_level = RiskLevel.CRITICAL

        self.findings.append(
            Finding(
                category=CATEGORY_SSHD_CONFIG,
                risk_level=risk_level,
                technique_id=TECHNIQUE_ID,
                path=config_path,
                details={
                    "directive": "AuthorizedKeysCommand",
                    "value": cmd_val,
                    "line_number": line_no,
                    "flags": flags,
                },
                raw_content=raw_line.strip(),
            )
        )

    def _check_authorized_keys_file(
        self, config_path: str, raw_line: str, line_no: int, value: str
    ) -> None:
        """Check AuthorizedKeysFile directive for non-standard paths.

        Args:
            config_path: Virtual configuration file path.
            raw_line: Raw configuration line.
            line_no: 1-based line number.
            value: Configured path specification.
        """
        path_tokens = value.split()
        non_standard: list[str] = []

        for token in path_tokens:
            clean_token = token.strip()
            # Standard paths are located in .ssh/ directory
            if clean_token in STANDARD_AUTHORIZED_KEYS_PATTERNS:
                continue
            if clean_token.startswith((".ssh/", "%h/.ssh/")):
                continue
            non_standard.append(clean_token)
            self.custom_keys_file_patterns.append(clean_token)

        if not non_standard:
            return

        flags = ["SSHD_CUSTOM_AUTHORIZED_KEYS_FILE"]
        risk_level = RiskLevel.MEDIUM

        if any(
            any(pat.search(tok) for pat in SUSPICIOUS_TMP_PATTERNS)
            for tok in non_standard
        ):
            flags.append("KEYS_FILE_IN_TMP")
            risk_level = RiskLevel.CRITICAL
        elif any("/home/" in tok for tok in non_standard):
            flags.append("KEYS_FILE_IN_USER_HOME")
            risk_level = RiskLevel.HIGH

        self.findings.append(
            Finding(
                category=CATEGORY_SSHD_CONFIG,
                risk_level=risk_level,
                technique_id=TECHNIQUE_ID,
                path=config_path,
                details={
                    "directive": "AuthorizedKeysFile",
                    "value": value,
                    "custom_paths": non_standard,
                    "line_number": line_no,
                    "flags": flags,
                },
                raw_content=raw_line.strip(),
            )
        )

    def _parse_authorized_keys_files(self) -> None:
        """Scan all identified authorized_keys files and evaluate key attributes."""
        files_to_scan: dict[str, str] = {}  # virtual_path -> user

        # 1. Root standard locations
        for p in ("/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2"):
            if self.target.exists(p):
                files_to_scan[p] = "root"

        # 2. User homes standard locations
        for p in self.target.glob("/home/*/.ssh/authorized_keys"):
            files_to_scan[p] = infer_user_from_path(p)
        for p in self.target.glob("/home/*/.ssh/authorized_keys2"):
            files_to_scan[p] = infer_user_from_path(p)

        # 3. Custom paths discovered in sshd_config
        for pattern in self.custom_keys_file_patterns:
            self._resolve_custom_pattern(pattern, files_to_scan)

        # 4. Loose or staged authorized_keys files
        for p in self.target.glob("*authorized_keys*"):
            norm = normalize_virtual_path(p)
            # Avoid scanning sshd_config or other non-key files
            if "sshd_config" in norm or norm.endswith(
                (".conf", ".c", ".h", ".py", ".md")
            ):
                continue
            if norm not in files_to_scan:
                files_to_scan[norm] = infer_user_from_path(norm)

        for vpath in sorted(files_to_scan.keys()):
            user = files_to_scan[vpath]
            self._scan_single_authorized_keys_file(vpath, user)

    def _resolve_custom_pattern(
        self, pattern: str, files_to_scan: dict[str, str]
    ) -> None:
        """Expand and add custom AuthorizedKeysFile directives to scan map.

        Args:
            pattern: Directive pattern containing %u, %h, or literal paths.
            files_to_scan: Target map to update with discovered paths and users.
        """
        if "%u" in pattern:
            glob_pat = pattern.replace("%u", "*").replace("%h", "/home/*")
            for vpath in self.target.glob(glob_pat):
                user = posixpath.basename(vpath)
                files_to_scan[vpath] = user
        elif "%h" in pattern:
            glob_pat = pattern.replace("%h", "/home/*")
            for vpath in self.target.glob(glob_pat):
                files_to_scan[vpath] = infer_user_from_path(vpath)
        else:
            if self.target.exists(pattern):
                files_to_scan[pattern] = infer_user_from_path(pattern)
            for vpath in self.target.glob(pattern):
                if vpath not in files_to_scan:
                    files_to_scan[vpath] = infer_user_from_path(vpath)

    def _scan_single_authorized_keys_file(self, vpath: str, user: str) -> None:
        """Scan and evaluate keys within an authorized_keys file.

        Args:
            vpath: Virtual file path.
            user: Operating system user associated with the key file.
        """
        content = self.target.read_text(vpath)
        if content is None:
            return

        is_root = user == "root" or vpath.startswith("/root/")

        for line_no, raw_line in enumerate(content.splitlines(), start=1):
            parsed = parse_authorized_keys_line(raw_line)
            if not parsed:
                continue

            options = parsed["options"]
            key_type = parsed["key_type"]
            key_blob = parsed["key_blob"]
            comment = parsed["comment"]

            flags: list[str] = ["SSH_AUTHORIZED_KEY_PRESENT"]
            if is_root:
                flags.append("ROOT_AUTHORIZED_KEY")

            decoded_payload: str | None = None

            # Check forced command option
            if "command" in options:
                flags.append("SSH_FORCED_COMMAND")
                cmd_str = str(options["command"])

                if any(pat.search(cmd_str) for pat in SUSPICIOUS_TMP_PATTERNS):
                    flags.append("FORCED_COMMAND_TMP")

                if any(pat.search(cmd_str) for pat in REVERSE_SHELL_PATTERNS):
                    flags.append("REVERSE_SHELL")

                if any(pat.search(cmd_str) for pat in BASE64_EXEC_PATTERNS):
                    flags.append("BASE64_PAYLOAD")
                    b64_m = re.search(
                        r"['\"]?([A-Za-z0-9+/=]{8,})['\"]?\s*\|\s*base64", cmd_str
                    )
                    if b64_m:
                        try:
                            decoded_payload = base64.b64decode(b64_m.group(1)).decode(
                                "utf-8", errors="replace"
                            )
                        except (ValueError, binascii.Error, TypeError):
                            decoded_payload = None

                if is_root and "/home/" in cmd_str:
                    flags.append("SYSTEM_KEY_POINTS_TO_USER_HOME")
                    flags.append("CROSS_BOUNDARY_EXECUTION")

            # Check environment injection option
            if "environment" in options:
                flags.append("SSH_ENVIRONMENT_INJECTION")
                env_str = str(options["environment"])
                if "LD_PRELOAD" in env_str or "LD_LIBRARY_PATH" in env_str:
                    flags.append("ENVIRONMENT_LD_PRELOAD")

            # Check uncommon comment
            if any(pat.match(comment) for pat in UNCOMMON_COMMENT_PATTERNS):
                flags.append("UNCOMMON_SSH_KEY_COMMENT")

            # Calculate risk level
            if (
                "REVERSE_SHELL" in flags
                or "FORCED_COMMAND_TMP" in flags
                or "SYSTEM_KEY_POINTS_TO_USER_HOME" in flags
                or "ENVIRONMENT_LD_PRELOAD" in flags
            ):
                risk_level = RiskLevel.CRITICAL
            elif (
                "BASE64_PAYLOAD" in flags
                or "SSH_FORCED_COMMAND" in flags
                or "SSH_ENVIRONMENT_INJECTION" in flags
            ):
                risk_level = RiskLevel.HIGH
            elif "ROOT_AUTHORIZED_KEY" in flags or "UNCOMMON_SSH_KEY_COMMENT" in flags:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.INFO

            key_fingerprint, key_blob_prefix = get_fingerprint_and_prefix(key_blob)

            details: dict[str, Any] = {
                "user": user,
                "key_type": key_type,
                "comment": comment,
                "options": options,
                "flags": flags,
                "key_fingerprint": key_fingerprint,
                "key_blob_prefix": key_blob_prefix,
                "line_number": line_no,
            }
            if "command" in options:
                details["forced_command"] = options["command"]
            if "environment" in options:
                details["environment"] = options["environment"]

            self.findings.append(
                Finding(
                    category=CATEGORY_AUTHORIZED_KEYS,
                    risk_level=risk_level,
                    technique_id=TECHNIQUE_ID,
                    path=vpath,
                    details=details,
                    raw_content=raw_line.strip(),
                    decoded_payload=decoded_payload,
                )
            )


def analyze_ssh(target: AnalysisTarget) -> list[Finding]:
    """Analyze SSH authorized keys and daemon configuration files for persistence.

    Args:
        target: Target AnalysisTarget providing filesystem access.

    Returns:
        List of detected SSH persistence findings.
    """
    return LinuxSSHParser(target).parse()


__all__ = [
    "LinuxSSHParser",
    "analyze_ssh",
    "parse_authorized_keys_line",
    "parse_options_list",
    "parse_sshd_line",
]
