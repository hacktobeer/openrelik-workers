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
"""Linux cron and anacron persistence parser submodule (MITRE ATT&CK T1053.003)."""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
from typing import Any

from src.utils.models import AnalysisTarget, Finding, RiskLevel

# MITRE ATT&CK Technique ID
TECHNIQUE_ID: str = "T1053.003"

# Common regex patterns for threat detection in cron jobs
ENV_VAR_REGEX: re.Pattern[str] = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
TMP_DEV_SHM_REGEX: re.Pattern[str] = re.compile(r"/(?:tmp|var/tmp|dev/shm)(?:/|\b)")
HIDDEN_PATH_REGEX: re.Pattern[str] = re.compile(r"/\.[a-zA-Z0-9_][a-zA-Z0-9_.-]*")
USER_HOME_REGEX: re.Pattern[str] = re.compile(r"/home/([^/\s'\">]+)(/[^\s'\">]*)?")

REVERSE_SHELL_REGEX: re.Pattern[str] = re.compile(
    r"(?:"
    r"/dev/(?:tcp|udp)/\S+|"
    r"\b(?:ba|z)?sh\s+-i\b|"
    r"\b(?:nc|ncat|netcat)(?:\.traditional|\.openbsd)?\s+.*-(?:e|c)\s+|"
    r"\b(?:nc|ncat|netcat)(?:\.traditional|\.openbsd)?\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+|"
    r"\bnc\s+|\bncat\s+|\bnetcat\s+|"
    r"\bmkfifo\s+|"
    r"\bsocat\s+|"
    r"python[0-9.]*\s+-[a-zA-Z]*c.*socket|"
    r"perl\s+-[a-zA-Z]*e.*socket|"
    r"ruby\s+-[a-zA-Z]*e.*socket"
    r")",
    re.IGNORECASE | re.DOTALL,
)

DOWNLOAD_CRADLE_REGEX: re.Pattern[str] = re.compile(
    r"(?:"
    r"(?:curl|wget)\b[^|;\n\r]*\|\s*(?:/bin/)?(?:ba|z)?sh|"
    r"(?:curl|wget)\b[^|;\n\r]*\|\s*python[0-9.]*|"
    r"(?:curl|wget)\b[^\n\r]*(?:-O|-o|--output|>)\s*(?:/tmp|/var/tmp|/dev/shm)/|"
    r"(?:curl|wget)\b[^\n\r]*(?:/tmp|/var/tmp|/dev/shm)/[^\s'\">]+|"
    r"\bfetch\b[^|;\n\r]*\|\s*(?:/bin/)?(?:ba|z)?sh"
    r")",
    re.IGNORECASE,
)

OBFUSCATION_INDICATORS: re.Pattern[str] = re.compile(
    r"(?:"
    r"\\x[0-9a-fA-F]{2}|"
    r"\\[0-7]{3}|"
    r"\$\{IFS\}|\$IFS|"
    r"\beval\s+\$|"
    r"base64\s+-(?:d|-decode)|"
    r"b64decode"
    r")"
)


def _try_b64decode(payload: str) -> str | None:
    """Attempt to decode a potential base64 string into readable text.

    Args:
        payload: Base64 candidate string.

    Returns:
        Decoded UTF-8 string if valid and printable, or None.
    """
    try:
        clean = payload.strip().strip("'\"")
        missing_padding = len(clean) % 4
        if missing_padding:
            clean += "=" * (4 - missing_padding)
        data = base64.b64decode(clean)
        text = data.decode("utf-8")
        if not text.strip():
            return None
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        if printable / max(len(text), 1) >= 0.8:
            return text
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    return None


def extract_and_decode_base64(text: str) -> tuple[str | None, str | None]:
    """Extract base64 encoded strings and decode them.

    Args:
        text: Shell command or script snippet to inspect.

    Returns:
        Tuple of (raw_base64_string, decoded_payload_string) or (None, None).
    """
    # 1. echo '...' | base64 -d
    pipe_match = re.search(
        r"(?:echo|printf)\s+(?:-n\s+)?['\"]?([A-Za-z0-9+/=]{8,})['\"]?\s*\|\s*base64(?:\s+-(?:d|-decode))?",
        text,
        re.IGNORECASE,
    )
    if pipe_match:
        b64_str = pipe_match.group(1)
        decoded = _try_b64decode(b64_str)
        if decoded:
            return b64_str, decoded

    # 2. base64 -d <<< "..."
    here_match = re.search(
        r"base64\s+-(?:d|-decode)[^|]*<<<\s*['\"]?([A-Za-z0-9+/=]{8,})['\"]?",
        text,
        re.IGNORECASE,
    )
    if here_match:
        b64_str = here_match.group(1)
        decoded = _try_b64decode(b64_str)
        if decoded:
            return b64_str, decoded

    # 3. Python b64decode('...')
    py_match = re.search(
        r"b64decode\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)",
        text,
        re.IGNORECASE,
    )
    if py_match:
        b64_str = py_match.group(1)
        decoded = _try_b64decode(b64_str)
        if decoded:
            return b64_str, decoded

    # 4. If 'base64' is referenced in text, check any quoted string
    if "base64" in text.lower():
        for candidate in re.findall(r"['\"]([A-Za-z0-9+/=]{12,})['\"]", text):
            decoded = _try_b64decode(candidate)
            if decoded:
                return candidate, decoded

    # 5. Plausible standalone base64 tokens with high length
    for candidate in re.findall(
        r"(?:^|[\s\'\"])([A-Za-z0-9+/]{20,}={0,2})(?:[\s\'\"]|$)", text
    ):
        decoded = _try_b64decode(candidate)
        if decoded and len(decoded.strip()) >= 5:
            return candidate, decoded

    return None, None


class LinuxCronParser:
    """Parser and threat analyzer for Linux crontabs and scheduled tasks."""

    def parse(self, target: AnalysisTarget) -> list[Finding]:
        """Analyze cron and anacron persistence artifacts on the given target.

        Args:
            target: The analysis target (mounted filesystem or loose artifacts).

        Returns:
            List of findings representing scheduled tasks and persistence anomalies.
        """
        findings: list[Finding] = []
        processed_paths: set[str] = set()

        # 1. System crontabs (/etc/crontab, /etc/cron.d/*)
        if target.exists("/etc/crontab"):
            findings.extend(self._parse_system_crontab(target, "/etc/crontab"))
            processed_paths.add("/etc/crontab")

        for path in target.glob("/etc/cron.d/*"):
            if path not in processed_paths:
                findings.extend(self._parse_system_crontab(target, path))
                processed_paths.add(path)

        # 2. Anacrontab (/etc/anacrontab)
        if target.exists("/etc/anacrontab"):
            findings.extend(self._parse_anacrontab(target, "/etc/anacrontab"))
            processed_paths.add("/etc/anacrontab")

        # 3. User crontabs (/var/spool/cron/crontabs/*, /var/spool/cron/*)
        for path in target.glob("/var/spool/cron/crontabs/*"):
            if path not in processed_paths:
                findings.extend(self._parse_user_crontab(target, path))
                processed_paths.add(path)

        for path in target.glob("/var/spool/cron/*"):
            # Skip the directory /var/spool/cron/crontabs itself
            if posixpath.basename(path) == "crontabs":
                continue
            if path not in processed_paths:
                findings.extend(self._parse_user_crontab(target, path))
                processed_paths.add(path)

        # 4. Periodic script directories (/etc/cron.hourly/*, etc.)
        for period in ("hourly", "daily", "weekly", "monthly"):
            pattern = f"/etc/cron.{period}/*"
            for path in target.glob(pattern):
                if path not in processed_paths:
                    findings.extend(self._parse_cron_script(target, path, period))
                    processed_paths.add(path)

        return findings

    def _parse_system_crontab(
        self,
        target: AnalysisTarget,
        virtual_path: str,
    ) -> list[Finding]:
        """Parse system crontabs (/etc/crontab and /etc/cron.d/*).

        Args:
            target: Analysis target providing filesystem access.
            virtual_path: Virtual path of the system crontab file.

        Returns:
            List of findings generated from crontab lines.
        """
        content = target.read_text(virtual_path)
        if content is None:
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if ENV_VAR_REGEX.match(stripped):
                continue

            schedule = ""
            user = "root"
            command = ""

            # Check special schedules: @reboot, @daily, etc.
            if stripped.startswith("@"):
                parts = stripped.split(None, 2)
                if len(parts) >= 3:
                    schedule = parts[0]
                    user = parts[1]
                    command = parts[2]
                elif len(parts) == 2:
                    schedule = parts[0]
                    user = "root"
                    command = parts[1]
                else:
                    continue
            else:
                parts = stripped.split(None, 6)
                if len(parts) >= 7:
                    schedule = " ".join(parts[:5])
                    user = parts[5]
                    command = parts[6]
                elif len(parts) == 6:
                    schedule = " ".join(parts[:5])
                    user = "root"
                    command = parts[5]
                else:
                    continue

            finding = self._build_finding(
                virtual_path=virtual_path,
                schedule=schedule,
                user=user,
                command=command,
                raw_content=line,
                is_system_context=True,
                default_category="cron_job",
            )
            findings.append(finding)

        return findings

    def _parse_anacrontab(
        self,
        target: AnalysisTarget,
        virtual_path: str,
    ) -> list[Finding]:
        """Parse /etc/anacrontab period/delay/job-id/command entries.

        Args:
            target: Analysis target providing filesystem access.
            virtual_path: Virtual path of the anacrontab file.

        Returns:
            List of findings from anacrontab entries.
        """
        content = target.read_text(virtual_path)
        if content is None:
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if ENV_VAR_REGEX.match(stripped):
                continue

            parts = stripped.split(None, 3)
            if len(parts) < 4:
                continue

            period, delay, job_id, command = parts
            schedule = f"period={period}, delay={delay}"
            user = "root"

            extra_details: dict[str, Any] = {
                "period": period,
                "delay": delay,
                "job_id": job_id,
            }

            finding = self._build_finding(
                virtual_path=virtual_path,
                schedule=schedule,
                user=user,
                command=command,
                raw_content=line,
                is_system_context=True,
                default_category="anacron_job",
                extra_details=extra_details,
            )
            findings.append(finding)

        return findings

    def _parse_user_crontab(
        self,
        target: AnalysisTarget,
        virtual_path: str,
    ) -> list[Finding]:
        """Parse user crontabs (/var/spool/cron/crontabs/* and /var/spool/cron/*).

        Args:
            target: Analysis target providing filesystem access.
            virtual_path: Virtual path of the user crontab file.

        Returns:
            List of findings parsed from the user crontab.
        """
        content = target.read_text(virtual_path)
        if content is None:
            return []

        # Derive user from the filename
        default_user = posixpath.basename(virtual_path)
        is_root_crontab = default_user == "root"

        findings: list[Finding] = []
        lines = content.splitlines()

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if ENV_VAR_REGEX.match(stripped):
                continue

            schedule = ""
            user = default_user
            command = ""

            if stripped.startswith("@"):
                parts = stripped.split(None, 1)
                schedule = parts[0]
                command = parts[1] if len(parts) > 1 else ""
            else:
                parts = stripped.split(None, 5)
                if len(parts) >= 6:
                    schedule = " ".join(parts[:5])
                    command = parts[5]
                elif len(parts) >= 5:
                    schedule = " ".join(parts[:5])
                    command = ""
                else:
                    continue

            finding = self._build_finding(
                virtual_path=virtual_path,
                schedule=schedule,
                user=user,
                command=command,
                raw_content=line,
                is_system_context=is_root_crontab,
                default_category="cron_job",
            )
            findings.append(finding)

        return findings

    def _parse_cron_script(
        self,
        target: AnalysisTarget,
        virtual_path: str,
        period: str,
    ) -> list[Finding]:
        """Parse scripts in /etc/cron.hourly/, /etc/cron.daily/, etc.

        Args:
            target: Analysis target providing filesystem access.
            virtual_path: Virtual path of the cron script file.
            period: Cron execution periodicity string (e.g. 'daily', 'hourly').

        Returns:
            List containing generated finding if script is present and non-empty.
        """
        content = target.read_text(virtual_path)
        if content is None:
            return []

        # Skip empty files or files that are solely whitespace
        stripped = content.strip()
        if not stripped:
            return []

        user = "root"
        schedule = period
        command = virtual_path

        extra_details: dict[str, Any] = {
            "script_path": virtual_path,
        }

        # Check if virtual_path is a symlink
        symlink_target = target.resolve_symlink(virtual_path)
        if symlink_target:
            extra_details["symlink_target"] = symlink_target

        finding = self._build_finding(
            virtual_path=virtual_path,
            schedule=schedule,
            user=user,
            command=command,
            raw_content=content,
            is_system_context=True,
            default_category="cron_script",
            extra_details=extra_details,
            script_body=content,
        )
        return [finding]

    def _build_finding(
        self,
        virtual_path: str,
        schedule: str,
        user: str,
        command: str,
        raw_content: str,
        is_system_context: bool,
        default_category: str,
        extra_details: dict[str, Any] | None = None,
        script_body: str | None = None,
    ) -> Finding:
        """Evaluate heuristic flags, risk levels, and construct a Finding object.

        Args:
            virtual_path: Virtual path of the cron artifact.
            schedule: Cron schedule string.
            user: Associated username.
            command: Command string executed by the cron job.
            raw_content: Raw configuration line or script text.
            is_system_context: Whether executed in system/root context.
            default_category: Fallback finding category name.
            extra_details: Optional dictionary of additional metadata.
            script_body: Optional entire script content if analyzing a script file.

        Returns:
            Constructed Finding object with heuristic flags and risk level.
        """
        flags: list[str] = []
        details: dict[str, Any] = {
            "schedule": schedule,
            "user": user,
            "command": command,
            "flags": flags,
        }
        if extra_details:
            details.update(extra_details)

        analysis_text = f"{command} {virtual_path}"
        if script_body:
            analysis_text += f"\n{script_body}"
        if extra_details and "symlink_target" in extra_details:
            analysis_text += f" {extra_details['symlink_target']}"

        # 1. Base64 payload & obfuscation check
        _, decoded_payload = extract_and_decode_base64(analysis_text)
        if decoded_payload is not None:
            flags.append("BASE64_PAYLOAD")
            flags.append("OBFUSCATED_COMMAND")

        if "OBFUSCATED_COMMAND" not in flags and OBFUSCATION_INDICATORS.search(
            analysis_text
        ):
            flags.append("OBFUSCATED_COMMAND")

        combined_text = analysis_text
        if decoded_payload:
            combined_text += f"\n{decoded_payload}"

        # 2. Reverse shell detection
        if REVERSE_SHELL_REGEX.search(combined_text):
            flags.append("REVERSE_SHELL_PATTERN")

        # 3. Download cradle detection
        if DOWNLOAD_CRADLE_REGEX.search(combined_text):
            flags.append("DOWNLOAD_CRADLE")

        # 4. Execution from /tmp, /var/tmp, or /dev/shm
        if TMP_DEV_SHM_REGEX.search(combined_text):
            flags.append("EXEC_FROM_TMP_OR_DEV_SHM")

        # 5. Hidden path execution (/.hidden_file or /.hidden_dir)
        if HIDDEN_PATH_REGEX.search(combined_text) or posixpath.basename(
            virtual_path
        ).startswith("."):
            flags.append("HIDDEN_PATH_EXECUTION")

        # 6. Reboot persistence
        if "@reboot" in schedule:
            flags.append("REBOOT_PERSISTENCE")

        # 7. Cross-boundary execution (/home/* execution under system context)
        # Applies when system cron executes a script/binary inside /home/<user>/*
        home_match = USER_HOME_REGEX.search(combined_text)
        if is_system_context and home_match:
            flags.append("SYSTEM_CRON_POINTS_TO_USER_HOME")
            flags.append("NON_ROOT_USER_PATH")
            details["target_binary_path"] = home_match.group(0)
            details["target_binary_owner"] = home_match.group(1)

        # 8. High frequency schedule
        if schedule.strip() == "* * * * *":
            flags.append("CRON_SCHEDULE_HIGH_FREQUENCY")

        # Category determination
        if "SYSTEM_CRON_POINTS_TO_USER_HOME" in flags:
            category = "cross_boundary_cron"
        else:
            category = default_category

        # Risk level determination
        if (
            "SYSTEM_CRON_POINTS_TO_USER_HOME" in flags
            or "REVERSE_SHELL_PATTERN" in flags
        ):
            risk_level = RiskLevel.CRITICAL
        elif any(
            f in flags
            for f in (
                "EXEC_FROM_TMP_OR_DEV_SHM",
                "BASE64_PAYLOAD",
                "OBFUSCATED_COMMAND",
                "DOWNLOAD_CRADLE",
                "HIDDEN_PATH_EXECUTION",
            )
        ):
            risk_level = RiskLevel.HIGH
        elif any(
            f in flags
            for f in (
                "REBOOT_PERSISTENCE",
                "CRON_SCHEDULE_HIGH_FREQUENCY",
            )
        ):
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.INFO

        return Finding(
            id="",
            category=category,
            risk_level=risk_level,
            technique_id=TECHNIQUE_ID,
            path=virtual_path,
            details=details,
            raw_content=raw_content,
            decoded_payload=decoded_payload,
        )


def analyze_cron(target: AnalysisTarget) -> list[Finding]:
    """Analyze Linux cron and anacron persistence mechanisms on an AnalysisTarget.

    Args:
        target: The target filesystem or staging collection.

    Returns:
        List of persistence findings.
    """
    return LinuxCronParser().parse(target)


__all__ = [
    "LinuxCronParser",
    "analyze_cron",
    "extract_and_decode_base64",
]
