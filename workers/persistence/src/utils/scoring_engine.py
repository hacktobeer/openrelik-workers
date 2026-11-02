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
"""Forensic risk scoring, ranking, and deduplication engine."""

from __future__ import annotations

from typing import Any

from src.utils.models import Finding, RiskLevel

CRITICAL_FLAGS: set[str] = {
    "SYSTEM_SERVICE_POINTS_TO_USER_HOME",
    "SYSTEM_CRON_POINTS_TO_USER_HOME",
    "CROSS_BOUNDARY_USER_HOME_EXECUTION",
    "CROSS_BOUNDARY_EXECUTION",
    "CROSS_BOUNDARY_TEMP_EXECUTION",
    "LD_SO_PRELOAD_ENTRY",
    "LD_PRELOAD_FILE_PRESENT",
    "PRELOAD_SHARED_OBJECT_IN_USER_PATH",
    "REVERSE_SHELL_PATTERN",
    "REVERSE_SHELL",
    "CRON_REVERSE_SHELL",
    "PAM_PERMIT_AUTH_BYPASS",
}

HIGH_FLAGS: set[str] = {
    "BASE64_PAYLOAD",
    "OBFUSCATED_COMMAND",
    "DOWNLOAD_CRADLE",
    "CURL_PIPE_EXEC",
    "CRON_DOWNLOAD_AND_EXECUTE",
    "PROMPT_COMMAND_HOOK",
    "PROMPT_COMMAND_INJECTION",
    "SUDOERS_NOPASSWD",
    "SUDOERS_NOPASSWD_ALL",
    "SUDOERS_TARGETS_USER_DIR",
    "SSH_FORCED_COMMAND",
    "SSHD_AUTHORIZED_KEYS_COMMAND",
    "PAM_EXEC_HOOK",
    "HIDDEN_PATH_EXECUTION",
    "HIDDEN_FILE_OR_DIR",
    "SUSPICIOUS_SCRIPT_EXECUTION",
    "NETWORK_UTILITY_IN_EXEC",
}

MEDIUM_FLAGS: set[str] = {
    "ROOT_AUTHORIZED_KEY",
    "ROOT_SSH_KEY_ADDED",
    "SSHD_PERMIT_ROOT_LOGIN",
    "USER_SYSTEMD_UNIT",
    "USER_XDG_AUTOSTART",
    "RC_LOCAL_ACTIVE_COMMANDS",
    "RC_LOCAL_ACTIVE_PAYLOAD",
    "REBOOT_PERSISTENCE",
    "UNCOMMON_SSH_KEY_COMMENT",
    "CRON_SCHEDULE_HIGH_FREQUENCY",
    "NON_STANDARD_AUTHORIZED_KEYS_FILE",
}

INFO_FLAGS: set[str] = {
    "SSH_AUTHORIZED_KEY_PRESENT",
    "STANDARD_CRON_JOB",
    "STANDARD_AUTOSTART",
}

SEVERITY_ORDER: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.HIGH: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.INFO: 3,
}

LEVEL_SCORE: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 4,
    RiskLevel.HIGH: 3,
    RiskLevel.MEDIUM: 2,
    RiskLevel.INFO: 1,
}


def _extract_finding_flags(finding: Finding) -> set[str]:
    """Extract all flag strings from finding details.

    Args:
        finding: The finding object to inspect.

    Returns:
        Set of uppercase string flag identifiers.
    """
    raw = finding.details.get("flags", [])
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, (list, tuple, set)):
        return {str(item) for item in raw}
    return set()


def evaluate_risk_level(finding: Finding) -> RiskLevel:
    """Evaluate flags and category to determine appropriate RiskLevel.

    Args:
        finding: The finding object to evaluate.

    Returns:
        Assigned RiskLevel enum value.
    """
    flags = _extract_finding_flags(finding)
    cat = (finding.category or "").lower()
    path = (finding.path or "").lower()

    is_system_path = (
        path.startswith(
            ("/etc/", "/lib/", "/usr/lib/", "/var/spool/cron/", "/var/cron/")
        )
        or "system" in cat
    )
    is_system_service_or_cron = is_system_path and (
        "systemd" in cat or "cron" in cat or "systemd" in path or "cron" in path
    )

    # 1. Check CRITICAL conditions
    if cat.startswith("cross_boundary"):
        return RiskLevel.CRITICAL

    if any(f in flags for f in CRITICAL_FLAGS):
        return RiskLevel.CRITICAL

    if cat in ("ld_preload", "ld_so_preload") or "ld.so.preload" in path:
        return RiskLevel.CRITICAL

    # Execution from /dev/shm or /tmp in system services or cron
    if is_system_service_or_cron:
        temp_flags = {
            "SUSPICIOUS_PATH_TMP",
            "CRON_EXECUTES_FROM_TMP",
            "CROSS_BOUNDARY_TEMP_EXECUTION",
        }
        if flags.intersection(temp_flags):
            return RiskLevel.CRITICAL

        target_bin = str(finding.details.get("target_binary_path", "")).lower()
        exec_start = str(finding.details.get("exec_start", "")).lower()
        if any(tp in target_bin for tp in ("/dev/shm", "/tmp", "/var/tmp")) or any(
            tp in exec_start for tp in ("/dev/shm", "/tmp", "/var/tmp")
        ):
            return RiskLevel.CRITICAL

    # 2. Check HIGH conditions
    if any(f in flags for f in HIGH_FLAGS) or (
        "sudoers" in cat and "nopasswd" in str(finding.raw_content or "").lower()
    ):
        computed_high = RiskLevel.HIGH
    else:
        computed_high = None

    if computed_high is not None:
        if (
            finding.risk_level == RiskLevel.CRITICAL
            or LEVEL_SCORE.get(finding.risk_level, 0) > LEVEL_SCORE[RiskLevel.HIGH]
        ):
            return finding.risk_level
        return RiskLevel.HIGH

    # 3. Check MEDIUM conditions
    if any(f in flags for f in MEDIUM_FLAGS) or cat in (
        "user_systemd",
        "user_systemd_unit",
        "user_xdg_autostart",
        "rc_local",
    ):
        computed_medium = RiskLevel.MEDIUM
    else:
        computed_medium = None

    if computed_medium is not None:
        if LEVEL_SCORE.get(finding.risk_level, 0) > LEVEL_SCORE[RiskLevel.MEDIUM]:
            return finding.risk_level
        return RiskLevel.MEDIUM

    # 4. Check INFO conditions or retain existing higher level
    if any(f in flags for f in INFO_FLAGS):
        if LEVEL_SCORE.get(finding.risk_level, 0) > LEVEL_SCORE[RiskLevel.INFO]:
            return finding.risk_level
        return RiskLevel.INFO

    # Retain existing risk level if explicitly set to higher than INFO
    if finding.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM):
        return finding.risk_level

    return RiskLevel.INFO


def score_and_rank_findings(findings: list[Finding]) -> list[Finding]:
    """Score, deduplicate, rank, and assign sequential IDs to findings.

    Args:
        findings: Unranked list of findings from parsers or analyzers.

    Returns:
        Ranked, deduplicated list of findings sorted by severity and path,
        with sequential identifiers (FINDING-001, FINDING-002, ...).
    """
    if not findings:
        return []

    # 1. Evaluate risk level for each finding
    for finding in findings:
        finding.risk_level = evaluate_risk_level(finding)

    # 2. Deduplicate findings with identical (path, category, raw_content)
    dedup_map: dict[tuple[str, str, str | None], Finding] = {}
    for finding in findings:
        key = (finding.path or "", finding.category or "", finding.raw_content)
        if key not in dedup_map:
            dedup_map[key] = finding
        else:
            existing = dedup_map[key]
            # Retain finding with higher severity if duplicates differ
            if LEVEL_SCORE.get(finding.risk_level, 0) > LEVEL_SCORE.get(
                existing.risk_level, 0
            ):
                dedup_map[key] = finding

    unique_findings = list(dedup_map.values())

    # 3. Sort findings by severity (CRITICAL -> HIGH -> MEDIUM -> INFO) and path
    unique_findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.risk_level, 4),
            f.path or "",
        )
    )

    # 4. Assign sequential finding IDs
    for idx, finding in enumerate(unique_findings, start=1):
        finding.id = f"FINDING-{idx:03d}"

    return unique_findings


class ScoringEngine:
    """Forensic scoring and ranking engine for persistence findings."""

    @staticmethod
    def evaluate(findings: list[Finding]) -> list[Finding]:
        """Score, deduplicate, rank, and assign sequential IDs to findings.

        Args:
            findings: Unranked list of findings.

        Returns:
            Ranked and deduplicated list of findings with IDs assigned.
        """
        return score_and_rank_findings(findings)

    @staticmethod
    def get_summary(findings: list[Finding]) -> dict[str, Any]:
        """Generate summary metrics by risk level and category.

        Args:
            findings: Scored list of findings.

        Returns:
            Dictionary containing total count, risk counts, and category counts.
        """
        counts: dict[str, int] = {
            RiskLevel.CRITICAL.value: 0,
            RiskLevel.HIGH.value: 0,
            RiskLevel.MEDIUM.value: 0,
            RiskLevel.INFO.value: 0,
        }
        categories: dict[str, int] = {}
        for f in findings:
            level_str = (
                f.risk_level.value
                if isinstance(f.risk_level, RiskLevel)
                else str(f.risk_level)
            )
            counts[level_str] = counts.get(level_str, 0) + 1
            cat = f.category or "unknown"
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_findings": len(findings),
            "risk_counts": counts,
            "category_counts": categories,
        }


__all__ = [
    "ScoringEngine",
    "evaluate_risk_level",
    "score_and_rank_findings",
]
