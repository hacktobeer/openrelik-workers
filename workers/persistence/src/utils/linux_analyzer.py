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
"""Linux Persistence Analyzer Orchestrator.

Coordinates all Linux persistence vector parsers, cross-boundary correlation,
operating system / hostname detection, risk scoring, ranking, and report metadata generation.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime

from src.utils.linux_autostart import analyze_autostart
from src.utils.linux_cron import analyze_cron
from src.utils.linux_cross_boundary import analyze_cross_boundary
from src.utils.linux_init import analyze_init
from src.utils.linux_ld_preload import analyze_ld_preload
from src.utils.linux_pam_sudoers import analyze_pam_sudoers
from src.utils.linux_shell_profiles import analyze_shell_profiles
from src.utils.linux_ssh import analyze_ssh
from src.utils.linux_systemd import analyze_systemd
from src.utils.models import AnalysisTarget, Finding, ReportMeta, RiskLevel
from src.utils.os_detector import detect_os_and_hostname
from src.utils.scoring_engine import score_and_rank_findings

logger: logging.Logger = logging.getLogger(__name__)

RISK_LEVEL_ORDER: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 4,
    RiskLevel.HIGH: 3,
    RiskLevel.MEDIUM: 2,
    RiskLevel.INFO: 1,
}


def _parse_min_risk_level(level: str | RiskLevel | None) -> RiskLevel | None:
    """Parse and normalize min_risk_level into a RiskLevel enum, or None.

    Args:
        level: Raw minimum risk level input (string, RiskLevel enum, or None).

    Returns:
        Normalized RiskLevel enum value, or None if level is None or invalid.
    """
    if level is None:
        return None
    if isinstance(level, RiskLevel):
        return level
    cleaned = str(level).strip().upper()
    try:
        return RiskLevel(cleaned)
    except ValueError:
        logger.warning("Unrecognized min_risk_level '%s', ignoring filter", level)
        return None


def _get_risk_score(risk_level: str | RiskLevel) -> int:
    """Return numeric severity score for a given RiskLevel or string.

    Args:
        risk_level: RiskLevel enum or case-insensitive severity string.

    Returns:
        Integer score between 1 (INFO) and 4 (CRITICAL), or 0 if unrecognized.
    """
    if isinstance(risk_level, RiskLevel):
        return RISK_LEVEL_ORDER.get(risk_level, 0)
    try:
        return RISK_LEVEL_ORDER.get(RiskLevel(str(risk_level).upper()), 0)
    except ValueError:
        return 0


def analyze_linux_target(target: AnalysisTarget) -> list[Finding]:
    """Analyze a single Linux target using all registered parsers and cross-boundary correlation.

    Invokes each parser in sequence, safely catching and logging unexpected errors so
    one parser failure does not abort the remaining parsers, and finally executes
    cross-boundary correlation.

    Args:
        target: The target filesystem abstraction (mounted image or extracted files).

    Returns:
        List of findings detected on the target.
    """
    findings: list[Finding] = []

    parsers: list[tuple[str, Callable[[AnalysisTarget], list[Finding]]]] = [
        ("systemd", analyze_systemd),
        ("cron", analyze_cron),
        ("shell_profiles", analyze_shell_profiles),
        ("ssh", analyze_ssh),
        ("init", analyze_init),
        ("ld_preload", analyze_ld_preload),
        ("pam_sudoers", analyze_pam_sudoers),
        ("autostart", analyze_autostart),
    ]

    for name, parser in parsers:
        try:
            results = parser(target)
            if results:
                findings.extend(results)
        except Exception:
            logger.exception("Error executing parser '%s' on target", name)

    try:
        findings = analyze_cross_boundary(target, existing_findings=findings)
    except Exception:
        logger.exception("Error executing cross-boundary analysis on target")

    return findings


def run_linux_persistence_analysis(
    targets: list[AnalysisTarget],
    min_risk_level: str | RiskLevel | None = None,
) -> tuple[ReportMeta, list[Finding]]:
    """Run full persistence analysis across one or more Linux analysis targets.

    Iterates over targets, detects OS name and hostname (recording the first
    non-'unknown' hostname), collects findings from each target, scores and ranks
    them via the scoring engine, optionally filters by minimum risk level,
    generates ReportMeta, and returns (meta, scored_findings).

    Args:
        targets: List of AnalysisTarget instances to analyze.
        min_risk_level: Optional minimum severity threshold (e.g. 'HIGH' or RiskLevel.HIGH).

    Returns:
        A tuple of (ReportMeta, list[Finding]).
    """
    hostname = "unknown"
    os_name = "linux"
    all_findings: list[Finding] = []

    for target in targets:
        cur_os, cur_host = detect_os_and_hostname(target)
        if hostname == "unknown" and cur_host and cur_host != "unknown":
            hostname = cur_host
        if cur_os and cur_os != "unknown":
            os_name = cur_os

        target_findings = analyze_linux_target(target)
        all_findings.extend(target_findings)

    scored_findings = score_and_rank_findings(all_findings)

    if min_risk_level is not None:
        parsed_min = _parse_min_risk_level(min_risk_level)
        if parsed_min is not None:
            min_score = RISK_LEVEL_ORDER[parsed_min]
            scored_findings = [
                f for f in scored_findings if _get_risk_score(f.risk_level) >= min_score
            ]
            for idx, finding in enumerate(scored_findings, start=1):
                finding.id = f"FINDING-{idx:03d}"

    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = ReportMeta(
        os=os_name,
        hostname=hostname,
        analysis_timestamp=timestamp,
        total_findings=len(scored_findings),
    )

    return meta, scored_findings


class LinuxPersistenceAnalyzer:
    """Orchestrator class for Linux persistence analysis."""

    def __init__(self, target: AnalysisTarget | None = None) -> None:
        """Initialize with an optional default target.

        Args:
            target: Optional AnalysisTarget to associate with this analyzer instance.
        """
        self.target: AnalysisTarget | None = target

    def analyze_target(self, target: AnalysisTarget) -> list[Finding]:
        """Analyze a single Linux target.

        Args:
            target: The AnalysisTarget to inspect.

        Returns:
            List of detected persistence findings.
        """
        return analyze_linux_target(target)

    def analyze_targets(
        self,
        targets: list[AnalysisTarget],
        min_risk_level: str | RiskLevel | None = None,
    ) -> tuple[ReportMeta, list[Finding]]:
        """Analyze multiple Linux targets, score, rank, and generate metadata.

        Args:
            targets: List of AnalysisTarget instances to inspect.
            min_risk_level: Optional minimum risk severity threshold.

        Returns:
            Tuple of (ReportMeta, scored findings list).
        """
        return run_linux_persistence_analysis(targets, min_risk_level=min_risk_level)

    def analyze(self, target: AnalysisTarget | None = None) -> list[Finding]:
        """Convenience method to analyze a target.

        Args:
            target: Optional target to analyze, defaults to self.target.

        Returns:
            List of detected persistence findings.

        Raises:
            ValueError: If no target is provided and self.target is None.
        """
        t = target or self.target
        if t is None:
            raise ValueError("No target provided to analyze()")
        return self.analyze_target(t)


# Alias LinuxAnalyzer to LinuxPersistenceAnalyzer
LinuxAnalyzer = LinuxPersistenceAnalyzer

__all__ = [
    "LinuxAnalyzer",
    "LinuxPersistenceAnalyzer",
    "analyze_linux_target",
    "run_linux_persistence_analysis",
]
