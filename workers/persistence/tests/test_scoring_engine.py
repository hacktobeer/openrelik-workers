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
"""Unit tests for the Risk Scoring Engine."""

from __future__ import annotations

import pytest

from src.utils.models import Finding, RiskLevel
from src.utils.scoring_engine import (
    ScoringEngine,
    evaluate_risk_level,
    score_and_rank_findings,
)


def test_score_finding_001_exact_schema():
    """Verify Section 4.1 FINDING-001 ranking and ID assignment."""
    finding = Finding(
        category="cross_boundary_systemd",
        risk_level=RiskLevel.INFO,  # Initial risk before scoring
        technique_id="T1543.002",
        path="/etc/systemd/system/nginx-helper.service",
        details={
            "service_name": "nginx-helper.service",
            "exec_start": "/home/www-data/.local/bin/helper_daemon --background",
            "system_config_path": "/etc/systemd/system/nginx-helper.service",
            "target_binary_owner": "www-data",
            "target_binary_path": "/home/www-data/.local/bin/helper_daemon",
            "flags": [
                "SYSTEM_SERVICE_POINTS_TO_USER_HOME",
                "NON_ROOT_USER_PATH",
            ],
        },
        raw_content="[Service]\nExecStart=/home/www-data/.local/bin/helper_daemon --background\nUser=root\n",
    )

    ranked = score_and_rank_findings([finding])

    assert len(ranked) == 1
    scored = ranked[0]
    assert scored.id == "FINDING-001"
    assert scored.risk_level == RiskLevel.CRITICAL
    assert scored.category == "cross_boundary_systemd"


@pytest.mark.parametrize(
    "flag",
    [
        "SYSTEM_SERVICE_POINTS_TO_USER_HOME",
        "SYSTEM_CRON_POINTS_TO_USER_HOME",
        "CROSS_BOUNDARY_USER_HOME_EXECUTION",
        "LD_SO_PRELOAD_ENTRY",
        "REVERSE_SHELL_PATTERN",
        "PAM_PERMIT_AUTH_BYPASS",
    ],
)
def test_critical_flags_promotion(flag):
    finding = Finding(
        path="/etc/security/pam_config",
        details={"flags": [flag]},
    )
    assert evaluate_risk_level(finding) == RiskLevel.CRITICAL


def test_critical_system_service_temp_execution():
    finding = Finding(
        category="systemd_service",
        path="/etc/systemd/system/miner.service",
        details={"flags": ["SUSPICIOUS_PATH_TMP"]},
    )
    assert evaluate_risk_level(finding) == RiskLevel.CRITICAL

    finding_cron = Finding(
        category="cron_job",
        path="/etc/cron.d/job",
        details={"flags": ["CRON_EXECUTES_FROM_TMP"]},
    )
    assert evaluate_risk_level(finding_cron) == RiskLevel.CRITICAL


@pytest.mark.parametrize(
    "flag",
    [
        "BASE64_PAYLOAD",
        "OBFUSCATED_COMMAND",
        "DOWNLOAD_CRADLE",
        "PROMPT_COMMAND_HOOK",
        "SUDOERS_NOPASSWD",
        "SSH_FORCED_COMMAND",
        "SSHD_AUTHORIZED_KEYS_COMMAND",
        "PAM_EXEC_HOOK",
        "HIDDEN_PATH_EXECUTION",
    ],
)
def test_high_flags_promotion(flag):
    finding = Finding(
        path="/home/user/.bashrc",
        details={"flags": [flag]},
    )
    assert evaluate_risk_level(finding) == RiskLevel.HIGH


@pytest.mark.parametrize(
    "flag",
    [
        "ROOT_AUTHORIZED_KEY",
        "SSHD_PERMIT_ROOT_LOGIN",
        "USER_SYSTEMD_UNIT",
        "USER_XDG_AUTOSTART",
        "RC_LOCAL_ACTIVE_COMMANDS",
        "REBOOT_PERSISTENCE",
    ],
)
def test_medium_flags_promotion(flag):
    finding = Finding(
        path="/home/user/.config/autostart/app.desktop",
        details={"flags": [flag]},
    )
    assert evaluate_risk_level(finding) == RiskLevel.MEDIUM


def test_info_flags():
    finding = Finding(
        path="/home/user/.ssh/authorized_keys",
        details={"flags": ["SSH_AUTHORIZED_KEY_PRESENT"]},
    )
    assert evaluate_risk_level(finding) == RiskLevel.INFO

    finding_empty = Finding(path="/etc/motd", details={})
    assert evaluate_risk_level(finding_empty) == RiskLevel.INFO


def test_deduplication():
    f1 = Finding(
        path="/etc/systemd/system/service1.service",
        category="systemd_service",
        raw_content="[Service]\nExecStart=/bin/true\n",
        details={"flags": ["INFO_FLAG"]},
    )
    f2 = Finding(
        path="/etc/systemd/system/service1.service",
        category="systemd_service",
        raw_content="[Service]\nExecStart=/bin/true\n",
        details={"flags": ["INFO_FLAG"]},
    )
    f3 = Finding(
        path="/etc/systemd/system/service2.service",
        category="systemd_service",
        raw_content="[Service]\nExecStart=/bin/false\n",
    )

    ranked = score_and_rank_findings([f1, f2, f3])
    assert len(ranked) == 2
    assert ranked[0].id == "FINDING-001"
    assert ranked[1].id == "FINDING-002"


def test_sorting_order_and_id_assignment():
    f_info = Finding(
        path="/home/user/.ssh/authorized_keys",
        details={"flags": ["SSH_AUTHORIZED_KEY_PRESENT"]},
    )
    f_med = Finding(
        path="/etc/rc.local",
        details={"flags": ["RC_LOCAL_ACTIVE_COMMANDS"]},
    )
    f_high = Finding(
        path="/home/user/.bashrc",
        details={"flags": ["BASE64_PAYLOAD"]},
    )
    f_crit_b = Finding(
        path="/etc/systemd/system/z_service.service",
        category="cross_boundary_systemd",
        details={"flags": ["SYSTEM_SERVICE_POINTS_TO_USER_HOME"]},
    )
    f_crit_a = Finding(
        path="/etc/systemd/system/a_service.service",
        category="cross_boundary_systemd",
        details={"flags": ["SYSTEM_SERVICE_POINTS_TO_USER_HOME"]},
    )

    # Pass in random unsorted order
    ranked = score_and_rank_findings([f_info, f_crit_b, f_med, f_high, f_crit_a])

    assert len(ranked) == 5
    assert ranked[0].id == "FINDING-001"
    assert ranked[0].risk_level == RiskLevel.CRITICAL
    assert ranked[0].path == "/etc/systemd/system/a_service.service"

    assert ranked[1].id == "FINDING-002"
    assert ranked[1].risk_level == RiskLevel.CRITICAL
    assert ranked[1].path == "/etc/systemd/system/z_service.service"

    assert ranked[2].id == "FINDING-003"
    assert ranked[2].risk_level == RiskLevel.HIGH
    assert ranked[2].path == "/home/user/.bashrc"

    assert ranked[3].id == "FINDING-004"
    assert ranked[3].risk_level == RiskLevel.MEDIUM
    assert ranked[3].path == "/etc/rc.local"

    assert ranked[4].id == "FINDING-005"
    assert ranked[4].risk_level == RiskLevel.INFO
    assert ranked[4].path == "/home/user/.ssh/authorized_keys"


def test_scoring_engine_class_methods():
    findings = [
        Finding(
            category="cross_boundary_systemd",
            path="/etc/systemd/system/helper.service",
            details={"flags": ["SYSTEM_SERVICE_POINTS_TO_USER_HOME"]},
        ),
        Finding(
            category="shell_rc_injection",
            path="/home/user/.bashrc",
            details={"flags": ["BASE64_PAYLOAD"]},
        ),
    ]

    evaluated = ScoringEngine.evaluate(findings)
    assert len(evaluated) == 2
    assert evaluated[0].id == "FINDING-001"

    summary = ScoringEngine.get_summary(evaluated)
    assert summary["total_findings"] == 2
    assert summary["risk_counts"]["CRITICAL"] == 1
    assert summary["risk_counts"]["HIGH"] == 1
    assert summary["risk_counts"]["MEDIUM"] == 0
    assert summary["risk_counts"]["INFO"] == 0
    assert summary["category_counts"]["cross_boundary_systemd"] == 1
    assert summary["category_counts"]["shell_rc_injection"] == 1
