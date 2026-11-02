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
"""Persistence report generator for JSON artifacts and OpenRelik Markdown task reports."""

from __future__ import annotations

import json
import os
from typing import Any

from openrelik_worker_common.reporting import Priority, Report

from src.utils.models import Finding, ReportMeta, RiskLevel

CATEGORY_DISPLAY_NAMES: dict[str, str] = {
    "cross_boundary_systemd": "Cross-Boundary Systemd Execution",
    "cross_boundary_cron": "Cross-Boundary Cron Execution",
    "cross_boundary_init": "Cross-Boundary Init Script Execution",
    "cross_boundary_sudoers": "Cross-Boundary Sudoers Execution",
    "cross_boundary_autostart": "Cross-Boundary Autostart Execution",
    "shell_rc_injection": "Shell RC Script Injection",
    "shell_profiles": "Shell Profile Injection",
    "ssh_authorized_keys": "SSH Authorized Keys",
    "ssh_config": "SSH Configuration",
    "systemd_service": "Systemd Service",
    "systemd_timer": "Systemd Timer",
    "systemd_user": "User Systemd Service",
    "cron_job": "Scheduled Cron Job",
    "cron_anacron": "Anacrontab Job",
    "init_script": "SysV Init Script",
    "rc_local": "RC Local Startup Script",
    "ld_preload": "Dynamic Linker Preload",
    "sudoers": "Sudoers Privileged Rule",
    "pam_module": "PAM Authentication Module",
    "xdg_autostart": "XDG Desktop Autostart",
}


def format_category_name(category: str) -> str:
    """Format a raw finding category string into a human-readable title.

    Args:
        category: Raw category identifier.

    Returns:
        Formatted human-readable category name.
    """
    if not category:
        return "Unknown"
    clean = category.strip().lower()
    if clean in CATEGORY_DISPLAY_NAMES:
        return CATEGORY_DISPLAY_NAMES[clean]
    words = clean.replace("_", " ").replace("-", " ").split()
    return " ".join(word.capitalize() for word in words)


def format_os_display(os_name: str) -> str:
    """Format the OS family string for Markdown display.

    Args:
        os_name: Raw operating system name string.

    Returns:
        Formatted OS name.
    """
    if not os_name:
        return "Unknown"
    clean = os_name.strip().lower()
    if clean == "linux":
        return "Linux"
    if clean == "windows":
        return "Windows"
    if clean in ("macos", "darwin"):
        return "macOS"
    return os_name.title()


def format_display_timestamp(timestamp: str) -> str:
    """Format an ISO-8601 or raw timestamp for Markdown presentation.

    Args:
        timestamp: Raw timestamp string.

    Returns:
        Formatted display timestamp string.
    """
    if not timestamp:
        return "N/A"
    clean = timestamp.strip()
    if "T" in clean and clean.endswith("Z"):
        return clean.replace("T", " ")[:-1] + " UTC"
    if "T" in clean and "+" in clean:
        return clean.replace("T", " ")
    return clean


def format_technique_link(technique_id: str) -> str:
    """Format a MITRE ATT&CK technique identifier as a Markdown hyperlink.

    Args:
        technique_id: MITRE ATT&CK technique identifier (e.g. 'T1543.002').

    Returns:
        Markdown link to the ATT&CK technique page.
    """
    if not technique_id:
        return "None"
    clean_id = technique_id.strip()
    url_path = clean_id.replace(".", "/")
    return f"MITRE ATT&CK [{clean_id}](https://attack.mitre.org/techniques/{url_path}/)"


def get_finding_title(finding: Finding) -> str:
    """Derive a concise, descriptive title for a finding.

    Args:
        finding: The Finding object to inspect.

    Returns:
        Human-readable title for the finding.
    """
    if finding.details.get("title"):
        return str(finding.details["title"])
    if finding.details.get("description"):
        return str(finding.details["description"])

    category = finding.category.lower()
    flags = [str(f) for f in finding.details.get("flags", [])]
    flags_set = set(flags)

    if category == "cross_boundary_systemd":
        return "Systemd Service Points to User Home Directory"
    if category == "cross_boundary_cron":
        return "Cron Job Points to User Home Directory"
    if category == "cross_boundary_init":
        return "Init Script Points to User Home Directory"
    if category == "cross_boundary_sudoers":
        return "Sudoers Rule Points to User Path"
    if category == "cross_boundary_autostart":
        return "Desktop Autostart Points to User Home Directory"

    if category in ("shell_rc_injection", "shell_profiles"):
        if "BASE64_PAYLOAD" in flags_set or finding.decoded_payload:
            return "Encoded Payload in User Shell Profile"
        if "REVERSE_SHELL" in flags_set:
            return "Reverse Shell Injected into User Shell Profile"
        if "PROMPT_COMMAND" in flags_set or "PROMPT_COMMAND_INJECTION" in flags_set:
            return "Prompt Command Hook Injected into User Shell Profile"
        return "Suspicious Shell Profile Modification"

    if category in ("ssh_authorized_keys", "ssh_config"):
        if "SSH_FORCED_COMMAND" in flags_set:
            return "SSH Authorized Key with Forced Command Execution"
        return "New SSH Public Key Added to User Directory"

    if category == "ld_preload":
        return "Dynamic Linker Preload Detected"

    if category in ("systemd_service", "systemd_timer", "systemd_user"):
        if "SUSPICIOUS_PATH_TMP" in flags_set:
            return "Systemd Service Executing from Temporary Directory"
        return "Suspicious Systemd Service Configuration"

    if category in ("cron_job", "cron_anacron"):
        if "CRON_REVERSE_SHELL" in flags_set:
            return "Cron Job with Reverse Shell Command"
        if "CRON_DOWNLOAD_AND_EXECUTE" in flags_set:
            return "Cron Job Downloading and Executing Remote Script"
        return "Suspicious Scheduled Cron Job"

    if category == "sudoers":
        return "Privileged Sudoers Configuration"
    if category == "pam_module":
        return "Non-Standard PAM Module Configuration"
    if category == "xdg_autostart":
        return "Suspicious XDG Desktop Autostart Entry"

    return format_category_name(finding.category) or "Persistence Finding"


def get_risk_explanation(finding: Finding) -> str:
    """Generate or retrieve the risk explanation for a finding.

    Args:
        finding: The Finding object to inspect.

    Returns:
        Risk explanation paragraph.
    """
    if finding.details.get("risk_explanation"):
        return str(finding.details["risk_explanation"])
    if finding.details.get("explanation"):
        return str(finding.details["explanation"])

    category = finding.category.lower()
    flags = [str(f) for f in finding.details.get("flags", [])]
    flags_set = set(flags)

    if (
        "cross_boundary" in category
        or "SYSTEM_SERVICE_POINTS_TO_USER_HOME" in flags_set
    ):
        home_path = str(
            finding.details.get("target_binary_path")
            or finding.details.get("target_executable")
            or ""
        )
        home_dir = ""
        if "/home/" in home_path:
            parts = home_path.split("/")
            if len(parts) >= 3:
                home_dir = f" (`/{parts[1]}/{parts[2]}`)"
        return (
            f"A root-level system service is configured to run a binary located inside a user's home directory{home_dir}. "
            "This allows unprivileged file modifications to alter root execution."
        )

    if "shell" in category or "BASE64_PAYLOAD" in flags_set or finding.decoded_payload:
        filename = finding.path.split("/")[-1] if "/" in finding.path else finding.path
        file_ref = f" (`{filename}`)" if filename else ""
        return (
            f"Detected a Base64-encoded execution string inside a shell startup file{file_ref}. "
            "This will automatically execute commands whenever the user logs in or starts an interactive session."
        )

    if "ssh" in category or "UNCOMMON_SSH_KEY_COMMENT" in flags_set:
        if "SSH_FORCED_COMMAND" in flags_set:
            return "SSH authorized key configured with a forced command option that executes scripts immediately upon authentication."
        return "RSA public key added without standard corporate key management tags."

    if "ld_preload" in category or "LD_PRELOAD_FILE_PRESENT" in flags_set:
        return "Dynamic linker preload file intercepts system library calls, allowing user-space rootkits or persistence hooks."

    if "sudoers" in category or "SUDOERS_NOPASSWD_ALL" in flags_set:
        return "Sudoers rule grants elevated execution permissions without password verification."

    if "cron" in category:
        return "Scheduled cron task configured to execute automatically at defined intervals."

    if "init" in category or "rc_local" in category:
        return "Legacy boot startup script configured to execute persistence commands on system startup."

    if "pam" in category:
        return "PAM authentication module configured outside standard system library directories."

    if "autostart" in category:
        return "Desktop autostart configuration launches an application upon user graphical session login."

    return f"Persistence mechanism identified in `{finding.path}` requiring forensic review."


def format_finding_code_blocks(finding: Finding) -> list[str]:
    """Format raw content and decoded payload into Markdown code blocks.

    Args:
        finding: The Finding object to format code blocks for.

    Returns:
        List of formatted Markdown code block strings.
    """
    blocks: list[str] = []
    category = finding.category.lower()
    path = finding.path.lower()
    raw = (finding.raw_content or "").strip()

    if raw:
        if (
            "systemd" in category
            or path.endswith((".service", ".timer", ".target", ".socket"))
            or "[unit]" in raw.lower()
            or "[service]" in raw.lower()
        ):
            blocks.append(f"#### Executable Configuration Details\n```ini\n{raw}\n```")
        elif (
            "shell" in category
            or "cron" in category
            or "init" in category
            or finding.decoded_payload is not None
            or path.endswith((".sh", ".bashrc", ".profile", ".zshrc", ".bash_profile"))
        ):
            blocks.append(f"#### Extracted Raw Payload\n```bash\n{raw}\n```")
        elif "ssh" in category or "authorized_keys" in path:
            blocks.append(f"```\n{raw}\n```")
        else:
            blocks.append(f"#### Configuration Details\n```\n{raw}\n```")

    if finding.decoded_payload:
        decoded = finding.decoded_payload.strip()
        blocks.append(f"#### Decoded Execution Preview\n```bash\n{decoded}\n```")

    return blocks


def render_finding_block(finding: Finding, number: int) -> str:
    """Render a single finding subsection in Markdown format.

    Args:
        finding: The Finding object to render.
        number: 1-based sequential finding index number.

    Returns:
        Rendered Markdown subsection string for the finding.
    """
    title = get_finding_title(finding)
    risk_level_str = (
        finding.risk_level.value
        if isinstance(finding.risk_level, RiskLevel)
        else str(finding.risk_level).upper()
    )

    lines = [f"### {number}. [{risk_level_str}] {title}"]

    if finding.technique_id:
        lines.append(f"* **Technique:** {format_technique_link(finding.technique_id)}")

    config_path = finding.details.get("system_config_path") or finding.path
    if config_path:
        lines.append(f"* **Configuration File:** `{config_path}`")

    target_exec = (
        finding.details.get("target_executable")
        or finding.details.get("target_binary_path")
        or finding.details.get("exec_path")
    )
    if target_exec:
        lines.append(f"* **Target Executable:** `{target_exec}`")

    if finding.details.get("target_user") or finding.details.get("user"):
        user_val = finding.details.get("target_user") or finding.details.get("user")
        lines.append(f"* **Target User:** `{user_val}`")
    elif finding.details.get("target_binary_owner") and not target_exec:
        lines.append(f"* **Target User:** `{finding.details['target_binary_owner']}`")

    key_comment = finding.details.get("key_comment") or finding.details.get("comment")
    if key_comment:
        lines.append(f"* **Key Comment:** `{key_comment}`")

    explanation = get_risk_explanation(finding)
    lines.append(f"* **Risk Explanation:** {explanation}")

    flags = finding.details.get("flags")
    if flags:
        if isinstance(flags, str):
            flags_list = [flags]
        else:
            flags_list = list(flags)
        formatted_flags = ", ".join(f"`{f}`" for f in flags_list)
        lines.append(f"* **Flags:** {formatted_flags}")

    code_blocks = format_finding_code_blocks(finding)
    for block in code_blocks:
        lines.append(f"\n{block}")

    return "\n".join(lines)


def get_highest_priority(findings: list[Finding]) -> Priority:
    """Determine Report Priority based on the highest risk finding severity.

    Args:
        findings: List of Finding objects.

    Returns:
        Priority enum value corresponding to highest severity finding.
    """
    risk_levels: set[str] = set()
    for f in findings:
        if isinstance(f.risk_level, RiskLevel):
            risk_levels.add(f.risk_level.value)
        else:
            risk_levels.add(str(f.risk_level).upper())

    if RiskLevel.CRITICAL.value in risk_levels:
        return Priority.CRITICAL
    if RiskLevel.HIGH.value in risk_levels:
        return Priority.HIGH
    if RiskLevel.MEDIUM.value in risk_levels:
        return Priority.MEDIUM
    if RiskLevel.INFO.value in risk_levels:
        return Priority.INFO
    return Priority.LOW


def get_primary_categories_for_risk(
    findings: list[Finding], risk_level: RiskLevel
) -> str:
    """Return formatted, comma-separated primary categories for a risk level.

    Args:
        findings: List of Finding objects.
        risk_level: The RiskLevel enum to match.

    Returns:
        Comma-separated string of unique category display names.
    """
    categories: list[str] = []
    seen: set[str] = set()
    for f in findings:
        rl = (
            f.risk_level
            if isinstance(f.risk_level, RiskLevel)
            else RiskLevel(str(f.risk_level).upper())
        )
        if rl == risk_level:
            cat_display = format_category_name(f.category)
            if cat_display not in seen:
                seen.add(cat_display)
                categories.append(cat_display)
    if not categories:
        return "None"
    return ", ".join(categories)


def generate_recommended_actions(
    meta: ReportMeta, findings: list[Finding]
) -> list[str]:
    """Generate context-aware, actionable next steps for the forensic analyst.

    Args:
        meta: Report metadata containing host and timestamp information.
        findings: List of scored persistence findings.

    Returns:
        List of recommended action strings.
    """
    recommendations: list[str] = []
    seen: set[str] = set()

    def add_rec(rec: str) -> None:
        """Add recommendation if not empty and not previously recorded.

        Args:
            rec: Recommendation string to append.
        """
        if rec and rec not in seen:
            seen.add(rec)
            recommendations.append(rec)

    for f in findings:
        if f.details.get("recommendation"):
            add_rec(str(f.details["recommendation"]))

        target_bin = (
            f.details.get("target_binary_path")
            or f.details.get("target_executable")
            or f.details.get("exec_path")
        )
        if not target_bin and f.details.get("exec_start"):
            parts = str(f.details["exec_start"]).split()
            if parts and parts[0].startswith("/"):
                target_bin = parts[0]
        if target_bin:
            add_rec(
                f"Inspect the binary at `{target_bin}` using an inspection worker or hash reputation lookup."
            )

        user = f.details.get("user") or f.details.get("target_user")
        category = f.category.lower()
        flags = [str(item) for item in f.details.get("flags", [])]
        flags_str = " ".join(flags)
        if user and (
            "shell" in category
            or "cron" in category
            or f.decoded_payload
            or "REVERSE_SHELL" in flags_str
            or "BASE64" in flags_str
        ):
            date_str = ""
            if meta.analysis_timestamp:
                date_str = meta.analysis_timestamp.split("T")[0].split(" ")[0]
            if date_str:
                add_rec(
                    f"Review network connection logs around `{date_str}` associated with user `{user}`."
                )
            else:
                add_rec(
                    f"Review network connection logs associated with user `{user}`."
                )

        key_comment = f.details.get("key_comment") or f.details.get("comment")
        if "ssh" in category or "authorized_keys" in f.path:
            if key_comment:
                add_rec(
                    f"Verify if `{key_comment}` is an authorized deployment key on this instance."
                )
            else:
                add_rec(
                    f"Verify whether authorized SSH keys in `{f.path}` are approved."
                )

        if "ld_preload" in category or "ld.so.preload" in f.path:
            add_rec(
                "Immediately investigate preloaded shared object libraries in `/etc/ld.so.preload` for unauthorized rootkit hooks."
            )

        if "sudoers" in category or "sudoers" in f.path:
            add_rec(
                f"Review elevated privileges and NOPASSWD entries in `{f.path}` for unauthorized administrative access."
            )

        if "pam" in category or "pam" in f.path:
            add_rec(
                "Audit PAM authentication modules in `/etc/pam.d/` to ensure no unauthorized authentication bypass modules are present."
            )

        if (
            ("cron" in category or "cron" in f.path)
            and not target_bin
            and not any("cron" in r.lower() for r in seen)
        ):
            add_rec(
                f"Audit scheduled cron jobs in `{f.path}` and cross-reference command parameters against authorized system baselines."
            )

        if (
            ("systemd" in category or ".service" in f.path)
            and not target_bin
            and not any("systemd" in r.lower() for r in seen)
        ):
            add_rec(
                f"Verify systemd service unit integrity for `{f.path}` and restrict execution permissions to root."
            )

    if not recommendations:
        add_rec(
            "No critical persistence anomalies requiring immediate remediation were identified. Maintain routine security monitoring."
        )

    return recommendations


def build_json_report(meta: ReportMeta, findings: list[Finding]) -> dict[str, Any]:
    """Produce structured dictionary conforming to Section 4.1 JSON schema.

    Args:
        meta: Report metadata summarizing analysis context.
        findings: Ranked list of findings.

    Returns:
        Structured dictionary matching report JSON schema.
    """
    meta_dict = meta.to_dict() if hasattr(meta, "to_dict") else dict(meta)
    if not meta_dict.get("total_findings") and findings:
        meta_dict["total_findings"] = len(findings)
    elif not findings:
        meta_dict["total_findings"] = 0

    return {
        "meta": meta_dict,
        "findings": [
            f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in findings
        ],
    }


def write_json_report(
    output_file_path: str,
    meta: ReportMeta,
    findings: list[Finding],
    indent: int = 2,
) -> dict[str, Any]:
    """Write structured persistence JSON report to file and return report dictionary.

    Args:
        output_file_path: Local filesystem destination path.
        meta: Report metadata.
        findings: Ranked list of findings.
        indent: Indentation level for JSON serialization.

    Returns:
        Dictionary representation of the written JSON report.
    """
    report_dict = build_json_report(meta, findings)
    output_dir = os.path.dirname(os.path.abspath(output_file_path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(output_file_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=indent)
    return report_dict


def build_task_report(meta: ReportMeta, findings: list[Finding]) -> Report:
    """Build OpenRelik Report conforming to Section 4.2 of persistence design document.

    Args:
        meta: Report metadata header.
        findings: List of identified persistence findings.

    Returns:
        OpenRelik Report instance with formatted Markdown sections.
    """
    report = Report("🔍 Persistence Analysis Report")
    report.priority = get_highest_priority(findings)

    total_count = len(findings) if findings else meta.total_findings
    if total_count == 0:
        report.summary = "No persistence artifacts flagged."
    else:
        report.summary = (
            f"Persistence analysis flagged {total_count} persistence artifact(s)."
        )

    # Section 1: Header metadata block
    s1 = report.add_section()
    os_display = format_os_display(meta.os)
    ts_display = format_display_timestamp(meta.analysis_timestamp)
    header_lines = [
        f"**Host System:** `{meta.hostname}`  ",
        f"**OS Target:** {os_display}  ",
        f"**Analysis Timestamp:** {ts_display}  ",
        f"**Total Persistence Artifacts Flagged:** {total_count}  ",
        "",
        "---",
    ]
    s1.content.append("\n".join(header_lines))

    # Section 2: Findings Summary table
    s2 = report.add_section()
    crit_count = sum(
        1
        for f in findings
        if (f.risk_level.value if isinstance(f.risk_level, RiskLevel) else f.risk_level)
        == RiskLevel.CRITICAL.value
    )
    high_count = sum(
        1
        for f in findings
        if (f.risk_level.value if isinstance(f.risk_level, RiskLevel) else f.risk_level)
        == RiskLevel.HIGH.value
    )
    med_count = sum(
        1
        for f in findings
        if (f.risk_level.value if isinstance(f.risk_level, RiskLevel) else f.risk_level)
        == RiskLevel.MEDIUM.value
    )
    info_count = sum(
        1
        for f in findings
        if (f.risk_level.value if isinstance(f.risk_level, RiskLevel) else f.risk_level)
        == RiskLevel.INFO.value
    )

    crit_cats = get_primary_categories_for_risk(findings, RiskLevel.CRITICAL)
    high_cats = get_primary_categories_for_risk(findings, RiskLevel.HIGH)
    med_cats = get_primary_categories_for_risk(findings, RiskLevel.MEDIUM)
    info_cats = get_primary_categories_for_risk(findings, RiskLevel.INFO)

    summary_table_lines = [
        "\n## 📊 Findings Summary\n",
        "| Risk Level | Count | Primary Categories |",
        "| :--- | :---: | :--- |",
        f"| 🔴 **CRITICAL** | {crit_count} | {crit_cats} |",
        f"| 🟠 **HIGH** | {high_count} | {high_cats} |",
        f"| 🟡 **MEDIUM** | {med_count} | {med_cats} |",
        f"| 🟢 **INFO** | {info_count} | {info_cats} |",
        "",
        "---",
    ]
    s2.content.append("\n".join(summary_table_lines))

    # Partition findings into Critical/High and Medium/Info
    crit_high_findings: list[Finding] = []
    med_info_findings: list[Finding] = []
    for f in findings:
        rl = (
            f.risk_level.value
            if isinstance(f.risk_level, RiskLevel)
            else str(f.risk_level).upper()
        )
        if rl in (RiskLevel.CRITICAL.value, RiskLevel.HIGH.value):
            crit_high_findings.append(f)
        else:
            med_info_findings.append(f)

    # Section 3: Critical & High Risk Findings
    s3 = report.add_section()
    crit_high_lines = ["\n## 🚨 Critical & High Risk Findings\n"]
    finding_idx = 1
    if crit_high_findings:
        crit_blocks: list[str] = []
        for f in crit_high_findings:
            crit_blocks.append(render_finding_block(f, finding_idx))
            finding_idx += 1
        crit_high_lines.append("\n\n---\n\n".join(crit_blocks))
    else:
        crit_high_lines.append(
            "*No critical or high-risk persistence mechanisms detected.*"
        )
    crit_high_lines.extend(["", "---"])
    s3.content.append("\n".join(crit_high_lines))

    # Section 4: Medium & Low Risk Findings
    s4 = report.add_section()
    med_info_lines = ["\n## ⚠️ Medium & Low Risk Findings\n"]
    if med_info_findings:
        med_blocks: list[str] = []
        for f in med_info_findings:
            med_blocks.append(render_finding_block(f, finding_idx))
            finding_idx += 1
        med_info_lines.append("\n\n---\n\n".join(med_blocks))
    else:
        med_info_lines.append(
            "*No medium or low-risk persistence mechanisms detected.*"
        )
    med_info_lines.extend(["", "---"])
    s4.content.append("\n".join(med_info_lines))

    # Section 5: Recommended Next Actions
    s5 = report.add_section()
    recommendations = generate_recommended_actions(meta, findings)
    rec_lines = ["\n## 💡 Recommended Next Actions for Analyst\n"]
    for i, action in enumerate(recommendations, 1):
        rec_lines.append(f"{i}. {action}")
    s5.content.append("\n".join(rec_lines))

    return report


def render_markdown_report(meta: ReportMeta, findings: list[Finding]) -> str:
    """Render the full Markdown report as a string conforming to Section 4.2.

    Args:
        meta: Report metadata header.
        findings: List of identified persistence findings.

    Returns:
        Rendered Markdown document string.
    """
    report = build_task_report(meta, findings)
    return report.to_markdown()


__all__ = [
    "build_json_report",
    "build_task_report",
    "render_markdown_report",
    "write_json_report",
]
