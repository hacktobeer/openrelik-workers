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
"""OpenRelik persistence analyzer utilities."""

from __future__ import annotations

from src.utils.linux_analyzer import (
    LinuxAnalyzer,
    LinuxPersistenceAnalyzer,
    analyze_linux_target,
    run_linux_persistence_analysis,
)
from src.utils.models import (
    AnalysisContext,
    AnalysisTarget,
    ArtifactTarget,
    Finding,
    PathTraversalSecurityError,
    ReportMeta,
    RiskLevel,
    normalize_virtual_path,
    safe_read_bytes,
    safe_read_text,
    safe_resolve_path,
    safe_resolve_symlink,
)
from src.utils.os_detector import (
    build_analysis_context,
    detect_os_and_hostname,
)
from src.utils.report_generator import (
    build_json_report,
    build_task_report,
    render_markdown_report,
    write_json_report,
)
from src.utils.scoring_engine import (
    ScoringEngine,
    evaluate_risk_level,
    score_and_rank_findings,
)
from src.utils.target_resolver import (
    infer_virtual_path_for_standalone_file,
    resolve_targets,
)

__all__ = [
    "AnalysisContext",
    "AnalysisTarget",
    "ArtifactTarget",
    "Finding",
    "LinuxAnalyzer",
    "LinuxPersistenceAnalyzer",
    "PathTraversalSecurityError",
    "ReportMeta",
    "RiskLevel",
    "ScoringEngine",
    "analyze_linux_target",
    "build_analysis_context",
    "build_json_report",
    "build_task_report",
    "detect_os_and_hostname",
    "evaluate_risk_level",
    "infer_virtual_path_for_standalone_file",
    "normalize_virtual_path",
    "render_markdown_report",
    "resolve_targets",
    "run_linux_persistence_analysis",
    "safe_read_bytes",
    "safe_read_text",
    "safe_resolve_path",
    "safe_resolve_symlink",
    "score_and_rank_findings",
    "write_json_report",
]
