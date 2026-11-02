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
"""Task definitions for the OpenRelik Persistence Analyzer worker."""

from __future__ import annotations

from typing import Any

from openrelik_common import telemetry
from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.task_utils import create_task_result, get_input_files

from src.utils.linux_analyzer import run_linux_persistence_analysis
from src.utils.report_generator import build_task_report, write_json_report
from src.utils.target_resolver import resolve_targets

from .app import celery

# Task name used to register and route the task to the correct queue.
TASK_NAME: str = "openrelik-worker-persistence.tasks.persistence"

# Task metadata for registration in the core system.
TASK_METADATA: dict[str, Any] = {
    "display_name": "Persistence Analyzer",
    "description": (
        "Identifies and analyzes system persistence mechanisms across disk "
        "images or extracted files."
    ),
    "task_config": [
        {
            "name": "min_risk_level",
            "label": "Minimum Risk Level",
            "description": (
                "Filter findings by minimum risk severity level (INFO, MEDIUM, "
                "HIGH, CRITICAL)"
            ),
            "type": "text",
        },
    ],
}


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def command(
    self: Any,
    pipe_result: str | None = None,
    input_files: list[dict[str, Any]] | None = None,
    output_path: str | None = None,
    workflow_id: str | None = None,
    task_config: dict[str, Any] | None = None,
) -> str:
    """Analyze system persistence mechanisms across disk images or extracted files.

    Args:
        self: The bound Celery task instance.
        pipe_result: Base64-encoded result from the previous Celery task, if any.
        input_files: List of input file dictionaries (unused if pipe_result exists).
        output_path: Path to the output directory.
        workflow_id: ID of the workflow.
        task_config: User configuration for the task.

    Returns:
        Base64-encoded dictionary containing task results.

    Raises:
        RuntimeError: If no input files are provided.
    """
    input_files = get_input_files(pipe_result, input_files or [])
    task_config = task_config or {}

    telemetry.add_attribute_to_current_span("input_files", input_files)
    telemetry.add_attribute_to_current_span("task_config", task_config)
    telemetry.add_attribute_to_current_span("workflow_id", workflow_id)

    if not input_files:
        raise RuntimeError("No input files provided.")

    min_risk_level = task_config.get("min_risk_level") or None

    with resolve_targets(input_files) as targets:
        meta, findings = run_linux_persistence_analysis(
            targets, min_risk_level=min_risk_level
        )

    json_output = create_output_file(
        output_path,
        display_name="persistence_report.json",
        data_type="openrelik:persistence:report:json",
    )
    write_json_report(json_output.path, meta, findings)

    report = build_task_report(meta, findings)

    self.send_event(
        "task-progress",
        data={"progress": 100, "total_findings": meta.total_findings},
    )
    telemetry.add_attribute_to_current_span("total_findings", meta.total_findings)

    return create_task_result(
        output_files=[json_output.to_dict()],
        workflow_id=workflow_id,
        task_report=report.to_dict(),
        meta=meta.to_dict(),
    )


# Alias task command to persistence
persistence = command
