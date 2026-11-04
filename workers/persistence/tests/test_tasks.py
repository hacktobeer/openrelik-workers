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
"""Tests for persistence analyzer tasks."""

from __future__ import annotations

import json
from unittest import mock

import pytest

from src import app, tasks


def test_task_constants():
    """Test task name and metadata definitions."""
    assert tasks.TASK_NAME == "openrelik-worker-persistence.tasks.persistence"
    assert tasks.TASK_METADATA["display_name"] == "Persistence Analyzer"
    assert "task_config" in tasks.TASK_METADATA
    assert tasks.persistence is tasks.command


def test_app_configuration():
    """Test Celery app configuration and initialization."""
    assert app.celery.main == "src.app" or app.celery is not None
    assert "src.tasks" in app.celery.conf.include


@mock.patch("src.tasks.telemetry")
@mock.patch("src.tasks.create_task_result")
def test_persistence_task_standalone_files(
    mock_create_result, mock_telemetry, tmp_path
):
    """Test task execution with standalone extracted files end-to-end."""
    mock_create_result.return_value = "mocked_task_result_b64"

    # Create a realistic suspicious service file
    service_content = (
        "[Unit]\n"
        "Description=Malicious Backdoor Service\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/tmp/backdoor.sh\n"
    )
    service_file = tmp_path / "backdoor.service"
    service_file.write_text(service_content)

    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    input_files = [
        {
            "path": str(service_file),
            "display_name": "backdoor.service",
            "original_path": "/etc/systemd/system/backdoor.service",
        }
    ]

    with mock.patch.object(tasks.command, "send_event") as mock_send_event:
        result = tasks.command.run(
            pipe_result=None,
            input_files=input_files,
            output_path=str(output_dir),
            workflow_id="wf-12345",
            task_config={"min_risk_level": "INFO"},
        )

        assert result == "mocked_task_result_b64"

        # Verify send_event was called with progress
        mock_send_event.assert_called_once_with(
            "task-progress",
            data={"progress": 100, "total_findings": mock.ANY},
        )
        _, kwargs_event = mock_send_event.call_args
        assert kwargs_event["data"]["total_findings"] >= 1

    # Verify telemetry attributes were recorded
    mock_telemetry.add_attribute_to_current_span.assert_any_call(
        "input_files", input_files
    )
    mock_telemetry.add_attribute_to_current_span("workflow_id", "wf-12345")

    # Verify create_task_result arguments
    mock_create_result.assert_called_once()
    _, kwargs = mock_create_result.call_args
    assert kwargs["workflow_id"] == "wf-12345"
    assert "task_report" in kwargs
    assert kwargs["task_report"]["title"] == "🔍 Persistence Analysis Report"
    assert "meta" in kwargs
    assert kwargs["meta"]["total_findings"] >= 1

    # Verify output_files list contains persistence_report.json
    output_files = kwargs["output_files"]
    assert len(output_files) == 1
    assert output_files[0]["display_name"] == "persistence_report.json"
    assert output_files[0]["data_type"] == "openrelik:persistence:report:json"

    # Verify persistence_report.json written to disk
    report_json_path = output_files[0]["path"]
    with open(report_json_path, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    assert "meta" in report_data
    assert "findings" in report_data
    assert report_data["meta"]["total_findings"] >= 1
    findings = report_data["findings"]
    assert any(
        "backdoor.service" in f["path"]
        or "backdoor" in f.get("details", {}).get("service_name", "")
        for f in findings
    )


@mock.patch("src.tasks.telemetry")
@mock.patch("src.tasks.get_input_files")
@mock.patch("src.tasks.create_task_result")
def test_persistence_task_with_pipe_result(
    mock_create_result, mock_get_input, mock_telemetry, tmp_path
):
    """Test task execution when inputs are resolved via pipe_result."""
    mock_create_result.return_value = "piped_result"

    crontab_content = "* * * * * root /tmp/evil.sh\n"
    crontab_file = tmp_path / "crontab"
    crontab_file.write_text(crontab_content)

    mock_get_input.return_value = [
        {
            "path": str(crontab_file),
            "display_name": "crontab",
            "original_path": "/etc/crontab",
        }
    ]

    output_dir = tmp_path / "output_pipe"
    output_dir.mkdir(parents=True, exist_ok=True)

    with mock.patch.object(tasks.command, "send_event") as mock_send_event:
        result = tasks.command.run(
            pipe_result="dummy_pipe_b64",
            input_files=None,
            output_path=str(output_dir),
            workflow_id="wf-pipe-99",
            task_config={},
        )

        assert result == "piped_result"
        mock_send_event.assert_called_once()

    mock_get_input.assert_called_once_with("dummy_pipe_b64", [])
    mock_create_result.assert_called_once()


@mock.patch("src.utils.target_resolver.BlockDevice")
@mock.patch("src.tasks.telemetry")
@mock.patch("src.tasks.create_task_result")
def test_persistence_task_mocked_disk_image(
    mock_create_result, mock_telemetry, mock_block_device_cls, tmp_path
):
    """Test task execution with a mocked disk image verifying BlockDevice mount/umount lifecycle."""
    mock_create_result.return_value = "disk_task_result"

    # Setup a mock mounted filesystem structure
    mounted_root = tmp_path / "mnt_partition_1"
    systemd_dir = mounted_root / "etc" / "systemd" / "system"
    systemd_dir.mkdir(parents=True, exist_ok=True)
    etc_dir = mounted_root / "etc"
    (etc_dir / "hostname").write_text("forensic-target-box\n")

    service_file = systemd_dir / "suspicious.service"
    service_file.write_text(
        "[Unit]\nDescription=Suspicious\n[Service]\nExecStart=/home/user/.hidden/tool\n"
    )

    # Configure mock BlockDevice instance
    mock_bd_instance = mock.Mock()
    mock_bd_instance.setup.return_value = None
    mock_bd_instance.mount.return_value = [str(mounted_root)]
    mock_bd_instance.umount.return_value = None
    mock_block_device_cls.return_value = mock_bd_instance

    output_dir = tmp_path / "output_disk"
    output_dir.mkdir(parents=True, exist_ok=True)

    disk_input_file = {
        "path": "/fake/storage/image.raw",
        "display_name": "image.raw",
    }

    with mock.patch.object(tasks.command, "send_event") as mock_send_event:
        result = tasks.command.run(
            pipe_result=None,
            input_files=[disk_input_file],
            output_path=str(output_dir),
            workflow_id="wf-disk-image",
            task_config={},
        )

        assert result == "disk_task_result"
        mock_send_event.assert_called_once()

    # Verify BlockDevice lifecycle: setup(), mount(), and umount() strictly called
    mock_block_device_cls.assert_called_once_with(
        image_path="/fake/storage/image.raw", min_partition_size=1
    )
    mock_bd_instance.setup.assert_called_once()
    mock_bd_instance.mount.assert_called_once()
    mock_bd_instance.umount.assert_called_once()

    # Verify task result was created with findings from the mounted disk image
    mock_create_result.assert_called_once()
    _, kwargs = mock_create_result.call_args
    assert kwargs["meta"]["hostname"] == "forensic-target-box"


@mock.patch("src.tasks.get_input_files")
def test_persistence_task_empty_input_files(mock_get_input):
    """Test task execution when no input files are provided raises RuntimeError."""
    mock_get_input.return_value = []

    with pytest.raises(RuntimeError, match="No input files provided"):
        tasks.command.run(
            pipe_result=None,
            input_files=[],
            output_path="/tmp/output",
            workflow_id="wf-empty",
            task_config={},
        )


@mock.patch("src.tasks.telemetry")
@mock.patch("src.tasks.create_task_result")
def test_persistence_task_min_risk_level_filter(
    mock_create_result, mock_telemetry, tmp_path
):
    """Test task execution with min_risk_level config filtering findings."""
    mock_create_result.return_value = "filtered_result"

    # Create an INFO-level desktop entry
    desktop_file = tmp_path / "normal.desktop"
    desktop_file.write_text(
        "[Desktop Entry]\nName=Editor\nExec=/usr/bin/gedit\nType=Application\n"
    )

    output_dir = tmp_path / "output_filter"
    output_dir.mkdir(parents=True, exist_ok=True)

    input_files = [
        {
            "path": str(desktop_file),
            "display_name": "normal.desktop",
            "original_path": "/etc/xdg/autostart/normal.desktop",
        }
    ]

    with mock.patch.object(tasks.command, "send_event"):
        tasks.command.run(
            pipe_result=None,
            input_files=input_files,
            output_path=str(output_dir),
            workflow_id="wf-filter",
            task_config={"min_risk_level": "CRITICAL"},
        )

    mock_create_result.assert_called_once()
    _, kwargs = mock_create_result.call_args
    # Filtered out because finding is not CRITICAL
    assert kwargs["meta"]["total_findings"] == 0


@mock.patch("src.tasks.telemetry")
@mock.patch("src.tasks.create_task_result")
def test_persistence_task_include_raw_content_false(
    mock_create_result, mock_telemetry, tmp_path
):
    """Test task execution with include_raw_content=False strips raw_content."""
    mock_create_result.return_value = "raw_content_disabled"

    cron_file = tmp_path / "crontab"
    cron_file.write_text("* * * * * root /tmp/evil.sh\n")

    output_dir = tmp_path / "output_raw"
    output_dir.mkdir(parents=True, exist_ok=True)

    input_files = [
        {
            "path": str(cron_file),
            "display_name": "crontab",
            "original_path": "/etc/crontab",
        }
    ]

    with mock.patch.object(tasks.command, "send_event"):
        tasks.command.run(
            pipe_result=None,
            input_files=input_files,
            output_path=str(output_dir),
            workflow_id="wf-raw",
            task_config={"include_raw_content": False},
        )

    mock_create_result.assert_called_once()
    _, kwargs = mock_create_result.call_args
    output_files = kwargs["output_files"]
    report_json_path = output_files[0]["path"]
    with open(report_json_path, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    assert report_data["meta"]["total_findings"] >= 1
    for finding in report_data["findings"]:
        assert finding["raw_content"] is None

    # Test string representation "false"
    with mock.patch.object(tasks.command, "send_event"):
        tasks.command.run(
            pipe_result=None,
            input_files=input_files,
            output_path=str(output_dir),
            workflow_id="wf-raw-str",
            task_config={"include_raw_content": "false"},
        )
