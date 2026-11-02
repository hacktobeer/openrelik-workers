# Copyright 2025 Google LLC
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
"""Unit tests for TargetResolver and standalone file virtual path inference."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.utils.target_resolver import (
    infer_virtual_path_for_standalone_file,
    resolve_targets,
)


def test_infer_virtual_path_with_original_path():
    """Verify original_path takes priority and is normalized."""
    input_file = {
        "display_name": "random.service",
        "original_path": "etc/systemd/system/malicious.service",
    }
    assert (
        infer_virtual_path_for_standalone_file(input_file)
        == "/etc/systemd/system/malicious.service"
    )

    input_file_meta = {
        "display_name": "foo.txt",
        "meta": {"original_path": "/var/spool/cron/crontabs/root"},
    }
    assert (
        infer_virtual_path_for_standalone_file(input_file_meta)
        == "/var/spool/cron/crontabs/root"
    )


def test_infer_virtual_path_name_heuristics():
    """Verify standard filename heuristics map to canonical virtual paths."""
    mappings = [
        ({"display_name": "nginx.service"}, "/etc/systemd/system/nginx.service"),
        ({"display_name": "backup.timer"}, "/etc/systemd/system/backup.timer"),
        ({"display_name": "crontab"}, "/etc/crontab"),
        ({"display_name": "anacrontab"}, "/etc/anacrontab"),
        ({"display_name": "profile"}, "/etc/profile"),
        ({"display_name": "bash.bashrc"}, "/etc/bash.bashrc"),
        ({"display_name": ".bashrc"}, "/home/user/.bashrc"),
        ({"display_name": ".bash_profile"}, "/home/user/.bash_profile"),
        ({"display_name": ".zshrc"}, "/home/user/.zshrc"),
        ({"display_name": ".profile"}, "/home/user/.profile"),
        ({"display_name": ".bash_logout"}, "/home/user/.bash_logout"),
        ({"display_name": "authorized_keys"}, "/root/.ssh/authorized_keys"),
        ({"display_name": "authorized_keys2"}, "/root/.ssh/authorized_keys2"),
        ({"display_name": "sshd_config"}, "/etc/ssh/sshd_config"),
        ({"display_name": "rc.local"}, "/etc/rc.local"),
        ({"display_name": "ld.so.preload"}, "/etc/ld.so.preload"),
        ({"display_name": "sudoers"}, "/etc/sudoers"),
        ({"display_name": "app.desktop"}, "/etc/xdg/autostart/app.desktop"),
        ({"display_name": "generic.txt"}, "/generic.txt"),
    ]
    for file_dict, expected in mappings:
        assert infer_virtual_path_for_standalone_file(file_dict) == expected


def test_infer_virtual_path_basename_fallback():
    """Verify fallback to basename of path when display_name is missing."""
    input_file = {"path": "/tmp/extracted/my_daemon.service"}
    assert (
        infer_virtual_path_for_standalone_file(input_file)
        == "/etc/systemd/system/my_daemon.service"
    )

    empty_file = {}
    assert infer_virtual_path_for_standalone_file(empty_file) == "/unnamed"


def test_infer_virtual_path_content_heuristics(tmp_path):
    """Verify file content sniffers route files when name is ambiguous."""
    # .conf file with .so reference -> ld.so.conf.d
    conf_file = tmp_path / "custom.conf"
    conf_file.write_text("/usr/local/lib/evil_hook.so\n")
    assert (
        infer_virtual_path_for_standalone_file(
            {"path": str(conf_file), "display_name": "custom.conf"}
        )
        == "/etc/ld.so.conf.d/custom.conf"
    )

    # .conf file without library paths -> fallback
    plain_conf = tmp_path / "other.conf"
    plain_conf.write_text("setting = 1\n")
    assert (
        infer_virtual_path_for_standalone_file(
            {"path": str(plain_conf), "display_name": "other.conf"}
        )
        == "/other.conf"
    )

    # Unknown file with [Unit] content -> systemd
    unit_file = tmp_path / "mystery_file"
    unit_file.write_text("[Unit]\nDescription=Test\n[Service]\nExecStart=/bin/sh\n")
    assert (
        infer_virtual_path_for_standalone_file(
            {"path": str(unit_file), "display_name": "mystery_file"}
        )
        == "/etc/systemd/system/mystery_file"
    )

    # Unknown file with [Desktop Entry] -> autostart
    desktop_file = tmp_path / "mystery_gui"
    desktop_file.write_text("[Desktop Entry]\nType=Application\nExec=/bin/app\n")
    assert (
        infer_virtual_path_for_standalone_file(
            {"path": str(desktop_file), "display_name": "mystery_gui"}
        )
        == "/etc/xdg/autostart/mystery_gui"
    )

    # Unknown file with ssh public key -> authorized_keys
    key_file = tmp_path / "mystery_key"
    key_file.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test@host\n")
    assert (
        infer_virtual_path_for_standalone_file(
            {"path": str(key_file), "display_name": "mystery_key"}
        )
        == "/root/.ssh/authorized_keys"
    )


@patch("src.utils.target_resolver.BlockDevice")
@patch("src.utils.target_resolver.is_disk_image")
def test_resolve_targets_disk_image_mounting(mock_is_disk_image, mock_bd_class):
    """Test mounting disk images via BlockDevice and unmounting in finally."""
    mock_is_disk_image.return_value = True
    mock_bd = MagicMock()
    mock_bd_class.return_value = mock_bd
    mock_bd.mount.return_value = ["/mnt/partition1", "/mnt/partition2"]

    input_files = [{"path": "/images/evidence.raw", "display_name": "evidence.raw"}]

    with resolve_targets(input_files, min_partition_size=100) as targets:
        assert len(targets) == 2
        assert targets[0].root_path == "/mnt/partition1"
        assert targets[0].is_mounted_image is True
        assert targets[0].source_file == input_files[0]
        assert targets[1].root_path == "/mnt/partition2"
        assert targets[1].is_mounted_image is True

        mock_bd_class.assert_called_once_with(
            image_path="/images/evidence.raw", min_partition_size=100
        )
        mock_bd.setup.assert_called_once()
        mock_bd.mount.assert_called_once()
        mock_bd.umount.assert_not_called()

    # BlockDevice.umount() must be called after context exit
    mock_bd.umount.assert_called_once()


@patch("src.utils.target_resolver.BlockDevice")
@patch("src.utils.target_resolver.is_disk_image")
def test_resolve_targets_umount_on_analysis_exception(
    mock_is_disk_image, mock_bd_class
):
    """Ensure BlockDevice.umount() is called even when analysis raises an exception."""
    mock_is_disk_image.return_value = True
    mock_bd = MagicMock()
    mock_bd_class.return_value = mock_bd
    mock_bd.mount.return_value = ["/mnt/partition1"]

    input_files = [{"path": "/images/evidence.raw", "display_name": "evidence.raw"}]

    with (
        pytest.raises(ValueError, match="Analysis crashed"),
        resolve_targets(input_files) as targets,
    ):
        assert len(targets) == 1
        raise ValueError("Analysis crashed")

    # Guaranteed cleanup
    mock_bd.umount.assert_called_once()


@patch("src.utils.target_resolver.BlockDevice")
@patch("src.utils.target_resolver.is_disk_image")
def test_resolve_targets_umount_on_mount_exception(mock_is_disk_image, mock_bd_class):
    """Ensure BlockDevice.umount() is called even if bd.mount() fails."""
    mock_is_disk_image.return_value = True
    mock_bd = MagicMock()
    mock_bd_class.return_value = mock_bd
    mock_bd.mount.side_effect = RuntimeError("Failed to mount partition")

    input_files = [{"path": "/images/evidence.raw", "display_name": "evidence.raw"}]

    with (
        pytest.raises(RuntimeError, match="Failed to mount partition"),
        resolve_targets(input_files),
    ):
        pass

    # Guaranteed cleanup
    mock_bd.umount.assert_called_once()


def test_resolve_targets_single_directory(tmp_path):
    """Verify single directory input produces an AnalysisTarget with root_path."""
    sub_dir = tmp_path / "extracted_sysroot"
    sub_dir.mkdir()

    input_files = [{"path": str(sub_dir), "display_name": "extracted_sysroot"}]
    with resolve_targets(input_files) as targets:
        assert len(targets) == 1
        target = targets[0]
        assert target.root_path == str(sub_dir)
        assert target.is_mounted_image is False
        assert target.source_file == input_files[0]


def test_resolve_targets_loose_files(tmp_path):
    """Verify multiple loose files are aggregated into virtual_paths."""
    file1 = tmp_path / "my.service"
    file1.write_text("[Unit]\n")
    file2 = tmp_path / ".bashrc"
    file2.write_text("export FOO=1\n")

    input_files = [
        {"path": str(file1), "display_name": "my.service"},
        {"path": str(file2), "display_name": ".bashrc"},
    ]

    with resolve_targets(input_files) as targets:
        assert len(targets) == 1
        target = targets[0]
        assert target.root_path is None
        assert target.is_mounted_image is False
        assert "/etc/systemd/system/my.service" in target.virtual_paths
        assert target.virtual_paths["/etc/systemd/system/my.service"] == str(file1)
        assert "/home/user/.bashrc" in target.virtual_paths
        assert target.virtual_paths["/home/user/.bashrc"] == str(file2)


@patch("src.utils.target_resolver.BlockDevice")
@patch("src.utils.target_resolver.is_disk_image")
def test_resolve_targets_umount_handles_exception(mock_is_disk_image, mock_bd_class):
    """Ensure exception in bd.umount() is caught and logged."""
    mock_is_disk_image.return_value = True
    mock_bd = MagicMock()
    mock_bd_class.return_value = mock_bd
    mock_bd.mount.return_value = ["/mnt/p1"]
    mock_bd.umount.side_effect = RuntimeError("Failed to detach loop device")

    input_files = [{"path": "/images/evidence.raw", "display_name": "evidence.raw"}]
    # Context manager should not crash on umount exception
    with resolve_targets(input_files) as targets:
        assert len(targets) == 1

    mock_bd.umount.assert_called_once()


@patch("src.utils.target_resolver.BlockDevice")
@patch("src.utils.target_resolver.is_disk_image")
def test_resolve_targets_disk_image_without_display_name(
    mock_is_disk_image, mock_bd_class
):
    """Ensure disk image without display_name in input_file dict is recognized."""
    mock_is_disk_image.return_value = True
    mock_bd = MagicMock()
    mock_bd_class.return_value = mock_bd
    mock_bd.mount.return_value = ["/mnt/p1"]

    input_files = [{"path": "/images/evidence.raw"}]
    with resolve_targets(input_files) as targets:
        assert len(targets) == 1

    mock_is_disk_image.assert_called_once_with(
        {"path": "/images/evidence.raw", "display_name": "evidence.raw"}
    )


def test_infer_virtual_path_os_error_reading_file(monkeypatch, tmp_path):
    """Ensure OSError during snippet read falls back gracefully."""
    test_file = tmp_path / "unreadable.conf"
    test_file.write_text("something")

    def mock_open(*args, **kwargs):
        raise OSError("Permission denied")

    monkeypatch.setattr("builtins.open", mock_open)
    assert (
        infer_virtual_path_for_standalone_file(
            {"path": str(test_file), "display_name": "unreadable.conf"}
        )
        == "/unreadable.conf"
    )


@patch("src.utils.target_resolver.is_disk_image")
def test_resolve_targets_is_disk_image_exception_fallback(mock_is_disk_image):
    """Ensure exception in is_disk_image treats file as loose file."""
    mock_is_disk_image.side_effect = RuntimeError("Malformed file structure")
    input_files = [{"path": "/tmp/test.txt", "display_name": "test.txt"}]

    with resolve_targets(input_files) as targets:
        assert len(targets) == 1
        assert "/test.txt" in targets[0].virtual_paths


def test_resolve_targets_empty_input():
    """Verify empty input returns empty targets list."""
    with resolve_targets([]) as targets:
        assert targets == []
