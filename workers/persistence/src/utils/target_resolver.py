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
"""Target resolver for disk images and loose/extracted forensic artifact files."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from openrelik_worker_common.file_utils import is_disk_image
from openrelik_worker_common.mount_utils import BlockDevice

from src.utils.models import AnalysisTarget, normalize_virtual_path

logger: logging.Logger = logging.getLogger(__name__)


def infer_virtual_path_for_standalone_file(input_file: dict[str, Any]) -> str:
    """Infer the virtual system path for a standalone file based on metadata or heuristics.

    Args:
        input_file: Dictionary containing metadata of the input file.

    Returns:
        A canonical normalized virtual path (e.g. '/etc/systemd/system/foo.service').
    """
    orig_path = input_file.get("original_path")
    if not orig_path and isinstance(input_file.get("meta"), dict):
        orig_path = input_file["meta"].get("original_path")
    if orig_path:
        return normalize_virtual_path(str(orig_path))

    name = input_file.get("display_name")
    phys_path = input_file.get("path")
    if not name and phys_path:
        name = os.path.basename(phys_path)
    if not name:
        name = "unnamed"

    base_name = os.path.basename(name)

    if base_name.endswith((".service", ".timer")):
        return f"/etc/systemd/system/{base_name}"

    if base_name == "crontab":
        return "/etc/crontab"

    if base_name == "anacrontab":
        return "/etc/anacrontab"

    if base_name == "profile":
        return "/etc/profile"

    if base_name == "bash.bashrc":
        return "/etc/bash.bashrc"

    if base_name in (".bashrc", ".bash_profile", ".zshrc", ".profile", ".bash_logout"):
        return f"/home/user/{base_name}"

    if base_name == "authorized_keys":
        return "/root/.ssh/authorized_keys"

    if base_name == "authorized_keys2":
        return "/root/.ssh/authorized_keys2"

    if base_name == "sshd_config":
        return "/etc/ssh/sshd_config"

    if base_name == "rc.local":
        return "/etc/rc.local"

    if base_name == "ld.so.preload":
        return "/etc/ld.so.preload"

    if base_name == "sudoers":
        return "/etc/sudoers"

    if base_name.endswith(".desktop"):
        return f"/etc/xdg/autostart/{base_name}"

    # Read content heuristics if physical file is accessible
    snippet = ""
    if phys_path and os.path.isfile(phys_path):
        try:
            with open(phys_path, "r", encoding="utf-8", errors="ignore") as f:
                snippet = f.read(4096)
        except OSError:
            pass

    if (
        base_name.endswith(".conf")
        and snippet
        and (".so" in snippet or "/lib" in snippet or "/usr" in snippet)
    ):
        return f"/etc/ld.so.conf.d/{base_name}"

    if snippet:
        if "[Unit]" in snippet or "[Service]" in snippet:
            return f"/etc/systemd/system/{base_name}"
        if "[Desktop Entry]" in snippet:
            return f"/etc/xdg/autostart/{base_name}"
        if any(key in snippet for key in ("ssh-rsa", "ssh-ed25519", "ecdsa-sha2-")):
            return "/root/.ssh/authorized_keys"

    return normalize_virtual_path(f"/{base_name}")


@contextmanager
def resolve_targets(
    input_files: list[dict[str, Any]],
    min_partition_size: int = 1,
) -> Iterator[list[AnalysisTarget]]:
    """Context manager to resolve input files into safe AnalysisTarget instances.

    Separates input files into disk images and loose/extracted files. Disk images
    are mounted via BlockDevice and unmounted strictly in a finally block.

    Args:
        input_files: List of input file dictionaries provided to the worker task.
        min_partition_size: Minimum partition size in bytes to mount from disk images.

    Yields:
        List of resolved AnalysisTarget instances ready for persistence analysis.
    """
    disk_files: list[dict[str, Any]] = []
    loose_files: list[dict[str, Any]] = []

    for f in input_files:
        is_disk = False
        try:
            file_check = dict(f)
            if "display_name" not in file_check and "path" in file_check:
                file_check["display_name"] = os.path.basename(file_check["path"])
            is_disk = is_disk_image(file_check)
        except (RuntimeError, ValueError, TypeError, KeyError, AttributeError):
            is_disk = False

        if is_disk:
            disk_files.append(f)
        else:
            loose_files.append(f)

    mounted_devices: list[BlockDevice] = []
    targets: list[AnalysisTarget] = []

    try:
        for f in disk_files:
            image_path = f.get("path", "")
            bd = BlockDevice(
                image_path=image_path, min_partition_size=min_partition_size
            )
            mounted_devices.append(bd)
            bd.setup()
            mountpoints = bd.mount()
            for mp in mountpoints:
                targets.append(
                    AnalysisTarget(
                        root_path=mp,
                        source_file=f,
                        is_mounted_image=True,
                    )
                )

        if loose_files:
            if (
                len(loose_files) == 1
                and loose_files[0].get("path")
                and os.path.isdir(loose_files[0]["path"])
            ):
                dir_path = loose_files[0]["path"]
                targets.append(
                    AnalysisTarget(
                        root_path=dir_path,
                        source_file=loose_files[0],
                        is_mounted_image=False,
                    )
                )
            else:
                virtual_map: dict[str, str] = {}
                for lf in loose_files:
                    phys = lf.get("path", "")
                    vpath = infer_virtual_path_for_standalone_file(lf)
                    virtual_map[vpath] = phys
                targets.append(
                    AnalysisTarget(
                        virtual_paths=virtual_map,
                        source_file=loose_files[0] if len(loose_files) == 1 else None,
                        is_mounted_image=False,
                    )
                )

        yield targets

    finally:
        for bd in reversed(mounted_devices):
            try:
                bd.umount()
            except (RuntimeError, OSError) as e:
                logger.warning("Error unmounting block device %s: %s", bd, e)


__all__ = [
    "infer_virtual_path_for_standalone_file",
    "resolve_targets",
]
