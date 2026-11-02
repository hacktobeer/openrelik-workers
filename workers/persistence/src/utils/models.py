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
"""Data models, enums, and safe filesystem abstractions for persistence analysis."""

from __future__ import annotations

import fnmatch
import os
import posixpath
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PathTraversalSecurityError(Exception):
    """Raised when a resolved path attempts to escape the root mountpoint/directory."""


class RiskLevel(str, Enum):
    """Forensic risk severity level for persistence findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents an identified persistence artifact or security anomaly."""

    id: str = ""
    category: str = ""
    risk_level: RiskLevel = RiskLevel.INFO
    technique_id: str = ""
    path: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    raw_content: str | None = None
    decoded_payload: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation.

        Returns:
            Dictionary representation of the finding.
        """
        return {
            "id": self.id,
            "category": self.category,
            "risk_level": (
                self.risk_level.value
                if isinstance(self.risk_level, RiskLevel)
                else str(self.risk_level)
            ),
            "technique_id": self.technique_id,
            "path": self.path,
            "details": self.details,
            "raw_content": self.raw_content,
            "decoded_payload": self.decoded_payload,
        }


@dataclass
class ReportMeta:
    """Metadata summary header for persistence analysis reports."""

    os: str = "linux"
    hostname: str = "unknown"
    analysis_timestamp: str = ""
    total_findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert report metadata to dictionary representation.

        Returns:
            Dictionary representation of the report metadata.
        """
        return {
            "os": self.os,
            "hostname": self.hostname,
            "analysis_timestamp": self.analysis_timestamp,
            "total_findings": self.total_findings,
        }


def normalize_virtual_path(path: str) -> str:
    """Normalize a virtual path to POSIX format with a leading slash.

    Safely handles relative segments and prevents directory traversal.

    Args:
        path: Virtual path string to normalize.

    Returns:
        Normalized absolute POSIX virtual path with a leading slash.
    """
    if not path:
        return "/"
    clean = path.replace("\\", "/")
    parts = [p for p in clean.split("/") if p and p != "."]
    safe_parts: list[str] = []
    for part in parts:
        if part == "..":
            if safe_parts:
                safe_parts.pop()
        else:
            safe_parts.append(part)
    return "/" + "/".join(safe_parts)


def safe_resolve_path(root_path: str, virtual_path: str) -> str:
    """Safely resolve a virtual path inside a root directory, preventing directory traversal.

    Args:
        root_path: Local filesystem path representing root of mounted image or folder.
        virtual_path: Virtual path of target file (e.g. '/etc/systemd/system/foo.service').

    Returns:
        Canonical absolute physical path on local filesystem.

    Raises:
        PathTraversalSecurityError: If the resolved path escapes root_path.
    """
    root_abs = os.path.abspath(root_path)
    clean_rel = virtual_path.replace("\\", "/").lstrip("/")
    full_path = os.path.abspath(os.path.join(root_abs, clean_rel))
    if os.path.commonpath([root_abs, full_path]) != root_abs:
        raise PathTraversalSecurityError(
            f"Path escapes mount root: {full_path} (root: {root_abs})"
        )
    return full_path


def safe_read_bytes(
    root_path: str,
    virtual_path: str,
    max_bytes: int = 1_048_576,
) -> bytes | None:
    """Safely read binary content of a file within root_path up to max_bytes.

    Args:
        root_path: Local filesystem path representing root directory.
        virtual_path: Virtual path of the file to read.
        max_bytes: Maximum number of bytes to read.

    Returns:
        Bytes read from file, or None if file does not exist, is a directory,
        or cannot be accessed safely.
    """
    try:
        physical_path = safe_resolve_path(root_path, virtual_path)
        if not os.path.isfile(physical_path):
            return None
        with open(physical_path, "rb") as f:
            return f.read(max_bytes)
    except (PathTraversalSecurityError, OSError):
        return None


def safe_read_text(
    root_path: str,
    virtual_path: str,
    max_bytes: int = 1_048_576,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> str | None:
    """Safely read text content of a file within root_path up to max_bytes.

    Args:
        root_path: Local filesystem path representing root directory.
        virtual_path: Virtual path of the file to read.
        max_bytes: Maximum number of bytes to read.
        encoding: Text encoding to use.
        errors: Error handling scheme for decoding.

    Returns:
        Decoded text string, or None if file cannot be read safely.
    """
    data = safe_read_bytes(root_path, virtual_path, max_bytes=max_bytes)
    if data is None:
        return None
    return data.decode(encoding=encoding, errors=errors)


def _resolve_virtual_symlink_target(parent_vdir: str, target: str) -> str | None:
    """Resolve a symlink target path against a virtual parent directory.

    Args:
        parent_vdir: Normalized virtual directory containing the symlink.
        target: Symlink target string (relative or absolute).

    Returns:
        Normalized virtual path, or None if target attempts to traverse above root.
    """
    clean_target = target.replace("\\", "/")
    if clean_target.startswith("/"):
        parts = clean_target.split("/")
        stack: list[str] = []
    else:
        parts = clean_target.split("/")
        stack = [p for p in parent_vdir.split("/") if p]

    for part in parts:
        if not part or part == ".":
            continue
        if part == "..":
            if not stack:
                # Target attempts to traverse above root
                return None
            stack.pop()
        else:
            stack.append(part)

    return "/" + "/".join(stack)


def safe_resolve_symlink(root_path: str, virtual_path: str) -> str | None:
    """Safely resolve a symlink within root_path, returning the resolved virtual path.

    Args:
        root_path: Local filesystem path representing root directory.
        virtual_path: Virtual path of the symlink.

    Returns:
        Resolved virtual path, or None if virtual_path is not a symlink,
        target is invalid, or target escapes root_path.
    """
    try:
        physical_path = safe_resolve_path(root_path, virtual_path)
        if not os.path.islink(physical_path):
            return None

        # Check physical symlink destination does not escape root
        root_abs = os.path.abspath(root_path)
        real_dest = os.path.realpath(physical_path)
        # Note: if real_dest exists outside root_abs, it's escaping host path
        if (
            os.path.exists(real_dest)
            and os.path.commonpath([root_abs, real_dest]) != root_abs
        ):
            return None

        target = os.readlink(physical_path)
        parent_vdir = posixpath.dirname(normalize_virtual_path(virtual_path))
        resolved_vpath = _resolve_virtual_symlink_target(parent_vdir, target)
        if resolved_vpath is None:
            return None

        # Validate that physical target doesn't escape root_path
        safe_resolve_path(root_path, resolved_vpath)
        return resolved_vpath
    except (PathTraversalSecurityError, OSError):
        return None


@dataclass
class AnalysisTarget:
    """Unified abstraction for mounted disk images or extracted file collections."""

    root_path: str | None = None
    virtual_paths: dict[str, str] = field(default_factory=dict)
    source_file: dict[str, Any] | None = None
    is_mounted_image: bool = False

    def get_physical_path(self, virtual_path: str) -> str | None:
        """Resolve a virtual path to a physical filesystem path.

        Args:
            virtual_path: Virtual path of the target file.

        Returns:
            Physical filesystem path if it exists, or None.
        """
        norm_vpath = normalize_virtual_path(virtual_path)
        if norm_vpath in self.virtual_paths:
            phys = self.virtual_paths[norm_vpath]
            if os.path.exists(phys):
                return phys
        if self.root_path:
            try:
                phys = safe_resolve_path(self.root_path, norm_vpath)
                if os.path.exists(phys):
                    return phys
            except (PathTraversalSecurityError, OSError):
                return None
        return None

    def exists(self, virtual_path: str) -> bool:
        """Check if a virtual path exists.

        Args:
            virtual_path: Virtual path to check.

        Returns:
            True if the virtual path exists on filesystem or map, False otherwise.
        """
        return self.get_physical_path(virtual_path) is not None

    def read_bytes(self, virtual_path: str, max_bytes: int = 1_048_576) -> bytes | None:
        """Read bytes from a virtual path up to max_bytes.

        Args:
            virtual_path: Virtual path of the file to read.
            max_bytes: Maximum number of bytes to read.

        Returns:
            Bytes read from the file, or None if unreadable.
        """
        norm_vpath = normalize_virtual_path(virtual_path)
        if norm_vpath in self.virtual_paths:
            phys = self.virtual_paths[norm_vpath]
            try:
                if not os.path.isfile(phys):
                    return None
                with open(phys, "rb") as f:
                    return f.read(max_bytes)
            except OSError:
                return None
        if self.root_path:
            return safe_read_bytes(self.root_path, norm_vpath, max_bytes=max_bytes)
        return None

    def read_text(
        self,
        virtual_path: str,
        max_bytes: int = 1_048_576,
        encoding: str = "utf-8",
        errors: str = "replace",
    ) -> str | None:
        """Read text from a virtual path up to max_bytes.

        Args:
            virtual_path: Virtual path of the file to read.
            max_bytes: Maximum number of bytes to read.
            encoding: Text encoding to use.
            errors: Error handling scheme for decoding.

        Returns:
            Decoded text string, or None if unreadable.
        """
        data = self.read_bytes(virtual_path, max_bytes=max_bytes)
        if data is None:
            return None
        return data.decode(encoding=encoding, errors=errors)

    def glob(self, pattern: str) -> list[str]:
        """Find virtual paths matching a glob pattern.

        Args:
            pattern: Glob pattern (e.g. '/etc/systemd/system/*.service').

        Returns:
            Sorted list of matching normalized virtual paths.
        """
        matches: set[str] = set()
        norm_pattern = normalize_virtual_path(pattern)

        # Match against mapped virtual paths
        for vpath in self.virtual_paths:
            if fnmatch.fnmatch(vpath, norm_pattern):
                matches.add(vpath)

        # Match against filesystem tree under root_path if available
        if self.root_path and os.path.isdir(self.root_path):
            root_abs = os.path.abspath(self.root_path)
            for dirpath, _, filenames in os.walk(root_abs, followlinks=False):
                for fname in filenames:
                    full_phys = os.path.join(dirpath, fname)
                    rel = os.path.relpath(full_phys, root_abs)
                    vpath = normalize_virtual_path(rel)
                    if fnmatch.fnmatch(vpath, norm_pattern):
                        matches.add(vpath)

        return sorted(matches)

    def resolve_symlink(self, virtual_path: str) -> str | None:
        """Safely resolve symlinks constrained to target root.

        Args:
            virtual_path: Virtual path of the symlink to resolve.

        Returns:
            Normalized virtual target path, or None if invalid or escapes root.
        """
        norm_vpath = normalize_virtual_path(virtual_path)
        if self.root_path:
            return safe_resolve_symlink(self.root_path, norm_vpath)
        if norm_vpath in self.virtual_paths:
            phys = self.virtual_paths[norm_vpath]
            try:
                if os.path.islink(phys):
                    target = os.readlink(phys)
                    parent_vdir = posixpath.dirname(norm_vpath)
                    return _resolve_virtual_symlink_target(parent_vdir, target)
            except OSError:
                return None
        return None


# Alias ArtifactTarget to AnalysisTarget for interchangeable naming across modules
ArtifactTarget = AnalysisTarget


@dataclass
class AnalysisContext:
    """Forensic context carrying analysis target, detected OS, and host information."""

    target: AnalysisTarget
    os_name: str = "linux"
    hostname: str = "unknown"


__all__ = [
    "AnalysisContext",
    "AnalysisTarget",
    "ArtifactTarget",
    "Finding",
    "PathTraversalSecurityError",
    "ReportMeta",
    "RiskLevel",
    "normalize_virtual_path",
    "safe_read_bytes",
    "safe_read_text",
    "safe_resolve_path",
    "safe_resolve_symlink",
]
