# -*- coding: utf-8 -*-
"""
security_engine/schemas.py
==========================
Typed configuration and output contracts for `SecurityEngine`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_FORBIDDEN_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe", ".dll", ".bat", ".cmd", ".sh", ".py", ".js",
        ".vbs", ".msi", ".scr", ".pif", ".reg", ".ps1", ".com",
        ".jar", ".hta", ".cpl", ".wsf", ".so", ".dylib",
    }
)


@dataclass
class SecurityPolicy:
    """Configurable security rules applied by `SecurityEngine`."""

    max_size_mb: float = 100.0
    forbidden_extensions: set[str] = field(
        default_factory=lambda: set(DEFAULT_FORBIDDEN_EXTENSIONS)
    )
    allowed_extensions: set[str] | None = None
    max_zip_uncompressed_mb: float = 500.0
    max_zip_ratio: float = 120.0
    transfer_mode: str = "copy"  # "copy" | "move" | "in_place"

    @property
    def max_size_bytes(self) -> int:
        return int(self.max_size_mb * 1024 * 1024)

    @property
    def max_zip_uncompressed_bytes(self) -> int:
        return int(self.max_zip_uncompressed_mb * 1024 * 1024)


@dataclass
class SecurityResult:
    """
    Output returned by `SecurityEngine.inspect()` when a file passes all checks.

    Implements `__fspath__` (`os.PathLike`), so `SecurityResult` can be passed
    directly anywhere a file path is expected (e.g., `extractor.extract(sec_res)`).
    """

    safe_path: Path
    file_hash: str          # Primary cryptographic reference: SHA-256 hex digest
    sha256_hash: str        # Explicit SHA-256 hex digest
    md5_hash: str           # Legacy-compatible MD5 hex digest
    original_path: Path
    file_name: str
    file_size: int
    mime_type: str
    extension: str
    safety_details: str = "File passed all security checks"
    inspected_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def __fspath__(self) -> str:
        return str(self.safe_path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_safe": True,
            "safe_path": str(self.safe_path),
            "file_hash": self.file_hash,
            "sha256_hash": self.sha256_hash,
            "md5_hash": self.md5_hash,
            "original_path": str(self.original_path),
            "file_name": self.file_name,
            "file_size": self.file_size,
            "mime_type": self.mime_type,
            "extension": self.extension,
            "safety_details": self.safety_details,
            "inspected_at": self.inspected_at,
        }

