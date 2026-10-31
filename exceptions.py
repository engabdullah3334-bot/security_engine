# -*- coding: utf-8 -*-
"""
security_engine/exceptions.py
=============================
Structured security rejection exceptions raised when an unverified file fails
any layer of the security audit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class SecurityRejectedError(Exception):
    """
    Base exception raised whenever `SecurityEngine` rejects an unverified file.
    """

    code: str = "SECURITY_REJECTED"

    def __init__(
        self,
        reason: str,
        file_path: str | Path | None = None,
        code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.file_path = str(file_path) if file_path is not None else None
        if code is not None:
            self.code = code
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_safe": False,
            "code": self.code,
            "reason": self.reason,
            "file_path": self.file_path,
            "details": self.details,
        }


class InvalidFilePathError(SecurityRejectedError):
    """Raised when the file is missing, unreadable, empty (0 bytes), or a directory."""

    code = "INVALID_FILE"


class ForbiddenExtensionError(SecurityRejectedError):
    """Raised when the file extension is blacklisted or outside allowed_extensions."""

    code = "FORBIDDEN_EXTENSION"


class FileSizeExceededError(SecurityRejectedError):
    """Raised when the file exceeds the configured maximum size in MB."""

    code = "FILE_SIZE_EXCEEDED"


class SpoofedSignatureError(SecurityRejectedError):
    """Raised when magic bytes reveal a disguised executable or mismatched file header."""

    code = "SPOOFED_SIGNATURE"


class ArchiveBombError(SecurityRejectedError):
    """Raised when a ZIP/OOXML container exhibits zip-bomb characteristics or corruption."""

    code = "ARCHIVE_BOMB"

