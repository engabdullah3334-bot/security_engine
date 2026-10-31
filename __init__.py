# -*- coding: utf-8 -*-
"""
security_engine
===============
Standalone entry-gate security auditing & cryptographic hashing engine.

Usage:
    from security_engine import SecurityEngine, SecurityRejectedError

    sec = SecurityEngine(safe_dir="./safe_files")
    result = sec.inspect("raw_document.pdf")
"""

from .engine import SecurityEngine, calculate_hashes, resolve_mime_type
from .exceptions import (
    ArchiveBombError,
    FileSizeExceededError,
    ForbiddenExtensionError,
    InvalidFilePathError,
    SecurityRejectedError,
    SpoofedSignatureError,
)
from .schemas import SecurityPolicy, SecurityResult

__all__ = [
    "SecurityEngine",
    "SecurityPolicy",
    "SecurityResult",
    "SecurityRejectedError",
    "InvalidFilePathError",
    "ForbiddenExtensionError",
    "FileSizeExceededError",
    "SpoofedSignatureError",
    "ArchiveBombError",
    "calculate_hashes",
    "resolve_mime_type",
]

