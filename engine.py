# -*- coding: utf-8 -*-
"""
security_engine/engine.py
=========================
`SecurityEngine` — Standalone entry-gate security auditing & hashing module.

Input:
    Raw, uninspected file path (`str | Path`).
Output:
    `SecurityResult` containing the verified `safe_path`, primary `SHA-256`
    (`file_hash` / `sha256_hash`), legacy `md5_hash`, size, and MIME type —
    OR raises `SecurityRejectedError` (with exact rejection subclass & reason).
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import zipfile
from pathlib import Path
from typing import Any

from .exceptions import (
    ArchiveBombError,
    FileSizeExceededError,
    ForbiddenExtensionError,
    InvalidFilePathError,
    SecurityRejectedError,
    SpoofedSignatureError,
)
from .schemas import DEFAULT_FORBIDDEN_EXTENSIONS, SecurityPolicy, SecurityResult

MIME_MAP: dict[str, str] = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".html": "text/html",
    ".htm": "text/html",
    ".json": "application/json",
    ".csv": "text/csv",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
}

_SAFE_FILENAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def calculate_hashes(file_path: str | Path, chunk_size: int = 65536) -> tuple[str, str]:
    """
    Compute BOTH SHA-256 and MD5 checksums in a single streaming disk read.

    Returns:
        `(sha256_hex, md5_hex)`
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, "rb") as fh:
        while True:
            buf = fh.read(chunk_size)
            if not buf:
                break
            sha256.update(buf)
            md5.update(buf)
    return sha256.hexdigest(), md5.hexdigest()


def resolve_mime_type(ext: str) -> str:
    """Map lowercase extension (with leading dot) to its canonical MIME string."""
    return MIME_MAP.get(ext.lower(), "application/octet-stream")


def sanitize_filename(name: str) -> str:
    """Strip path separators and dangerous control characters from a file name."""
    base = Path(name).name.strip()
    cleaned = _SAFE_FILENAME_RE.sub("_", base)
    return cleaned or "unnamed_file"


class SecurityEngine:
    """
    Standalone Security Auditing Engine.

    Usage:
        from security_engine import SecurityEngine, SecurityRejectedError

        sec = SecurityEngine(safe_dir="./safe_files")
        result = sec.inspect("raw_upload.pdf")
        print(result.safe_path, result.file_hash)
    """

    def __init__(
        self,
        safe_dir: str | Path | None = None,
        max_size_mb: float = 100.0,
        allowed_extensions: set[str] | list[str] | None = None,
        forbidden_extensions: set[str] | list[str] | None = None,
        mode: str = "copy",
    ) -> None:
        default_safe = Path(__file__).resolve().parent / "safe_files"
        self.safe_dir = Path(safe_dir).resolve() if safe_dir else default_safe.resolve()

        norm_allowed = (
            {e.lower() if e.startswith(".") else f".{e.lower()}" for e in allowed_extensions}
            if allowed_extensions is not None
            else None
        )
        norm_forbidden = (
            {e.lower() if e.startswith(".") else f".{e.lower()}" for e in forbidden_extensions}
            if forbidden_extensions is not None
            else set(DEFAULT_FORBIDDEN_EXTENSIONS)
        )

        if mode not in ("copy", "move", "in_place"):
            raise ValueError("`mode` must be one of: 'copy', 'move', or 'in_place'.")

        self.policy = SecurityPolicy(
            max_size_mb=max_size_mb,
            forbidden_extensions=norm_forbidden,
            allowed_extensions=norm_allowed,
            transfer_mode=mode,
        )

    # ── Core Inspection Entry Point ──────────────────────────────────────────

    def inspect(
        self,
        file_path: str | Path | os.PathLike[str],
        safe_dir: str | Path | None = None,
        mode: str | None = None,
    ) -> SecurityResult:
        """
        Audit a raw file through 5 defense layers and place it in `safe_dir`.

        Raises:
            SecurityRejectedError (or specific subclass) if ANY check fails.
        """
        src_path = Path(file_path).resolve()

        # Layer 1 — Existence, File Type, & Non-Empty Check
        if not src_path.exists():
            raise InvalidFilePathError(
                f"File does not exist: '{src_path}'", file_path=src_path
            )
        if not src_path.is_file():
            raise InvalidFilePathError(
                f"Target path is not a regular file: '{src_path}'", file_path=src_path
            )

        try:
            file_size = src_path.stat().st_size
        except OSError as exc:
            raise InvalidFilePathError(
                f"Cannot stat file: {exc}", file_path=src_path
            ) from exc

        if file_size == 0:
            raise InvalidFilePathError(
                "Empty (0-byte) files are rejected.", file_path=src_path
            )

        # Layer 2 — Extension Blacklist & Optional Whitelist
        ext = src_path.suffix.lower()
        if ext in self.policy.forbidden_extensions:
            raise ForbiddenExtensionError(
                f"Forbidden executable/script extension: '{ext}'",
                file_path=src_path,
                details={"extension": ext},
            )
        if self.policy.allowed_extensions is not None and ext not in self.policy.allowed_extensions:
            raise ForbiddenExtensionError(
                f"Extension '{ext}' is not in the allowed extensions list.",
                file_path=src_path,
                details={
                    "extension": ext,
                    "allowed": sorted(self.policy.allowed_extensions),
                },
            )

        # Layer 3 — Maximum File Size Enforcement
        if file_size > self.policy.max_size_bytes:
            actual_mb = round(file_size / (1024 * 1024), 2)
            raise FileSizeExceededError(
                f"File size ({actual_mb} MB) exceeds the {self.policy.max_size_mb} MB limit.",
                file_path=src_path,
                details={"file_size_mb": actual_mb, "max_size_mb": self.policy.max_size_mb},
            )

        # Layer 4 — Magic-Bytes & Container Integrity / Zip-Bomb Verification
        self._verify_magic_and_container(src_path, ext, file_size)

        # Layer 5 — Dual Cryptographic Hashing (SHA-256 primary + MD5 legacy)
        sha256_hex, md5_hex = calculate_hashes(src_path)

        # Safe Zone Placement
        active_mode = mode or self.policy.transfer_mode
        target_dir = Path(safe_dir).resolve() if safe_dir else self.safe_dir
        final_safe_path = self._place_in_safe_zone(
            src_path=src_path,
            sha256_hex=sha256_hex,
            target_dir=target_dir,
            mode=active_mode,
        )

        return SecurityResult(
            safe_path=final_safe_path,
            file_hash=sha256_hex,
            sha256_hash=sha256_hex,
            md5_hash=md5_hex,
            original_path=src_path,
            file_name=sanitize_filename(src_path.name),
            file_size=file_size,
            mime_type=resolve_mime_type(ext),
            extension=ext,
            safety_details="File passed all 5 security audit layers",
        )

    def inspect_directory(
        self,
        source_dir: str | Path,
        safe_dir: str | Path | None = None,
        mode: str | None = None,
    ) -> dict[str, Any]:
        """
        Batch-inspect all files in `source_dir` without aborting on individual rejections.
        Returns a structured summary with `accepted` (`list[SecurityResult]`) and `rejected`.
        """
        src_root = Path(source_dir).resolve()
        if not src_root.exists() or not src_root.is_dir():
            raise InvalidFilePathError(
                f"Directory does not exist: '{src_root}'", file_path=src_root
            )

        accepted: list[SecurityResult] = []
        rejected: list[dict[str, Any]] = []

        for item in sorted(src_root.glob("**/*")):
            if not item.is_file():
                continue
            try:
                res = self.inspect(item, safe_dir=safe_dir, mode=mode)
                accepted.append(res)
            except SecurityRejectedError as err:
                rejected.append(err.to_dict())

        return {
            "processed": len(accepted) + len(rejected),
            "safe_count": len(accepted),
            "rejected_count": len(rejected),
            "accepted": accepted,
            "rejected": rejected,
        }

    # ── Internal Security Helpers ────────────────────────────────────────────

    def _verify_magic_and_container(
        self, src_path: Path, ext: str, file_size: int
    ) -> None:
        try:
            with open(src_path, "rb") as fh:
                header = fh.read(16)
        except OSError as exc:
            raise InvalidFilePathError(
                f"Unable to read file header: {exc}", file_path=src_path
            ) from exc

        # Universal executable disguise checks
        if header[:2] == b"MZ":
            raise SpoofedSignatureError(
                "Disguised Windows executable detected (MZ/PE header).",
                file_path=src_path,
            )
        if header[:4] == b"\x7fELF":
            raise SpoofedSignatureError(
                "Disguised Linux ELF binary detected.",
                file_path=src_path,
            )

        # Format-specific magic signatures
        if ext == ".pdf" and not header.startswith(b"%PDF"):
            raise SpoofedSignatureError(
                "File has '.pdf' extension but lacks a valid '%PDF' signature.",
                file_path=src_path,
            )

        if ext in {".docx", ".xlsx", ".pptx"}:
            if header[:4] != b"PK\x03\x04":
                raise SpoofedSignatureError(
                    f"File labeled as '{ext}' lacks a valid Office Open XML (PK/ZIP) header.",
                    file_path=src_path,
                )
            self._check_zip_safety(src_path, compressed_file_size=file_size)

        if ext == ".png" and header[:8] != b"\x89PNG\r\n\x1a\n":
            raise SpoofedSignatureError(
                "File labeled as '.png' lacks a valid PNG header.",
                file_path=src_path,
            )

        if ext in {".jpg", ".jpeg"} and header[:3] != b"\xff\xd8\xff":
            raise SpoofedSignatureError(
                f"File labeled as '{ext}' lacks a valid JPEG header.",
                file_path=src_path,
            )

        if ext in {".txt", ".md", ".html", ".htm", ".csv", ".json"}:
            # Reject raw null-byte binary payloads masquerading as plain text
            try:
                with open(src_path, "rb") as fh:
                    sample = fh.read(4096)
                if b"\x00\x00" in sample and header[:2] not in (b"\xff\xfe", b"\xfe\xff"):
                    raise SpoofedSignatureError(
                        f"Binary payload detected inside text file '{ext}'.",
                        file_path=src_path,
                    )
            except SpoofedSignatureError:
                raise
            except OSError as exc:
                raise InvalidFilePathError(str(exc), file_path=src_path) from exc

    def _check_zip_safety(self, zip_path: Path, compressed_file_size: int) -> None:
        """Inspect OOXML/ZIP central directory for corruption or Zip-Bomb attacks."""
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                total_uncompressed = sum(info.file_size for info in zf.infolist())
        except zipfile.BadZipFile as exc:
            raise SpoofedSignatureError(
                f"Corrupted or invalid Office/ZIP container: {exc}",
                file_path=zip_path,
            ) from exc

        if total_uncompressed > self.policy.max_zip_uncompressed_bytes:
            uncomp_mb = round(total_uncompressed / (1024 * 1024), 1)
            raise ArchiveBombError(
                f"Uncompressed container size ({uncomp_mb} MB) exceeds safety ceiling.",
                file_path=zip_path,
            )

        if compressed_file_size > 0:
            ratio = total_uncompressed / compressed_file_size
            if ratio > self.policy.max_zip_ratio and total_uncompressed > 10 * 1024 * 1024:
                raise ArchiveBombError(
                    f"Suspicious compression ratio ({ratio:.1f}x) — potential Zip Bomb.",
                    file_path=zip_path,
                )

    def _place_in_safe_zone(
        self,
        src_path: Path,
        sha256_hex: str,
        target_dir: Path,
        mode: str,
    ) -> Path:
        if mode == "in_place":
            return src_path

        target_dir.mkdir(parents=True, exist_ok=True)
        clean_name = sanitize_filename(src_path.name)
        dest = target_dir / clean_name

        if dest.resolve() == src_path.resolve():
            return dest

        if dest.exists():
            existing_sha256, _ = calculate_hashes(dest)
            if existing_sha256 == sha256_hex:
                # Identical safe file already in safe_dir — no duplicate clutter!
                if mode == "move" and src_path.exists():
                    src_path.unlink(missing_ok=True)
                return dest

            stem = Path(clean_name).stem
            suffix = Path(clean_name).suffix
            counter = 1
            while dest.exists():
                candidate = target_dir / f"{stem}_{counter}{suffix}"
                if candidate.exists():
                    cand_sha, _ = calculate_hashes(candidate)
                    if cand_sha == sha256_hex:
                        if mode == "move" and src_path.exists():
                            src_path.unlink(missing_ok=True)
                        return candidate
                dest = candidate
                counter += 1

        if mode == "move":
            shutil.move(str(src_path), str(dest))
        else:
            shutil.copy2(str(src_path), str(dest))

        return dest.resolve()

