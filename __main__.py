# -*- coding: utf-8 -*-
"""
security_engine/__main__.py
===========================
Standalone CLI, UI launcher, and self-test suite for `security_engine`.

Commands:
    python -m security_engine --ui
    python -m security_engine --self-test
    python -m security_engine path/to/file.pdf --safe-dir ./safe
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from security_engine import (
        FileSizeExceededError,
        ForbiddenExtensionError,
        InvalidFilePathError,
        SecurityEngine,
        SecurityRejectedError,
        SpoofedSignatureError,
    )
else:
    from .engine import SecurityEngine
    from .exceptions import (
        FileSizeExceededError,
        ForbiddenExtensionError,
        InvalidFilePathError,
        SecurityRejectedError,
        SpoofedSignatureError,
    )


def _configure_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def launch_ui() -> None:
    app_path = Path(__file__).resolve().parent / "ui" / "app.py"
    subprocess.run([sys.executable, str(app_path)], check=False)


def run_self_test() -> None:
    _configure_utf8()
    print("=" * 64)
    print("  SecurityEngine — Standalone Self-Test Suite")
    print("=" * 64)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        sec = SecurityEngine(safe_dir=tmp / "safe_zone", max_size_mb=1.0, mode="copy")

        # 1. Forbidden extension (.exe)
        bad_exe = tmp / "malware.exe"
        bad_exe.write_bytes(b"MZ\x90\x00dummy")
        try:
            sec.inspect(bad_exe)
            raise AssertionError("Expected ForbiddenExtensionError")
        except ForbiddenExtensionError:
            print("  [PASS] Forbidden extension (.exe) rejected")

        # 2. Disguised executable inside .pdf
        spoof_pdf = tmp / "invoice.pdf"
        spoof_pdf.write_bytes(b"MZ\x90\x00disguised_binary")
        try:
            sec.inspect(spoof_pdf)
            raise AssertionError("Expected SpoofedSignatureError")
        except SpoofedSignatureError:
            print("  [PASS] Magic-byte spoofed PDF rejected")

        # 3. Empty 0-byte file
        empty_f = tmp / "empty.txt"
        empty_f.write_bytes(b"")
        try:
            sec.inspect(empty_f)
            raise AssertionError("Expected InvalidFilePathError")
        except InvalidFilePathError:
            print("  [PASS] Empty 0-byte file rejected")

        # 4. Oversized file (> 1 MB test limit)
        huge_f = tmp / "oversized.pdf"
        huge_f.write_bytes(b"%PDF-1.7\n" + (b"A" * (1024 * 1024 + 512)))
        try:
            sec.inspect(huge_f)
            raise AssertionError("Expected FileSizeExceededError")
        except FileSizeExceededError:
            print("  [PASS] Oversized file limit enforced")

        # 5. Valid PDF passes, returns SHA-256 + MD5, and works with os.fspath()
        good_pdf = tmp / "clean_doc.pdf"
        good_pdf.write_bytes(b"%PDF-1.7\nValid PDF body content")
        res = sec.inspect(good_pdf)
        assert res.safe_path.exists()
        assert len(res.sha256_hash) == 64 and res.file_hash == res.sha256_hash
        assert len(res.md5_hash) == 32
        assert Path(os.fspath(res)) == res.safe_path
        print(
            f"  [PASS] Valid PDF accepted -> sha256={res.sha256_hash[:16]}... "
            f"| md5={res.md5_hash[:12]}..."
        )

    print("=" * 64)
    print("  ALL SECURITY ENGINE SELF-TESTS PASSED SUCCESSFULLY!")
    print("=" * 64)


def main() -> None:
    _configure_utf8()
    parser = argparse.ArgumentParser(description="SecurityEngine Standalone CLI & UI")
    parser.add_argument("target", nargs="?", help="File or directory path to inspect")
    parser.add_argument("--safe-dir", type=str, default=None, help="Destination directory for safe files")
    parser.add_argument("--mode", choices=["copy", "move", "in_place"], default="copy")
    parser.add_argument("--max-mb", type=float, default=100.0, help="Max file size in MB")
    parser.add_argument("--ui", action="store_true", help="Launch calm standalone Web UI")
    parser.add_argument("--self-test", action="store_true", help="Run standalone security test suite")
    args = parser.parse_args()

    if args.ui:
        launch_ui()
        return

    if args.self_test:
        run_self_test()
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    sec = SecurityEngine(safe_dir=args.safe_dir, max_size_mb=args.max_mb, mode=args.mode)
    target = Path(args.target)

    try:
        if target.is_dir():
            report = sec.inspect_directory(target)
            print(
                json.dumps(
                    {
                        "processed": report["processed"],
                        "safe_count": report["safe_count"],
                        "rejected_count": report["rejected_count"],
                        "accepted": [r.to_dict() for r in report["accepted"]],
                        "rejected": report["rejected"],
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            res = sec.inspect(target)
            print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
    except SecurityRejectedError as err:
        print(json.dumps(err.to_dict(), ensure_ascii=False, indent=2), file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
