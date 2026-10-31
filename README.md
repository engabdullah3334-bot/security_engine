# `security_engine` — Entry-Gate File Auditing & Cryptographic Hashing

**`security_engine`** is a standalone, zero-dependency Python security module designed to act as the first line of defense for any file-processing pipeline or web service.

### Engineering Problem Solved
Accepting raw user-uploaded files directly into document parsers, OCR tools, or archive extractors exposes applications to disguised executables (`MZ` / `ELF` binaries renamed to `.pdf`), corrupted containers, path-traversal filenames, oversized payloads, and decompression Zip Bombs inside `.docx`/`.xlsx`/`.pptx` archives. In addition, downstream databases need both modern cryptographic identity (`SHA-256`) and legacy checksum compatibility (`MD5`) without reading large files from disk twice.

`SecurityEngine` solves these problems in a single deterministic gate: it validates files across five defense layers, computes `SHA-256` and `MD5` simultaneously in one streaming pass, places accepted files into a sanitized safe zone with hash-based deduplication, and raises structured `SecurityRejectedError` subclasses when any check fails.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Testing](#testing)
- [License and Contributing](#license-and-contributing)

---

## Prerequisites

- **Operating System:** Windows, Linux, or macOS.
- **Python:** `>= 3.10`
- **External Libraries:** **None.** Runs 100% on the Python Standard Library (`hashlib`, `zipfile`, `shutil`, `pathlib`, `http.server`).
- **Database Requirements:** None (stateless file auditor; outputs integrate directly with `StorageEngine.save_security()` if desired).

---

## Installation

### Option A: Within the Full Workspace

```powershell
git clone <repository-url> engines
cd engines
python -m venv .venv
.\.venv\Scripts\Activate.ps1
# No third-party packages required for security_engine
python -m security_engine --self-test
```

### Option B: Standalone Copy into Any External Project

```powershell
Copy-Item -Recurse .\security_engine C:\path\to\your_project\security_engine
```

---

## Usage

### 1. Python API Example

```python
from security_engine import (
    SecurityEngine,
    SecurityRejectedError,
    SpoofedSignatureError,
)

security = SecurityEngine(
    safe_dir="./safe_files",
    max_size_mb=100.0,
    mode="copy",
)

try:
    result = security.inspect("incoming/contract.pdf")
    print("Safe Path :", result.safe_path)
    print("SHA-256   :", result.sha256_hash)
    print("MD5       :", result.md5_hash)
    # `result` implements os.PathLike and can be passed directly to open() or Path()
except SpoofedSignatureError as spoof_err:
    print("Blocked disguised binary:", spoof_err.to_dict())
except SecurityRejectedError as sec_err:
    print(f"Rejected [{sec_err.code}]: {sec_err.reason}")
```

### 2. Command-Line Interface & Calm Standalone Web UI

```powershell
# Inspect a single file from the terminal
python -m security_engine ./uploads/report.pdf --safe-dir ./safe_files --max-mb 50

# Batch-audit an entire directory of untrusted files
python -m security_engine ./uploads --safe-dir ./safe_files --mode copy

# Launch the calm standalone Web UI in your browser
python -m security_engine --ui
```

### 3. Expected Input & Output Shapes

- **Input:** Path to an uninspected file (`str | Path | os.PathLike`).
- **Accepted Output (`SecurityResult.to_dict()`):**
  ```json
  {
    "is_safe": true,
    "safe_path": "C:/programming/engines/security_engine/safe_files/report.pdf",
    "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
    "original_path": "C:/uploads/report.pdf",
    "file_name": "report.pdf",
    "file_size": 204800,
    "mime_type": "application/pdf",
    "extension": ".pdf",
    "safety_details": "File passed all security checks",
    "inspected_at": "2026-10-30T19:00:00"
  }
  ```
- **Rejected Output (Raised `SecurityRejectedError.to_dict()`):**
  ```json
  {
    "is_safe": false,
    "code": "SPOOFED_SIGNATURE",
    "reason": "Disguised Windows executable detected (MZ/PE header).",
    "file_path": "C:/uploads/invoice.pdf",
    "details": {}
  }
  ```

---

## Architecture

### Package File Structure

```text
security_engine/
├── __init__.py          # Public exports: SecurityEngine, SecurityPolicy, SecurityResult, exceptions
├── __main__.py          # CLI entry point, --ui launcher, and --self-test verification suite
├── engine.py            # 5-layer inspection pipeline, streaming dual-hasher, & safe-zone placement
├── schemas.py           # SecurityPolicy, SecurityResult (os.PathLike), DEFAULT_FORBIDDEN_EXTENSIONS
├── exceptions.py        # SecurityRejectedError hierarchy with machine-readable error codes
├── requirements.txt     # Documents zero external dependencies
├── ui/
│   ├── __init__.py
│   └── app.py           # Zero-dependency calm standalone HTTP Web UI (port 8701)
└── README.md
```

### Internal 5-Layer Inspection Data Flow

```text
Raw File Path
  ├─► Layer 1: Existence, Regular-File Verification, & Non-Zero Byte Check (InvalidFilePathError)
  ├─► Layer 2: Forbidden Extension Blacklist & Optional Whitelist Policy (ForbiddenExtensionError)
  ├─► Layer 3: Byte-Size Ceiling Enforcement against max_size_mb (FileSizeExceededError)
  ├─► Layer 4: Magic-Byte Header Verification (MZ/ELF block, %PDF, PK/ZIP, PNG, JPEG, null-byte text guard)
  │            + OOXML/ZIP Uncompressed Ceiling & Compression Ratio Bomb Check (SpoofedSignatureError / ArchiveBombError)
  └─► Layer 5: Single-Pass 64 KB Streaming SHA-256 + MD5 Computation & Deduplicated Safe-Zone Placement
        └─► Returns SecurityResult
```

---

## Configuration

`SecurityEngine` is configured via constructor arguments backed by the `SecurityPolicy` dataclass (no external `.env` file required):

| Parameter / Policy Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `safe_dir` | `str \| Path \| None` | `security_engine/safe_files` | Destination folder for verified files. |
| `max_size_mb` | `float` | `100.0` | Maximum allowed file size in megabytes. |
| `allowed_extensions` | `set[str] \| list[str] \| None` | `None` (all non-forbidden) | Optional strict whitelist (e.g., `{".pdf", ".docx"}`). |
| `forbidden_extensions` | `set[str] \| list[str] \| None` | `DEFAULT_FORBIDDEN_EXTENSIONS` | Blocks `.exe`, `.dll`, `.bat`, `.cmd`, `.sh`, `.py`, `.js`, `.ps1`, `.msi`, `.jar`, etc. |
| `mode` / `transfer_mode` | `str` | `"copy"` | `"copy"` (preserve source), `"move"`, or `"in_place"` (audit without copying). |
| `max_zip_uncompressed_mb` | `float` | `500.0` | Maximum total uncompressed size permitted inside ZIP/OOXML files. |
| `max_zip_ratio` | `float` | `120.0` | Maximum allowed decompression ratio (`uncompressed / compressed`) above 10 MB. |
| `--port` (UI CLI flag) | `int` | `8701` (auto-fallback) | Localhost port for `python security_engine/ui/app.py`. |

---

## API Reference

### `SecurityEngine`

- **`SecurityEngine(safe_dir=None, max_size_mb=100.0, allowed_extensions=None, forbidden_extensions=None, mode="copy")`**
  Initializes the auditor with a `SecurityPolicy`.
- **`inspect(file_path: str | Path | os.PathLike, safe_dir: str | Path | None = None, mode: str | None = None) -> SecurityResult`**
  Audits a single file across all five layers, places it into `safe_dir` (with automatic `SHA-256` deduplication if an identical file already exists), and returns `SecurityResult`. Raises `SecurityRejectedError` on failure.
- **`inspect_directory(directory_path: str | Path, recursive: bool = False) -> dict[str, Any]`**
  Audits every file in a directory without aborting on individual rejections. Returns `{"processed": int, "safe_count": int, "rejected_count": int, "accepted": list[SecurityResult], "rejected": list[dict]}`.

### Utility Functions & Exception Hierarchy

- **`calculate_hashes(file_path: str | Path, chunk_size: int = 65536) -> tuple[str, str]`**
  Returns `(sha256_hex, md5_hex)` in a single streaming file read.
- **`sanitize_filename(name: str) -> str`**
  Strips directory traversal components and unsafe control characters.
- **Exceptions (`security_engine.exceptions`):**
  - `SecurityRejectedError` (base class; `.code`, `.reason`, `.file_path`, `.details`, `.to_dict()`)
  - `InvalidFilePathError` (`code="INVALID_FILE"`)
  - `ForbiddenExtensionError` (`code="FORBIDDEN_EXTENSION"`)
  - `FileSizeExceededError` (`code="FILE_SIZE_EXCEEDED"`)
  - `SpoofedSignatureError` (`code="SPOOFED_SIGNATURE"`)
  - `ArchiveBombError` (`code="ARCHIVE_BOMB"`)

---

## Testing

Run the built-in self-test suite, which exercises valid PDF acceptance, `SHA-256`/`MD5` accuracy, `os.PathLike` compatibility, spoofed `MZ` executable rejection, forbidden `.exe` rejection, size-limit rejection, and Zip-Bomb detection:

```powershell
python -m security_engine --self-test
```

---

## License and Contributing

- **License:** MIT License.
- **Contributing:** Keep `security_engine` 100% pure Python Standard Library with zero cross-engine imports. Ensure all comments and docstrings are in English and that `python -m security_engine --self-test` passes before submitting a Pull Request.
