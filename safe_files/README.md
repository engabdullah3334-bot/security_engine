# Modular Processing Engines

**Modular Processing Engines** is an open-ended, decoupled Python software ecosystem (`*_engine`) designed for secure document ingestion, structured extraction, context-preserving chunking, structure-safe localization, AI embeddings/analysis/chat, and central relational-vector lineage persistence.

### Engineering Problem Solved
Traditional document-processing and RAG codebases suffer from tight coupling: security checks, PDF/OCR parsers, chunkers, translation models, LLM chat handlers, and database queries become entangled through shared global configurations and cross-module imports. Extracting a single capability into another project—or adding a new processing stage—requires rewriting half the stack, while tracking which stages have processed a given file becomes error-prone.

This repository solves that architectural bottleneck through three strict engineering guarantees:
1. **Zero Cross-Engine Coupling:** Every `*_engine/` directory is a 100% self-contained Python package with zero imports from sibling engines. Any single folder can be copied into an external codebase and used immediately.
2. **Uniform Multi-Surface Access:** Every engine exposes a single-entry Python Facade class, typed input/output `dataclass` contracts, a standalone CLI (`--self-test`, file processing), and a calm, zero-dependency browser Web UI (`--ui`) isolated from core logic.
3. **Chronological Multi-Engine Lineage:** When composed together, `storage_engine` serves as the central relational (`SQLite WAL`) and vector (`ChromaDB` / cosine) foundation, returning deterministic `StorageReceipt` IDs and tracking complete **File Engine Lineage** (`last_engine`, `engines_used`, and full audit history) across any built-in or pluggable engine stage.

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

| Requirement | Version / Details | Scope |
| :--- | :--- | :--- |
| **Operating System** | Windows 10/11, Linux, or macOS | All packages |
| **Python** | `>= 3.10` (tested through Python `3.14`) | All packages |
| **SQLite** | Built into Python standard library (`sqlite3`, WAL mode) | `storage_engine`, `ai_engine` |
| **Web Browser** | Any modern browser (Chrome, Edge, Firefox, Safari) | Standalone `--ui` & Studio UI |
| **Tesseract OCR** *(Optional)* | `tesseract >= 5.0` binary in system `PATH` (with `ara` / `eng` traineddata) | `extraction_engine` (scanned PDFs/images) |
| **Ollama** *(Optional)* | Local server at `http://localhost:11434` (`ollama serve`) | `ai_engine` live LLM & `translation_engine` intent router |
| **ChromaDB** *(Optional)* | `chromadb >= 0.5.0` (automatic pure-Python cosine fallback if absent) | `storage_engine` HNSW vector index |

> **Zero-Dependency Packages:** `security_engine`, `chunking_engine`, `storage_engine` (core SQLite + fallback cosine search), and all standalone Web UIs run exclusively on the **Python Standard Library** without third-party packages.

---

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url> engines
cd engines
```

### 2. Create and Activate a Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

### 3. Install Engine Dependencies

Install only the dependencies required for the engines you intend to run with full neural/document backends:

```powershell
# Document extraction (PDF, DOCX, HTML, OpenCV layout QA, OCR wrapper)
pip install -r extraction_engine/requirements.txt

# Neural NLLB-200 translation backend
pip install -r translation_engine/requirements.txt

# SentenceTransformers embeddings & Ollama Python client
pip install -r ai_engine/requirements.txt

# Optional HNSW persistent vector indexing for StorageEngine
pip install -r storage_engine/requirements.txt
```

### 4. Standalone Single-Engine Portability
To embed any individual engine into a separate project, copy its package folder directly:
```powershell
Copy-Item -Recurse .\security_engine C:\path\to\your_project\security_engine
```

---

## Usage

### 1. Composed End-to-End Python Pipeline

```python
from security_engine import SecurityEngine
from extraction_engine import ExtractionEngine
from chunking_engine import ChunkingEngine
from translation_engine import TranslationEngine
from ai_engine import AIEngine
from storage_engine import StorageEngine

# Initialize independent engines
security   = SecurityEngine(safe_dir="./safe_files", max_size_mb=100.0)
extractor  = ExtractionEngine(enable_ocr=True, ocr_lang="ara")
chunker    = ChunkingEngine(max_words=350, overlap_words=50)
translator = TranslationEngine()
storage    = StorageEngine(db_path="./data/master.db", vector_dir="./data/vectors")
ai         = AIEngine(llm_model="llama3", chat_store=storage)

# 1. Security Gate -> Safe Path + SHA-256 & MD5
sec_result = security.inspect("raw_upload.pdf")
r_sec = storage.save_security(sec_result)
file_id = r_sec.file_id

# 2. Structured Extraction -> Separated Headings, Texts, Tables, Media
doc = extractor.extract(sec_result)  # SecurityResult implements os.PathLike
r_ext = storage.save_extraction(file_id, doc)

# 3. Context-Preserving Chunking -> Independent Chunks + Breadcrumbs
chunks = chunker.chunk(doc)
r_chk = storage.save_chunks(file_id, chunks, extraction_id=r_ext.primary_id)

# 4. Structure-Preserving Translation
tr_chunks = translator.translate_chunks(chunks, target_lang="english")
translator.unload()
r_trn = storage.save_translations(file_id, tr_chunks, chunk_ids=r_chk.record_ids)

# 5. Embeddings, Analysis, & Pluggable Stage Persistence
vectors = ai.embed_chunks(chunks)
storage.save_embeddings(file_id, vectors, chunk_ids=r_chk.record_ids)
summary = ai.analyze(chunks, task="summarize")
storage.save_analysis(file_id, summary)

# Register output from any custom pipeline stage
storage.save_stage_output(file_id, engine_name="quality_gate", payload={"verified": True})

# 6. Inspect Chronological File Lineage
lineage = storage.get_file_lineage(file_id)
print("Last Engine:", lineage.last_engine, lineage.last_engine_status)
print("All Participating Engines:", lineage.engines_used)
```

### 2. Expected Input & Output Shapes across Stages

| Engine Package | Expected Input | Expected Output |
| :--- | :--- | :--- |
| `security_engine` | Raw file path (`str \| Path`) | `SecurityResult` (`safe_path`, `sha256_hash`, `md5_hash`) or `SecurityRejectedError` |
| `extraction_engine` | Safe file path or `SecurityResult` | `ExtractedDocument` (`headings`, `texts`, `tables`, `media`, `pages`) |
| `chunking_engine` | `ExtractedDocument`, `dict`, JSON, or text | `list[Chunk]` (`content`, `chapter_context`, `section_breadcrumb`, `ChunkMetadata`) |
| `translation_engine` | `list[Chunk]` + `target_lang` | `list[TranslatedChunk]` (preserving tables, links, IDs, and page bounds) |
| `ai_engine` | `list[Chunk]`, query `str`, or chat prompt | `list[EmbeddingRecord]`, `AnalysisResult`, or persisted `ChatResponse` |
| `storage_engine` | Any stage output + `file_id` | `StorageReceipt` (`file_id`, `run_id`, `primary_id`, `record_ids`) + `FileLineage` |

### 3. Launching Standalone Engine UIs & the Integrated Workbench UI

```powershell
# Launch the comprehensive End-to-End Integrated Workbench UI (default port 8700)
python examples/full_pipeline_demo.py --ui

# Launch any individual engine's calm standalone Web UI
python -m security_engine --ui
python -m extraction_engine --ui
python -m chunking_engine --ui
python -m translation_engine --ui
python -m ai_engine --ui
python -m storage_engine --ui
```

---

## Architecture

### Workspace Directory Layout

```text
engines/
├── security_engine/        # Entry-gate file auditing, magic-byte checks, & SHA-256 / MD5 hashing
├── extraction_engine/      # PDF / DOCX / HTML / TXT / MD structured extraction, Visual QA, & OCR
├── chunking_engine/        # Hierarchical chapter-aware semantic chunking & smart keyword tagging
├── translation_engine/     # Structure-preserving NLLB-200 neural translation & language routing
├── ai_engine/              # Dense embeddings, LLM text analysis, & persistent multi-session chatbot
├── storage_engine/         # SQLite WAL + vector persistence & chronological multi-engine lineage
├── examples/               # End-to-end CLI verifier & Modular Engines Studio Web Workbench
├── _legacy_archive/        # Archived legacy reference modules (excluded from active runtime)
└── README.md               # Ecosystem documentation
```

### Internal Data Flow & Decoupled Orchestration

```text
[Raw File]
    │
    ▼
┌───────────────────┐    SecurityResult (safe_path + SHA-256 + MD5)
│  security_engine  ├──────────────────────────────────────────────┐
└─────────┬─────────┘                                              │
          ▼                                                        ▼
┌───────────────────┐    ExtractedDocument (headings/texts/tables) │
│ extraction_engine ├──────────────────────────────────────────────┤
└─────────┬─────────┘                                              │
          ▼                                                        ▼
┌───────────────────┐    list[Chunk] (metadata + breadcrumbs)    ┌───────────────────┐
│  chunking_engine  ├───────────────────────────────────────────►│  storage_engine   │
└─────────┬─────────┘                                            │  ───────────────  │
          ├──────────────────────────┐                           │ • Relational DB   │
          ▼                          ▼                           │ • Vector Search   │
┌────────────────────┐     ┌───────────────────┐                 │ • Chat Archive    │
│ translation_engine │     │     ai_engine     ├────────────────►│ • FileLineage     │
└─────────┬──────────┘     └───────────────────┘                 │ • Custom Stages   │
          │  list[TranslatedChunk]                               └───────────────────┘
          └────────────────────────────────────────────────────────▲
```

Engines never call or import one another directly; an application or orchestrator passes plain Python data contracts (or `dict` / JSON payloads) from one stage to the next and records receipts in `StorageEngine`.

---

## Configuration

| Variable / Setting | Affected Engine(s) | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `OLLAMA_BASE_URL` | `ai_engine`, `translation_engine` | `http://localhost:11434` | Base HTTP endpoint for local Ollama LLM inference. |
| `OLLAMA_MODEL` | `ai_engine`, `translation_engine` | `llama3` | Default Ollama model tag used for chat, analysis, and intent routing. |
| `safe_dir` | `security_engine` | `security_engine/safe_files` | Target directory where audited safe files are copied or moved. |
| `media_dir` | `extraction_engine` | `extraction_engine/extracted_media` | Directory where extracted inline figures and cropped images are saved. |
| `chat_db_path` | `ai_engine` | `ai_engine/data/chat_history.db` | Local SQLite archive used when `AIEngine` runs standalone without `StorageEngine`. |
| `db_path` | `storage_engine` | `storage_engine/data/storage_core.db` | Primary SQLite WAL database file path. |
| `vector_dir` | `storage_engine` | `storage_engine/data/chroma_vectors` | Directory for persistent ChromaDB HNSW vector collections. |

### Default Web UI Ports (Auto-Fallback to Free Ephemeral Port if Busy)

| Interface | Launch Command | Preferred Localhost Port |
| :--- | :--- | :--- |
| **Modular Engines Studio (`examples`)** | `python examples/full_pipeline_demo.py --ui` | `8700` |
| **Security Engine UI** | `python -m security_engine --ui` | `8701` |
| **Extraction Engine UI** | `python -m extraction_engine --ui` | `8702` |
| **Chunking Engine UI** | `python -m chunking_engine --ui` | `8703` |
| **Translation Engine UI** | `python -m translation_engine --ui` | `8704` |
| **AI Engine UI** | `python -m ai_engine --ui` | `8705` |
| **Storage Engine UI** | `python -m storage_engine --ui` | `8706` |

---

## API Reference

Each engine package exposes its primary facade at the package root (`<name>_engine/__init__.py`). Refer to each package's dedicated `README.md` for full parameter-by-parameter documentation:

| Package | Facade Class | Key Public Methods | Primary Return Types |
| :--- | :--- | :--- | :--- |
| [security_engine](security_engine/README.md) | `SecurityEngine` | `inspect(file_path, safe_dir, mode)`, `inspect_directory(dir_path)` | `SecurityResult` / raises `SecurityRejectedError` |
| [extraction_engine](extraction_engine/README.md) | `ExtractionEngine` | `extract(file_path, enable_ocr, ocr_lang, page_range)` | `ExtractedDocument` (`.to_json()`, `.to_markdown()`, `.to_docx()`) |
| [chunking_engine](chunking_engine/README.md) | `ChunkingEngine` | `chunk(structured_doc, max_words, overlap_words)`, `save_to_json(...)` | `list[Chunk]` (`ChunkMetadata`, `section_breadcrumb`) |
| [translation_engine](translation_engine/README.md) | `TranslationEngine` | `translate_chunks(chunks, target_lang, source_lang)`, `translate_text(...)`, `unload()` | `list[TranslatedChunk]` |
| [ai_engine](ai_engine/README.md) | `AIEngine` | `embed_chunks(...)`, `embed_query(...)`, `analyze(...)`, `chat(...)`, `chat_stream(...)` | `list[EmbeddingRecord]`, `AnalysisResult`, `ChatResponse` |
| [storage_engine](storage_engine/README.md) | `StorageEngine` | `save_security(...)`, `save_extraction(...)`, `save_chunks(...)`, `save_translations(...)`, `save_embeddings(...)`, `save_analysis(...)`, `save_stage_output(...)`, `search_vectors(...)`, `get_file_lineage(...)` | `StorageReceipt`, `FileLineage` |
| [examples](examples/README.md) | `full_pipeline_demo` | `discover_engine_packages()`, `verify_zero_cross_engine_imports()`, `run_demo()` | CLI report / Web Studio UI |

---

## Testing

Every engine includes an embedded, deterministic `--self-test` suite requiring no external network access or heavy model downloads, alongside the end-to-end integration and AST isolation verifier:

```powershell
# Run individual standalone engine self-tests
python -m security_engine --self-test
python -m extraction_engine --self-test
python -m chunking_engine --self-test
python -m translation_engine --self-test
python -m ai_engine --self-test
python -m storage_engine --self-test

# Run full end-to-end integration, lineage verification, & AST zero-coupling audit
python examples/full_pipeline_demo.py
```

---

## License and Contributing

### License
Distributed under the **MIT License**. You are free to use, copy, modify, merge, publish, and distribute any individual `*_engine` package or the complete repository in personal and commercial software.

### Contributing & Pull Request Guidelines
1. **Strict Package Isolation:** Never import a sibling `*_engine` inside another `*_engine` package. Verify isolation via `python examples/full_pipeline_demo.py` before opening a Pull Request.
2. **Non-Intrusive UIs:** Keep UI code strictly inside `<package>/ui/app.py` without adding UI dependencies to core engine modules.
3. **English-Only Code & Docs:** Write all inline comments, docstrings, CLI help messages, UI labels, and Markdown documentation in clear English.
4. **Open-Ended Extensibility:** Follow the `<name>_engine` naming convention, export typed `dataclass` contracts with `.to_dict()` serialization, and include a deterministic `--self-test` mode in `__main__.py`.
