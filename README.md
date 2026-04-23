<div align="center">

```
 _   _ _   _ _____ _   _ ___________ ___________ ___  _______ _   _ _   _ ___  _      _     _____ ______
| \ | | | | |_   _| | | |  ___|  ___||  ___| ___ \  | | _____|_  | | | | |    | |    | |   |  ___|| ___ \
|  \| | | | | | | | |_| | |__ | |__  | |__ | |_/ /  | | |      | | | | | |    | |    | |   | |__  | |_/ /
| . ` | | | | | | |  _  |  __||  __| |  __||    /   | | |___   | | | | | |    | |    | |   |  __| |    /
| |\  | |_| | | | | | | | |___| |___ | |___| |\ \   | \_____| _| |_| |_| |___ | |____| |___| |___ | |\ \
\_| \_/\___/  \_/ \_| |_/\____/\____/\____/\_| \_|  |_|\____/ \___/ \___/____/\_____/\_____/\____/\_| \_|
```

**Themida/WinLicense unpacker → Nuitka onefile extractor**  
Full two-stage pipeline (dynamic + static)

[![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![CI](https://img.shields.io/github/actions/workflow/status/DimaReverse/nuitka-themida-unpacker/ci.yml?style=flat-square)](./.github/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey?style=flat-square)]()
[![Stage 1](https://img.shields.io/badge/stage%201-dynamic%20(unlicense)-orange?style=flat-square)]()
[![Stage 2](https://img.shields.io/badge/stage%202-static%20(nuthem)-brightgreen?style=flat-square)]()

Full unpacking pipeline for executables that are **both** Themida/WinLicense protected **and** built with Nuitka onefile (KAX/KAY).

</div>

---

## What this repo does

Some executables are protected with two layers stacked on top of each other:

```
┌─────────────────────────────────────────┐
│  Themida / WinLicense protection layer  │  ← encrypts, virtualizes, anti-debug
├─────────────────────────────────────────┤
│  Nuitka onefile payload (KAX / KAY)     │  ← embedded PE + all DLLs + Python runtime
└─────────────────────────────────────────┘
```

No single existing tool handles both layers. This repo documents and automates the full pipeline:

1. **Stage 1 (dynamic)**: strip Themida/WinLicense using [unlicense](https://github.com/ergrelet/unlicense) (executes the target).
2. **Stage 2 (static)**: extract Nuitka onefile payload from the unpacked PE using **nuthem** (no execution needed).
3. **Stage 3 (optional)**: feed the extracted inner EXE into [nuitka-static-unpacker](https://github.com/DimaReverse/nuitka-static-unpacker) to recover Python artifacts.

---

## Safety / important notes

- **Stage 1 executes the target binary** (by design). Always run it in a VM/sandbox for untrusted samples.
- **Stage 2 and Stage 3 are static** (safe to run anywhere).
- **Responsible use**: only analyze software you own or have authorization to test.

---

## Requirements

**Stage 1:**
- Windows (required for Themida unpacking)
- [unlicense](https://github.com/ergrelet/unlicense) — download the prebuilt `.exe` from their [Releases](https://github.com/ergrelet/unlicense/releases) page

**Stage 2:**
- Python 3.8+
- `zstandard` (only needed for KAY/compressed payloads): `pip install zstandard`

**Stage 3 (optional):**
- [nuitka-static-unpacker](https://github.com/DimaReverse/nuitka-static-unpacker)
- `pefile`: `pip install pefile`

---

## Installation

```bash
git clone https://github.com/DimaReverse/nuitka-themida-unpacker.git
cd nuitka-themida-unpacker
python -m pip install -U pip
python -m pip install .
```

Download `unlicense64.exe` (or `unlicense32.exe` for 32-bit targets) from [ergrelet/unlicense releases](https://github.com/ergrelet/unlicense/releases) and put it in the same folder, or anywhere on your PATH.

### Quick start

If you already have an **unpacked** PE (Themida removed), skip Stage 1:

```bash
nuthem-pipeline unpacked_target.exe --skip-stage1
```

Otherwise, run the full pipeline (Stage 1 + 2):

```bash
nuthem-pipeline target_protected.exe
```

### Developer setup (optional)

```bash
python -m pip install -U pip
python -m pip install -e ".[dev]"
ruff check .
```

---

## Usage

### Full pipeline (recommended)

```bash
nuthem-pipeline target_protected.exe
```

This runs all stages automatically and drops results into `./output/`.

Useful flags:

```bash
nuthem-pipeline target.exe --out ./output --unlicense .\\unlicense64.exe
nuthem-pipeline unpacked_target.exe --skip-stage1
```

### Manual stage by stage

**Stage 1 — Strip Themida:**
```bash
unlicense64.exe target_protected.exe
# Produces: unpacked_target_protected.exe
```

**Stage 2 — Extract Nuitka onefile payload:**
```bash
nuthem extract unpacked_target_protected.exe
# Produces: unpacked_target_protected.exe.nuthem/ (1776 files in your example)
```

**Stage 3 — Recover Python source (optional):**
```bash
# Find the main Nuitka-compiled EXE inside the extracted folder, then:
python nuitka_decompiler.py --source unpacked_target_protected.exe.nuthem/YourApp.exe --all
```

---

## What nuthem.py does

`nuthem.py` (and the `nuthem` CLI) is a **pure-static** parser for the Nuitka onefile format. It:

- Parses the PE section table to locate `KAX` / `KAY` magic markers
- Handles both **uncompressed (KAX)** and **zstd-compressed (KAY)** payloads
- Supports both global-stream compression and per-file archive compression
- Auto-detects the presence of the optional checksum field (caching builds)
- Extracts all embedded files with path traversal protection
- Writes a `nuthem_manifest.json` with SHA-256 hashes of every extracted file

### Nuitka onefile format (KAX / KAY)

```
[3 bytes]  Magic: KAX (uncompressed) or KAY (zstd compressed)
[stream]   Sequence of entries until empty filename:
  [UTF-16LE NUL-terminated filename]
  [u64 file_size]
  [u32 checksum]        ← optional, auto-detected
  [u32 archive_size]    ← only in KAY archive mode (per-file compression)
  [file bytes / compressed frame]
[u16 0x0000]           ← EOF marker (empty filename)
```

See [`docs/nuitka_onefile_format.md`](docs/nuitka_onefile_format.md) for the full format documentation.

---

## Output structure

```
output/
├── nuthem_manifest.json         ← SHA-256 manifest of all extracted files
├── YourApp.exe                  ← Main Nuitka-compiled binary
├── python311.dll
├── vcruntime140.dll
├── tcl/
│   └── ...
└── lib/
    └── ...
```

---

## Pipeline diagram

```
 target.exe
 (Themida/WinLicense + Nuitka onefile)
        │
        │  [STAGE 1 — DYNAMIC]
        │  unlicense64.exe target.exe
        ▼
 unpacked_target.exe
 (plain PE, Themida layer removed)
        │
        │  [STAGE 2 — STATIC]
        │  python nuthem.py extract unpacked_target.exe
        ▼
 unpacked_target.exe.nuthem/
 ├── YourApp.exe         ← the inner Nuitka binary
 ├── python311.dll
 └── ...
        │
        │  [STAGE 3 — STATIC, OPTIONAL]
        │  python nuitka_decompiler.py --source YourApp.exe
        ▼
 output/
 ├── module.py           ← recovered Python source
 ├── constants.json
 └── REPORT.json
```

---

## Relation to nuitka-static-unpacker

This repo handles the **outer layer** (Themida → Nuitka onefile payload extraction). Once you have the inner EXE, [nuitka-static-unpacker](https://github.com/DimaReverse/nuitka-static-unpacker) handles the **inner layer** (Nuitka constants blob → Python source recovery, including Commercial encrypted builds).

They are designed to chain together.

---

## FAQ / troubleshooting

**`nuthem` says “No Nuitka onefile header (KAX/KAY) found”**
- You might be pointing it at the **Themida-protected** file (run Stage 1 first), or the target simply isn’t a Nuitka onefile build.

**`nuthem` fails on KAY**
- Install zstandard: `python -m pip install zstandard`

**unlicense not found**
- Download it from [unlicense releases](https://github.com/ergrelet/unlicense/releases) and either place it next to `pipeline.py` or pass `--unlicense path/to/unlicense64.exe`.

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## License

MIT — see [`LICENSE`](LICENSE).

## Credits

- `nuthem.py` — Dimitri Bordei / `dima_reverse`
- Themida/WinLicense unpacking — [ergrelet/unlicense](https://github.com/ergrelet/unlicense)

---

<div align="center">

*Part of a larger effort to document and open-source the full Nuitka reverse engineering pipeline.*

**[nuitka-static-unpacker](https://github.com/DimaReverse/nuitka-static-unpacker) ← companion tool for the inner Nuitka layer**

⭐ If this helped you, a star goes a long way.

</div>
