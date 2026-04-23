# Nuitka Onefile Format (KAX / KAY)

Documentation of the embedded payload format used by Nuitka's onefile bootstrap, as observed in real binaries and cross-referenced with Nuitka's open-source `OnefileBootstrap.c`.

---

## Detection

Scan the PE's raw section data for the 3-byte magic:

| Magic | Meaning |
|-------|---------|
| `KAX` | Uncompressed payload stream |
| `KAY` | zstd-compressed payload (global stream or per-file archive) |

The magic appears at the very start of the payload blob, typically embedded in a dedicated PE section or appended to the `.data` section.

---

## Stream layout (KAX and KAY global mode)

After the 3-byte magic, the stream is a sequence of file entries terminated by an empty filename:

```
for each file:
  [UTF-16LE filename, NUL-terminated]   variable length
  [u64 LE: uncompressed file size]      8 bytes
  [u32 LE: checksum]                    4 bytes  ← OPTIONAL (caching builds only)
  [file bytes]                          file_size bytes

terminator:
  [u16 0x0000]                          empty filename = end of stream
```

For **KAY global mode**: the entire stream above (after the magic) is a single zstd frame. Decompress it first, then parse as above.

### Checksum field detection

The checksum field is **optional** — it is present in builds compiled with Nuitka's caching mode enabled (common on Windows). `nuthem.py` auto-detects its presence using two heuristics:

1. **Signature check**: for `.exe`, `.dll`, `.pyd` entries, it checks whether skipping 4 bytes makes the content start with `MZ`.
2. **Boundary check**: tests whether either interpretation (with or without checksum) results in the next filename being parseable at the expected offset.

---

## KAY archive mode (per-file compression)

When `_NUITKA_ONEFILE_ARCHIVE_BOOL==1` and compression is enabled, each file entry is individually compressed:

```
for each file:
  [UTF-16LE filename, NUL-terminated]   variable length
  [u64 LE: uncompressed file size]      8 bytes
  [u32 LE: checksum]                    4 bytes  ← OPTIONAL
  [u32 LE: compressed frame size]       4 bytes
  [compressed frame]                    archive_file_size bytes (zstd)

terminator:
  [u16 0x0000]
```

Each compressed frame is an independent zstd frame. The uncompressed size is stored in `file_size` and validated after decompression.

---

## Filename encoding

Filenames are **UTF-16LE, NUL-terminated** (two zero bytes). They use platform-native separators (backslash on Windows) and are typically relative paths like:

```
UI.exe
python311.dll
tcl\tk8.6\bgerror.tcl
lib\site-packages\...
```

`nuthem.py` normalizes separators and strips leading `\` or `/` before writing, and validates all paths against the output root to prevent path traversal.

---

## False positives

The bytes `KAX` and `KAY` can appear as false positives in arbitrary binary data. `nuthem.py` mitigates this by:

- Only scanning within PE section bounds
- Scoring all candidates by number of valid entries and total bytes
- Selecting the candidate with the most plausible parse result

---

## Nuitka version notes

The onefile format has been stable across Nuitka 1.x and 2.x for the aspects documented here. The main variance is in whether the checksum field is present (a build-time option) and whether KAY uses global or per-file compression.

If you encounter a binary that `nuthem.py` fails to parse, please open an issue with:
- Nuitka version (if known)
- The first 64 bytes of the raw section starting at the KAX/KAY magic (hex dump)
- The error message from `nuthem.py`
