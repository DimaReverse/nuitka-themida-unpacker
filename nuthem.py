#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Iterator, Optional

MAGICS = (b"KAX", b"KAY")  # Nuitka onefile attached data header: KA + X(uncompressed) / Y(zstd)


class NuthemError(Exception):
    pass


def _u16le_cstr(data: memoryview, offset: int, max_chars: int = 65536) -> tuple[str, int]:
    """Read UTF-16LE NUL-terminated string; returns (value, new_offset)."""
    end = offset
    chars = []
    for _ in range(max_chars):
        if end + 2 > len(data):
            raise NuthemError("Unexpected EOF while reading UTF-16LE filename.")
        (code_unit,) = struct.unpack_from("<H", data, end)
        end += 2
        if code_unit == 0:
            break
        chars.append(code_unit)
    else:
        raise NuthemError("Filename too long / missing terminator.")

    try:
        s = bytes(struct.pack("<" + "H" * len(chars), *chars)).decode("utf-16le", errors="strict")
    except UnicodeDecodeError as e:
        raise NuthemError(f"Invalid UTF-16LE filename at 0x{offset:x}: {e}") from e
    return s, end


def _looks_like_relpath(p: str) -> bool:
    if not p:
        return False
    # Nuitka payload typically uses relative paths like "UI.exe", "tcl/tk..." etc.
    if p.startswith(("\\\\", "//")):
        return False
    if ":" in p[:3]:  # "C:\..."
        return False
    # Avoid absurd control chars.
    for ch in p:
        if ord(ch) < 0x20:
            return False
    return True


def _safe_join(root: Path, rel: str) -> Path:
    # Normalize Nuitka separators (it uses platform separators in practice, but be defensive).
    rel = rel.replace("/", os.sep).replace("\\", os.sep)
    # Nuitka payloads sometimes store paths with a leading separator (e.g. "\\bgerror.tcl").
    # Treat them as relative to payload root.
    rel = rel.lstrip("\\/")  # safe even on Windows; we normalize above.
    out = (root / rel).resolve()
    root_r = root.resolve()
    if root_r not in out.parents and out != root_r:
        raise NuthemError(f"Refusing path traversal outside output dir: {rel!r}")
    return out


@dataclasses.dataclass(frozen=True)
class PESection:
    name: str
    raw_ptr: int
    raw_size: int
    virt_addr: int
    virt_size: int


def parse_pe_sections(buf: memoryview) -> list[PESection]:
    # Minimal PE parser: DOS -> NT -> section table.
    if len(buf) < 0x100:
        raise NuthemError("File too small to be a PE.")
    if buf[0:2].tobytes() != b"MZ":
        raise NuthemError("Not a PE (missing MZ).")

    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    if e_lfanew + 4 + 20 > len(buf):
        raise NuthemError("Invalid PE header offset.")
    if buf[e_lfanew : e_lfanew + 4].tobytes() != b"PE\x00\x00":
        raise NuthemError("Not a PE (missing PE\\0\\0).")

    coff_off = e_lfanew + 4
    (machine, number_of_sections, _time, _ptrsym, _numsym, size_of_optional_header, _chars) = struct.unpack_from(
        "<HHIIIHH", buf, coff_off
    )
    opt_off = coff_off + 20
    sec_off = opt_off + size_of_optional_header
    if sec_off + number_of_sections * 40 > len(buf):
        raise NuthemError("Section table out of range.")

    sections: list[PESection] = []
    for i in range(number_of_sections):
        off = sec_off + i * 40
        name = buf[off : off + 8].tobytes().split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", buf, off + 8)
        sections.append(
            PESection(
                name=name,
                raw_ptr=raw_ptr,
                raw_size=raw_size,
                virt_addr=virt_addr,
                virt_size=virt_size,
            )
        )
    return sections


def iter_magic_hits(buf: memoryview, sections: list[PESection]) -> Iterator[tuple[int, bytes, PESection]]:
    # Scan each section's raw data to reduce false positives.
    for s in sections:
        if s.raw_ptr == 0 or s.raw_size == 0:
            continue
        start = s.raw_ptr
        end = min(len(buf), s.raw_ptr + s.raw_size)
        chunk_bytes = buf[start:end].tobytes()
        for magic in MAGICS:
            pos = chunk_bytes.find(magic)
            while pos != -1:
                abs_pos = start + pos
                yield abs_pos, magic, s
                pos = chunk_bytes.find(magic, pos + 1)


def _try_import_zstd():
    try:
        import zstandard as zstd  # type: ignore
    except Exception:
        return None
    return zstd


def _decompress_kay_zstd(payload: bytes) -> bytes:
    zstd = _try_import_zstd()
    if zstd is None:
        raise NuthemError(
            "Payload appears compressed (KAY) but python package 'zstandard' is not installed.\n"
            "Install it with: py -3.11 -m pip install zstandard"
        )
    # Payload blob often contains trailing non-zstd bytes after the first frame
    # (e.g. the rest of the PE section). Use a decompressobj and stop at EOF of frame.
    dctx = zstd.ZstdDecompressor()
    dobj = dctx.decompressobj()
    try:
        out_chunks: list[bytes] = []
        view = memoryview(payload)
        chunk_size = 1024 * 1024

        for off in range(0, len(view), chunk_size):
            out = dobj.decompress(view[off : off + chunk_size])
            if out:
                out_chunks.append(out)
            if dobj.eof:
                break

        if not dobj.eof:
            raise NuthemError("Zstd frame did not terminate within provided data.")

        return b"".join(out_chunks)
    except Exception as e:
        raise NuthemError(f"Zstd decompression failed: {e}") from e


@dataclasses.dataclass
class ExtractedEntry:
    name: str
    size: int
    sha256: str


def _zstd_decompress_exact(comp: bytes, expected_size: Optional[int] = None) -> bytes:
    zstd = _try_import_zstd()
    if zstd is None:
        raise NuthemError(
            "Need zstd decompression but python package 'zstandard' is not installed.\n"
            "Install it with: py -3.11 -m pip install zstandard"
        )

    dctx = zstd.ZstdDecompressor()
    dobj = dctx.decompressobj()
    out = dobj.decompress(comp)
    # Some frames may have trailing data, but for Nuitka per-file compression, it should end cleanly.
    if not dobj.eof:
        # Try to finish (in case internal buffering wants more calls)
        out += dobj.flush()
    if expected_size is not None and len(out) != expected_size:
        # Keep it a soft check: some payloads may store file_size that includes e.g. padding,
        # but in practice Nuitka expects exact.
        raise NuthemError(f"Decompressed size mismatch: got {len(out)} expected {expected_size}")
    return out


def parse_onefile_stream_raw(stream: bytes, assume_checksum: Optional[bool] = None) -> list[tuple[str, bytes, Optional[int]]]:
    """
    Parse Nuitka onefile stream where file bytes are stored raw (not per-file compressed).
    Layout (Windows typical):
      [UTF-16LE filename NUL-terminated]
      [u64 file_size]
      [u32 checksum]   (present when caching enabled; common on Windows)
      [file bytes...]
    EOF marker: empty filename (u16 NUL).

    Returns list of (filename, file_bytes, checksum_or_None).
    """
    data = memoryview(stream)
    off = 0
    out: list[tuple[str, bytes, Optional[int]]] = []

    def prefer_no_checksum_by_signature(filename: str, content_offset: int) -> Optional[bool]:
        """
        Return True to prefer checksum present, False to prefer checksum absent, or None if unsure.
        For common binaries, we can strongly disambiguate because the first bytes are known.
        """
        lower = filename.lower()
        if not (lower.endswith(".exe") or lower.endswith(".dll") or lower.endswith(".pyd")):
            return None
        # Without checksum, file content starts at content_offset.
        sig_no = data[content_offset : content_offset + 2].tobytes()
        # With checksum, file content starts at content_offset+4.
        sig_yes = data[content_offset + 4 : content_offset + 6].tobytes() if content_offset + 6 <= len(data) else b""

        if sig_no == b"MZ" and sig_yes != b"MZ":
            return False
        if sig_yes == b"MZ" and sig_no != b"MZ":
            return True
        return None

    def peek_next_filename(o: int) -> bool:
        try:
            s, _no = _u16le_cstr(data, o, max_chars=512)
        except Exception:
            return False
        if s == "":
            return True
        return _looks_like_relpath(s)

    while True:
        name, off = _u16le_cstr(data, off)
        if name == "":
            break
        if not _looks_like_relpath(name):
            raise NuthemError(f"Unreasonable filename parsed: {name!r} at offset 0x{off:x}")

        if off + 8 > len(data):
            raise NuthemError("Unexpected EOF while reading file size.")
        (file_size,) = struct.unpack_from("<Q", data, off)
        off += 8
        if file_size > (1 << 40):  # 1 TB sanity
            raise NuthemError(f"Unreasonable file size {file_size} for {name!r}")

        checksum_val: Optional[int] = None
        if assume_checksum is True:
            if off + 4 > len(data):
                raise NuthemError("Unexpected EOF while reading checksum.")
            (checksum_val,) = struct.unpack_from("<I", data, off)
            off += 4
        elif assume_checksum is False:
            checksum_val = None
        else:
            # Auto-detect: try "with checksum" only if it doesn't make the next filename implausible
            # and doesn't push beyond stream.
            sig_pref = prefer_no_checksum_by_signature(name, off)
            if sig_pref is False:
                checksum_val = None
            elif sig_pref is True:
                (checksum_val,) = struct.unpack_from("<I", data, off)
                off += 4
            elif off + 4 <= len(data):
                # This is a heuristic: if reading checksum makes the following file bytes align
                # such that next filename looks plausible after skipping file_size bytes.
                off_with = off + 4
                end_with = off_with + file_size
                end_without = off + file_size
                if end_with <= len(data) and peek_next_filename(end_with):
                    (checksum_val,) = struct.unpack_from("<I", data, off)
                    off = off_with
                elif end_without <= len(data) and peek_next_filename(end_without):
                    checksum_val = None
                else:
                    # If we cannot validate boundaries (e.g. huge file), default to no-checksum.
                    checksum_val = None

        if off + file_size > len(data):
            raise NuthemError(f"Unexpected EOF while reading {name!r} bytes.")
        blob = data[off : off + file_size].tobytes()
        off += file_size

        out.append((name, blob, checksum_val))

    return out


def parse_onefile_stream_kay_archive(stream: bytes, assume_checksum: Optional[bool] = None) -> list[tuple[str, bytes, Optional[int]]]:
    """
    Parse Nuitka onefile stream for KAY *archive* mode (per-file compression).
    Layout (observed in Nuitka OnefileBootstrap.c when _NUITKA_ONEFILE_ARCHIVE_BOOL==1 && compression==1):
      [UTF-16LE filename NUL-terminated]
      [u64 file_size]              (uncompressed)
      [u32 checksum]               (optional; caching mode)
      [u32 archive_file_size]      (compressed blob size)
      [archive_file_size bytes]    (zstd frame for this file content)
    EOF marker: empty filename.
    """
    data = memoryview(stream)
    off = 0
    out: list[tuple[str, bytes, Optional[int]]] = []

    def peek_next_filename(o: int) -> bool:
        try:
            s, _no = _u16le_cstr(data, o, max_chars=512)
        except Exception:
            return False
        if s == "":
            return True
        return _looks_like_relpath(s)

    while True:
        name, off = _u16le_cstr(data, off)
        if name == "":
            break
        if not _looks_like_relpath(name):
            raise NuthemError(f"Unreasonable filename parsed: {name!r} at offset 0x{off:x}")

        if off + 8 > len(data):
            raise NuthemError("Unexpected EOF while reading file size.")
        (file_size,) = struct.unpack_from("<Q", data, off)
        off += 8

        checksum_val: Optional[int] = None
        if assume_checksum is True:
            if off + 4 > len(data):
                raise NuthemError("Unexpected EOF while reading checksum.")
            (checksum_val,) = struct.unpack_from("<I", data, off)
            off += 4
        elif assume_checksum is False:
            checksum_val = None
        else:
            # Auto-detect: decide based on whether reading checksum allows a plausible next filename
            # after consuming this entry. We need archive_file_size first; so do a two-path check.
            if off + 4 <= len(data):
                # Path A: checksum present
                try_off = off + 4
                if try_off + 4 <= len(data):
                    (afs_a,) = struct.unpack_from("<I", data, try_off)
                    end_a = try_off + 4 + afs_a
                else:
                    end_a = 1 << 62

                # Path B: checksum absent
                if off + 4 <= len(data):
                    (afs_b,) = struct.unpack_from("<I", data, off)
                    end_b = off + 4 + afs_b
                else:
                    end_b = 1 << 62

                ok_a = end_a <= len(data) and peek_next_filename(end_a)
                ok_b = end_b <= len(data) and peek_next_filename(end_b)

                if ok_a and not ok_b:
                    (checksum_val,) = struct.unpack_from("<I", data, off)
                    off = try_off
                elif ok_b and not ok_a:
                    checksum_val = None
                else:
                    # Default to checksum present (common on Windows caching builds)
                    (checksum_val,) = struct.unpack_from("<I", data, off)
                    off = try_off

        if off + 4 > len(data):
            raise NuthemError("Unexpected EOF while reading archive_file_size.")
        (archive_file_size,) = struct.unpack_from("<I", data, off)
        off += 4
        if archive_file_size > len(data) - off:
            raise NuthemError("archive_file_size exceeds remaining stream.")

        comp = data[off : off + archive_file_size].tobytes()
        off += archive_file_size

        blob = _zstd_decompress_exact(comp, expected_size=int(file_size))
        out.append((name, blob, checksum_val))

    return out


def extract_from_exe(exe_path: Path, out_dir: Path, pick: str = "best") -> dict:
    blob = exe_path.read_bytes()
    buf = memoryview(blob)
    sections = parse_pe_sections(buf)

    hits = list(iter_magic_hits(buf, sections))
    if not hits:
        raise NuthemError("No Nuitka onefile header (KAX/KAY) found in PE sections.")

    candidates = []
    for abs_pos, magic, sec in hits:
        # The onefile payload blob is embedded with a known bounded size (e.g. Windows resource size
        # or a dedicated section). Don't attempt to decode until EOF of whole file.
        sec_end = min(len(blob), sec.raw_ptr + sec.raw_size)
        if not (sec.raw_ptr <= abs_pos < sec_end):
            continue
        stream = blob[abs_pos + 3 : sec_end]
        try:
            # Nuitka has two relevant KAY interpretations:
            # - global stream zstd (archive_bool==0): decompress whole stream then parse raw
            # - per-file archive zstd (archive_bool==1): parse metadata raw and decompress each file
            if magic == b"KAX":
                entries = parse_onefile_stream_raw(stream, assume_checksum=None)
            elif magic == b"KAY":
                # Prefer archive mode first; it's common on Windows.
                try:
                    entries = parse_onefile_stream_kay_archive(stream, assume_checksum=None)
                except Exception:
                    stream2 = _decompress_kay_zstd(stream)
                    entries = parse_onefile_stream_raw(stream2, assume_checksum=None)
            else:
                continue
            # Score by number of files and total bytes.
            total = sum(len(b) for _n, b, _c in entries)
            candidates.append((len(entries), total, abs_pos, magic, sec.name, entries))
        except Exception:
            continue

    if not candidates:
        raise NuthemError(
            "Found KAX/KAY markers but couldn't parse a valid onefile stream. "
            "This can happen if the marker is a false positive or if Nuitka format changed."
        )

    candidates.sort(reverse=True)  # best: most entries, then biggest total
    best = candidates[0]
    _count, _total, abs_pos, magic, sec_name, entries = best

    out_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[ExtractedEntry] = []

    for name, content, _checksum_val in entries:
        target = _safe_join(out_dir, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

        sha256 = hashlib.sha256(content).hexdigest()
        extracted.append(ExtractedEntry(name=name, size=len(content), sha256=sha256))

    manifest = {
        "tool": "nuthem",
        "input": str(exe_path),
        "output_dir": str(out_dir),
        "nuitka_header_offset": abs_pos,
        "nuitka_header_magic": magic.decode("ascii"),
        "pe_section": sec_name,
        "file_count": len(extracted),
        "files": [dataclasses.asdict(e) for e in extracted],
    }
    (out_dir / "nuthem_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="nuthem",
        description="Static extractor for Nuitka onefile payload from Themida-unwrapped executables.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    ex = sub.add_parser("extract", help="Extract embedded Nuitka onefile payload.")
    ex.add_argument("exe", type=Path, help="Input EXE (already unpacked from Themida/WinLicense layer).")
    ex.add_argument("-o", "--out", type=Path, default=None, help="Output directory (default: <exe>.nuthem/).")

    args = ap.parse_args(argv)

    if args.cmd == "extract":
        exe_path: Path = args.exe
        if args.out is None:
            out_dir = exe_path.with_suffix(exe_path.suffix + ".nuthem")
        else:
            out_dir = args.out

        manifest = extract_from_exe(exe_path, out_dir)
        print(json.dumps({k: manifest[k] for k in ["file_count", "output_dir", "nuitka_header_magic", "pe_section"]}, indent=2))
        return 0

    ap.print_help()
    return 2


def cli() -> None:
    raise SystemExit(main(sys.argv[1:]))


if __name__ == "__main__":
    cli()

