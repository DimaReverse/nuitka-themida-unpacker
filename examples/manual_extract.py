#!/usr/bin/env python3
"""
Example: use nuthem programmatically (without CLI) to extract a Nuitka onefile payload.

Assumes you have already run unlicense on the target and have the unpacked PE.

Usage:
    python examples/manual_extract.py unpacked_target.exe ./output
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from nuthem import NuthemError, extract_from_exe


def main():
    if len(sys.argv) < 2:
        print("Usage: manual_extract.py <unpacked.exe> [output_dir]")
        sys.exit(1)

    exe = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else exe.with_suffix(exe.suffix + ".nuthem")

    try:
        manifest = extract_from_exe(exe, out)
    except NuthemError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Extracted {manifest['file_count']} files to {manifest['output_dir']}")
    print(f"Magic:   {manifest['nuitka_header_magic']}")
    print(f"Section: {manifest['pe_section']}")
    print()

    # Show the top-level EXEs and DLLs found
    exes = [f for f in manifest["files"] if f["name"].lower().endswith(".exe")]
    dlls = [f for f in manifest["files"] if f["name"].lower().endswith(".dll")]
    print(f"EXEs found ({len(exes)}):")
    for e in exes[:10]:
        print(f"  {e['name']}  ({e['size']:,} bytes)")
    print(f"DLLs found ({len(dlls)}):")
    for d in dlls[:10]:
        print(f"  {d['name']}  ({d['size']:,} bytes)")
    if len(dlls) > 10:
        print(f"  ... and {len(dlls) - 10} more")


if __name__ == "__main__":
    main()
