#!/usr/bin/env python3
"""
Full two-stage pipeline for Themida/WinLicense + Nuitka onefile protected executables.

Stage 1 (dynamic): unlicense.exe strips the Themida/WinLicense layer.
Stage 2 (static):  nuthem.py extracts the Nuitka onefile payload.

Usage:
    python pipeline.py target.exe
    python pipeline.py target.exe --out ./results --unlicense path/to/unlicense64.exe
    python pipeline.py target.exe --skip-stage1   # if already unpacked from Themida
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path


def find_unlicense(hint: Path | None) -> Path | None:
    """Locate unlicense64.exe or unlicense32.exe."""
    candidates = []
    if hint:
        candidates.append(hint)
    # Same directory as this script
    here = Path(__file__).parent
    candidates += [
        here / "unlicense64.exe",
        here / "unlicense32.exe",
    ]
    # PATH
    for name in ("unlicense64.exe", "unlicense32.exe", "unlicense.exe"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))

    for c in candidates:
        if c.exists():
            return c
    return None


def run_unlicense(unlicense_exe: Path, target: Path, out_dir: Path) -> Path:
    """
    Run unlicense on target and return path to the dumped PE.
    unlicense writes output next to the target by default, named unpacked_<target>.
    """
    expected_output = target.parent / f"unpacked_{target.name}"

    print(f"[STAGE 1] Running unlicense on {target.name} ...")
    print("          This EXECUTES the target binary — use a VM for untrusted files.")
    print(f"          unlicense: {unlicense_exe}")

    result = subprocess.run(
        [str(unlicense_exe), str(target)],
        capture_output=False,   # let unlicense print its own output
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"unlicense exited with code {result.returncode}. "
            "Check output above for details."
        )

    # unlicense may take a moment to write the file after the process returns
    for _ in range(20):
        if expected_output.exists():
            break
        time.sleep(0.5)

    if not expected_output.exists():
        raise RuntimeError(
            f"unlicense finished but expected output not found: {expected_output}\n"
            "Check unlicense output above. The unpacked file may have a different name."
        )

    dest = out_dir / expected_output.name
    shutil.move(str(expected_output), str(dest))
    print(f"[STAGE 1] Done -> {dest}")
    return dest


def run_nuthem(unpacked_exe: Path, out_dir: Path) -> Path:
    """Run nuthem.py extract on the unlicensed PE."""
    nuthem = Path(__file__).parent / "nuthem.py"
    if not nuthem.exists():
        raise RuntimeError(f"nuthem.py not found at {nuthem}")

    nuthem_out = out_dir / (unpacked_exe.name + ".nuthem")
    print(f"\n[STAGE 2] Running nuthem extract on {unpacked_exe.name} ...")

    result = subprocess.run(
        [sys.executable, str(nuthem), "extract", str(unpacked_exe), "-o", str(nuthem_out)],
        capture_output=False,
    )

    if result.returncode != 0:
        raise RuntimeError(f"nuthem exited with code {result.returncode}.")

    print(f"[STAGE 2] Done -> {nuthem_out}")
    return nuthem_out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="pipeline",
        description="Two-stage unpacker: Themida/WinLicense (unlicense) -> Nuitka onefile (nuthem).",
    )
    ap.add_argument("target", type=Path, help="Protected EXE to unpack.")
    ap.add_argument("-o", "--out", type=Path, default=None,
                    help="Output directory (default: ./output/)")
    ap.add_argument("--unlicense", type=Path, default=None,
                    help="Path to unlicense64.exe / unlicense32.exe")
    ap.add_argument("--skip-stage1", action="store_true",
                    help="Skip Themida unpacking (target is already an unpacked PE)")
    args = ap.parse_args(argv)

    target: Path = args.target.resolve()
    if not target.exists():
        print(f"[ERROR] Target not found: {target}", file=sys.stderr)
        return 1

    out_dir: Path = (args.out or Path("output")).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Target:     {target}")
    print(f"Output dir: {out_dir}")
    print()

    # ── Stage 1: Themida unpacking ────────────────────────────────────────────
    if args.skip_stage1:
        print("[STAGE 1] Skipped (--skip-stage1 flag set).")
        unpacked = target
    else:
        unlicense_exe = find_unlicense(args.unlicense)
        if unlicense_exe is None:
            print(
                "[ERROR] unlicense not found.\n"
                "Download unlicense64.exe from https://github.com/ergrelet/unlicense/releases\n"
                "and place it next to this script, or pass --unlicense /path/to/unlicense64.exe",
                file=sys.stderr,
            )
            return 1
        try:
            unpacked = run_unlicense(unlicense_exe, target, out_dir)
        except RuntimeError as e:
            print(f"[ERROR] Stage 1 failed: {e}", file=sys.stderr)
            return 1

    # ── Stage 2: Nuitka onefile extraction ───────────────────────────────────
    try:
        nuthem_out = run_nuthem(unpacked, out_dir)
    except RuntimeError as e:
        print(f"[ERROR] Stage 2 failed: {e}", file=sys.stderr)
        return 1

    print()
    print("=" * 60)
    print("Pipeline complete.")
    print(f"Extracted Nuitka payload: {nuthem_out}")
    print()
    print("Next step (optional):")
    print("  Find the main EXE inside the extracted folder and run:")
    print(f"  python nuitka_decompiler.py --source {nuthem_out}/<MainApp.exe> --all")
    print("  (nuitka-static-unpacker: https://github.com/DimaReverse/nuitka-static-unpacker)")
    return 0


def cli() -> None:
    raise SystemExit(main(sys.argv[1:]))


if __name__ == "__main__":
    cli()
