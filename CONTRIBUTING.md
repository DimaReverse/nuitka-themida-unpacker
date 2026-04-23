# Contributing

## What's most useful

- **Bug reports** with reproduction steps and the hex dump of the first 64 bytes at the KAX/KAY magic offset
- **New Nuitka version support** — format notes and sample manifests welcome
- **Checksum detection edge cases** — if auto-detection fails, note the Nuitka version and build flags
- **Pipeline improvements** — better unlicense integration, error handling, progress reporting

## Before opening a PR

1. Describe what problem you're solving
2. Keep changes focused — one thing per PR
3. If you're touching `nuthem.py` parsing logic, explain which Nuitka version or build variant it targets

## Reporting bugs

Please include:
- OS and Python version
- Nuitka version of the target (if known)
- Whether the payload is KAX or KAY (shown in nuthem output)
- Full command and full console output
- Hex dump of first 64 bytes starting at the KAX/KAY magic (helps a lot)

## Code style

- PEP 8
- Magic numbers in struct parsing need inline comments
- No new required dependencies without discussion
