"""Tiny exact-match patcher: python patch.py <file> <patchfile>. Patchfile blocks: <<<OLD ... === ... >>>NEW"""
import sys
from pathlib import Path

target, patch = Path(sys.argv[1]), Path(sys.argv[2]).read_text(encoding="utf-8")
src = target.read_text(encoding="utf-8")
for block in patch.split("<<<OLD\n")[1:]:
    old, rest = block.split("\n===\n", 1)
    new = rest.split("\n>>>NEW", 1)[0]
    n = src.count(old)
    if n != 1:
        sys.exit(f"FAILED: old text found {n} times in {target.name}: {old[:80]!r}")
    src = src.replace(old, new)
target.write_text(src, encoding="utf-8")
print(f"patched {target.name}")
