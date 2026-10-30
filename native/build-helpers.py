#!/usr/bin/env python3
"""Build static, Linux 4.9-compatible installation and SSH supervision helpers."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from paths import NATIVE, STOCK as HERE, BUILD, SOURCES, ZIG


def main():
    records = {}
    for arch, names in {"aarch64": ("supervisor", "directory-times", "ubi-control", "nand-agent", "ram-restart"),
                        "x86_64": ("password-hash",)}.items():
        for name in names:
            target = HERE / "bin" / arch / name
            target.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run([str(ZIG), "cc",
                            "-target", arch + "-linux-musl", "-static", "-Os", "-Wall", "-Wextra", "-Werror",
                            str(NATIVE / (name + ".c")), "-o", str(target)],
                           env={**os.environ, "ZIG_GLOBAL_CACHE_DIR": str(BUILD / "zig-cache")}, check=True)
            records[f"{arch}/{name}"] = {"sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                                         "bytes": target.stat().st_size}
    (HERE / "helpers-build.json").write_text(json.dumps(records, indent=2) + "\n")
    print("Built", len(records), "static helpers")


if __name__ == "__main__":
    main()
