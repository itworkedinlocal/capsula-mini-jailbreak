#!/usr/bin/env python3
"""Developer-only cross build. No compiler or Python is shipped to users."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from paths import NATIVE, STOCK as HERE, BUILD, SOURCES, ZIG

def main():
    target = HERE / 'bin/windows-x86_64/password-hash.exe'
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(ZIG), 'cc',
                    '-target', 'x86_64-windows-gnu', '-Os', '-Wall', '-Wextra', '-Werror',
                    str(NATIVE / 'password-hash.c'), '-lbcrypt', '-o', str(target)],
                   env={**os.environ, 'ZIG_GLOBAL_CACHE_DIR': str(BUILD / 'zig-cache')}, check=True)
    record = {'target': 'windows/amd64', 'files': {'password-hash.exe': {
        'bytes': target.stat().st_size, 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}},
        'sources': {name: hashlib.sha256((NATIVE / name).read_bytes()).hexdigest()
                    for name in ('password-hash.c', 'sha512-crypt.c')}}
    (HERE / 'host-windows.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))

if __name__ == '__main__':
    main()
